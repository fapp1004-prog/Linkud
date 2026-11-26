"""(A) proxy.py — 담당: A. 다른 사람은 고치지 않는다.

게이트웨이 본체. 도구 서버를 자식 프로세스로 실행하고, AI 앱과 서버 사이의
JSON-RPC 메시지(한 줄에 하나)를 중계하면서 tools/list·tools/call을 통제한다. (SPEC 2·6·7장)

실행:
    python -m gateway.proxy --server-id calc-ok -- python testservers/calc_ok/server.py
    (--server-id 필수. `--` 뒤가 진짜 서버 실행 명령. 서버 폴더를 못 찾는 실행 방식이면 --server-dir로 지정)

주의: 이 프로세스의 stdout은 곧 AI 앱과의 통신 선이다. print()가 섞이면 연결이 깨지므로
시작하자마자 sys.stdout을 stderr로 돌려놓는다. 프로토콜 출력은 to_client()로만 한다.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from gateway import audit, paths
from gateway.cache import UNAVAILABLE, CacheKey, TrustStore, Verdict, tool_hash
from gateway.policy import (SERVER_LEVEL, decide, load_checkers, load_fingerprints, load_policy, policy_fp,
                            run_checker)
from gateway.sanitize import RESTRICTED_DESCRIPTION, Unsafe, load_scan, sanitize_tool  # noqa: F401 (테스트·문서용 재노출)

log = logging.getLogger("gateway")

SERVER_ID_RE = re.compile(r"^[a-z0-9-]{1,40}$")
BLOCK_MESSAGE = "보안 정책에 의해 사용할 수 없는 도구입니다. (참조: {ref})"
RESTRICT_MESSAGE = "관리자 승인이 필요한 도구입니다. 승인 후 다시 시도하세요. (참조: {ref})"


class Gateway:
    def __init__(self, server_id: str, server_cmd: list[str], client_in, client_out,
                 server_dir: str | None = None, store: TrustStore | None = None, policy: dict | None = None):
        self.server_id = server_id
        self.server_cmd = server_cmd
        self.client_in = client_in          # AI 앱 → 게이트웨이 (바이너리 스트림)
        self.client_out = client_out        # 게이트웨이 → AI 앱
        self.mode = paths.mode()
        self.store = store or TrustStore()
        # C의 신원 검사기가 같은 DB(identity_baseline 표)를 찾도록 현재 모드의 DB 경로를 알려준다 (결정 #27)
        os.environ["LINKUD_DB_PATH"] = str(self.store.db_file)
        self.policy = policy or load_policy()
        self.policy_fp = policy_fp(self.policy)
        self.checkers = load_checkers(self.policy)
        self.file_fp_fn, self.dep_fp_fn = load_fingerprints()
        self.scan = load_scan(self.mode)
        self.timeout = float(self.policy.get("checkers", {}).get("timeout_seconds", 10))

        self.proc: subprocess.Popen | None = None
        self._client_lock = threading.Lock()
        self._server_lock = threading.Lock()
        self._pending: dict[str, tuple[str, bool]] = {}  # 요청 id → (method, 첫 페이지인가). 응답에는 method가 없어서
        self._pending_lock = threading.Lock()
        self._tools: dict[str, CacheKey | None] = {}     # 현재 도구 목록: 이름 → 판정 키 (None = 같은 이름 중복 → 거절)
        self._tools_lock = threading.Lock()
        self._verify_locks: dict[CacheKey, threading.Lock] = {}
        self._verify_locks_guard = threading.Lock()
        self.server_info = {"server_id": server_id, "name": "", "version": "",
                            "dir": server_dir or _server_dir(server_cmd), "command": list(server_cmd)}

    # ── 입출력 ──
    def _send(self, stream, lock, msg) -> None:
        data = (json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8")
        with lock:
            stream.write(data)
            stream.flush()

    def to_client(self, msg) -> None:
        self._send(self.client_out, self._client_lock, msg)

    def to_server(self, msg) -> None:
        self._send(self.proc.stdin, self._server_lock, msg)

    # ── 실행 ──
    def run(self) -> int:
        exe = shutil.which(self.server_cmd[0]) or self.server_cmd[0]
        env = {k: v for k, v in os.environ.items() if k != "LINKUD_DB_PATH"}  # 서버에는 DB 위치를 넘기지 않는다
        self.proc = subprocess.Popen(
            [exe, *self.server_cmd[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=sys.stderr, bufsize=0, env=env,
        )
        log.info("서버 실행 [%s, %s 모드]: %s (pid %s)", self.server_id, self.mode, " ".join(self.server_cmd),
                 self.proc.pid)
        t = threading.Thread(target=self._pump_server, name="server->client", daemon=True)
        t.start()
        try:
            self._pump_client()
        finally:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
        return self.proc.returncode or 0

    def _pump_client(self) -> None:
        """AI 앱 → 서버 방향. stdin이 닫히면(앱 종료) 끝난다."""
        for raw in iter(self.client_in.readline, b""):
            if not raw.strip():
                continue
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                log.warning("AI 앱이 보낸 JSON이 아닌 줄을 서버로 그대로 넘김")
                with self._server_lock:
                    self.proc.stdin.write(raw)
                    self.proc.stdin.flush()
                continue
            try:
                self.handle_client(msg)
            except BrokenPipeError:
                log.error("서버와의 연결이 끊김")
                return
            except Exception:
                log.exception("AI 앱 메시지 처리 중 오류")
                if isinstance(msg, dict) and "id" in msg:
                    self.to_client(_error(msg["id"], -32603, "게이트웨이 내부 오류"))

    def _pump_server(self) -> None:
        """서버 → AI 앱 방향. 서버가 끝나면 게이트웨이도 끝낸다."""
        for raw in iter(self.proc.stdout.readline, b""):
            if not raw.strip():
                continue
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                log.warning("서버가 JSON이 아닌 줄을 보냄 → 버림: %r", raw[:200])
                continue
            try:
                self.handle_server(msg)
            except Exception:
                log.exception("서버 메시지 처리 중 오류")
        log.info("서버 종료 → 게이트웨이 종료")
        try:
            self.client_in.close()
        except Exception:
            pass
        os._exit(0)

    # ── AI 앱 → 서버 ──
    def handle_client(self, msg) -> None:
        if isinstance(msg, list):
            # JSON-RPC 배치는 tools/call을 섞어서 검사를 우회할 수 있어서 받지 않는다 (MCP 최신 규격도 배치 없음)
            for m in msg:
                if isinstance(m, dict) and "id" in m:
                    self.to_client(_error(m["id"], -32600, "배치 요청은 지원하지 않습니다."))
            return
        method = msg.get("method")
        if "id" in msg and method:
            first_page = not (msg.get("params") or {}).get("cursor")
            with self._pending_lock:
                self._pending[_key(msg["id"])] = (method, first_page)
        if method == "tools/call":
            if self.guard_call(msg):
                self.to_server(msg)
            else:
                with self._pending_lock:
                    self._pending.pop(_key(msg["id"]), None)
            return
        self.to_server(msg)

    def guard_call(self, msg) -> bool:
        """tools/call 허용 여부. 검사기는 부르지 않고 SQLite만 본다. False면 거부 응답까지 보낸다. (SPEC 7장)"""
        req_id = msg.get("id")
        name = (msg.get("params") or {}).get("name", "")
        with self._tools_lock:
            key = self._tools.get(name)
        v = self.store.lookup(key) if key else None
        state = v.effective if v else "unknown"
        info = {"server_id": self.server_id, "tool": name, "hash": key.tool_hash if key else None,
                "rowid": v.rowid if v else None}

        if state in ("allow", "approved"):
            audit.write("call_allowed", grade=state, **info)
            return True

        ref = audit.new_ref()
        if state == "restrict" and v.exposable:
            audit.write("call_denied", grade="restrict", ref=ref, **info)
            self.to_client({"jsonrpc": "2.0", "id": req_id, "result": {
                "content": [{"type": "text", "text": RESTRICT_MESSAGE.format(ref=ref)}], "isError": True}})
        else:
            # 차단, 정제 불가로 숨긴 제한 도구, 목록에 없는 도구, 이름 중복, 판정 기록 없음 → 모두 거절 (fail-closed)
            # 숨긴 도구는 '목록에 없는 도구'와 같은 응답을 준다 (있는지 떠보기 방지)
            grade = "hidden" if state == "restrict" else state
            audit.write("call_denied", grade=grade, ref=ref, **info)
            self.to_client(_error(req_id, -32602, BLOCK_MESSAGE.format(ref=ref)))
        return False

    # ── 서버 → AI 앱 ──
    def handle_server(self, msg) -> None:
        if isinstance(msg, dict) and "id" in msg and "method" not in msg:  # 응답
            with self._pending_lock:
                method, first_page = self._pending.pop(_key(msg["id"]), (None, True))
            if method == "initialize" and "result" in msg:
                info = msg["result"].get("serverInfo") or {}
                self.server_info["name"] = str(info.get("name", ""))
                self.server_info["version"] = str(info.get("version", ""))
                log.info("서버 신원(자기 신고): %s %s", self.server_info["name"], self.server_info["version"])
            elif method == "tools/list" and "result" in msg:
                msg = self.filter_tools_response(msg, first_page)
        self.to_client(msg)

    def filter_tools_response(self, msg: dict, first_page: bool = True) -> dict:
        """tools/list 응답을 검사가 끝날 때까지 붙잡고, 등급대로 걸러서 돌려준다. (SPEC 6·7장)

        cursor 없는 요청(첫 페이지)의 응답이면 도구 목록을 새로 시작한다 → 지난 목록에만 있던 도구는 호출 거절.
        """
        result = dict(msg["result"])
        tools = [t for t in (result.get("tools") or []) if isinstance(t, dict)]
        if first_page:
            with self._tools_lock:
                self._tools = {}
        try:
            verdicts = self.verify_tools(tools)
        except Exception as e:  # 검증 자체가 망가지면 아무 도구도 보여주지 않는다 (fail-closed)
            log.exception("도구 검증 실패")
            audit.write("checker_error", server_id=self.server_id, checker="gateway", error=f"{type(e).__name__}: {e}")
            result["tools"] = []
            return {**msg, "result": result}

        counts: dict[str, int] = {}
        for t in tools:
            counts[t.get("name", "")] = counts.get(t.get("name", ""), 0) + 1

        shown = []
        with self._tools_lock:
            for tool, v in zip(tools, verdicts):
                name = tool.get("name", "")
                if counts[name] > 1 or name in self._tools:
                    # 같은 이름이 둘 이상이면 AI가 부르는 이름이 어느 정의인지 알 수 없다 → 숨기고 호출 거절
                    self._tools[name] = None
                    continue
                self._tools[name] = v.key
                state = v.effective
                if state == "allow":
                    shown.append(tool)
                elif state in ("restrict", "approved") and v.exposable:
                    # 승인된 제한 도구도 정제본을 보여준다 — 원본 설명은 끝까지 AI에게 가지 않는다 (결정 #34)
                    # 정제는 매번 다시 한다 (B의 규칙이 바뀌었을 수 있음). 이제 안 되면 숨기고 호출도 거절
                    try:
                        shown.append(sanitize_tool(tool, self.scan))
                    except Unsafe as e:
                        log.warning("%s 정제 불가 → 비노출: %s", name, e)
                        self._tools[name] = None
                # block, 정제 불가 → 목록에서 뺀다
            shown = [t for t in shown if self._tools.get(t["name"]) is not None]
        result["tools"] = shown
        return {**msg, "result": result}

    # ── 검증 ──
    def fingerprints(self) -> tuple[str, str]:
        """C의 서버 파일·의존성 지문. 못 구하면 빈 값 → 그 판정은 재사용·승인하지 않는다 (결정 #29)."""
        out = []
        for label, fn in (("file_fp", self.file_fp_fn), ("dep_fp", self.dep_fp_fn)):
            if fn is None:
                out.append(UNAVAILABLE)
                continue
            try:
                fp = fn(dict(self.server_info))
                out.append(fp if isinstance(fp, str) else UNAVAILABLE)
            except Exception as e:
                log.warning("%s 계산 실패: %s", label, e)
                audit.write("checker_error", server_id=self.server_id, checker=label, error=f"{type(e).__name__}: {e}")
                out.append(UNAVAILABLE)
        return out[0], out[1]

    def verify_tools(self, tools: list[dict]) -> list[Verdict]:
        file_fp, dep_fp = self.fingerprints()
        server_level = _Once(self._run_server_level)  # 공급망·신원은 이 목록에서 서버당 한 번만
        with ThreadPoolExecutor(max_workers=4) as ex:
            return list(ex.map(lambda t: self.verify_tool(t, file_fp, dep_fp, server_level), tools))

    def _lock_for(self, key: CacheKey) -> threading.Lock:
        with self._verify_locks_guard:
            return self._verify_locks.setdefault(key, threading.Lock())

    def verify_tool(self, tool: dict, file_fp: str, dep_fp: str, server_level=None) -> Verdict:
        key = CacheKey(self.server_id, tool_hash(tool), file_fp, dep_fp, self.policy_fp, self.mode)
        cached = self.store.get(key)
        if cached:
            return cached
        with self._lock_for(key):  # 같은 도구에 대한 검사는 한 번만
            cached = self.store.get(key)
            if cached:
                return cached
            results = {}
            for name, fn in self.checkers.items():
                if name not in SERVER_LEVEL:
                    results[name] = run_checker(name, fn, tool, dict(self.server_info), self.timeout)
            results.update((server_level or _Once(self._run_server_level))(tool))
            d = decide(results, self.policy)

            exposable = True
            if d.grade == "restrict":
                try:
                    sanitize_tool(tool, self.scan)
                except Unsafe as e:
                    exposable = False
                    d.reasons.append(f"정제 불가 → 비노출: {e}")
            if not key.complete:
                d.reasons.append("서버 지문 없음 → 재사용·승인 안 함")

            v = Verdict(
                key=key, tool=tool.get("name", ""), grade=d.grade, score=d.score,
                signals=d.signals, reasons=d.reasons, exposable=exposable,
                server_name=self.server_info["name"], server_version=self.server_info["version"],
                results=[r if isinstance(r, dict) else {"checker": n, "error": f"{type(r).__name__}: {r}"}
                         for n, r in results.items()],
            )
            self.store.put(v)
            for n, r in results.items():
                if isinstance(r, BaseException):
                    audit.write("checker_error", server_id=self.server_id, tool=v.tool, hash=key.tool_hash,
                                checker=n, error=f"{type(r).__name__}: {r}", rowid=v.rowid)
            audit.write("verdict", server_id=self.server_id, server_name=v.server_name, tool=v.tool,
                        hash=key.tool_hash, rowid=v.rowid, score=v.score, grade=v.grade, exposable=v.exposable,
                        fingerprints=key.complete, signals=v.signals, reasons=v.reasons)
            log.info("판정 %s/%s → %s (%s점)", self.server_id, v.tool, v.grade, v.score)
            return v

    def _run_server_level(self, tool: dict) -> dict:
        results = {}
        for name, fn in self.checkers.items():
            if name in SERVER_LEVEL:
                results[name] = run_checker(name, fn, tool, dict(self.server_info), self.timeout)
        return results


# ── 도우미 ───────────────────────────────────────────

class _Once:
    """처음 부를 때 한 번만 계산하고 같은 결과를 돌려준다 (스레드 안전)."""

    def __init__(self, fn):
        self.fn, self.lock, self.value, self.done = fn, threading.Lock(), None, False

    def __call__(self, *args):
        with self.lock:
            if not self.done:
                self.value, self.done = self.fn(*args), True
            return self.value


def _key(req_id) -> str:
    return json.dumps(req_id)  # 1과 "1"을 다른 id로 구분


def _error(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _server_dir(cmd: list[str]) -> str | None:
    """실행 명령에서 처음 나오는 .py/.js 파일의 폴더(절대경로). 없으면 None → C 검사기는 raise(→ 제한). (결정 #26)"""
    for part in cmd:
        p = Path(part)
        if p.suffix in (".py", ".js", ".mjs", ".cjs", ".ts") and p.is_file():
            return str(p.resolve().parent)
    return None


class UsageError(Exception):
    pass


USAGE = "사용법: python -m gateway.proxy --server-id <id> [--server-dir <폴더>] -- <서버 실행 명령>"


def parse_args(argv: list[str]) -> tuple[str, str | None, list[str]]:
    if "--" not in argv:
        raise UsageError("서버 실행 명령 앞에 `--`가 필요합니다")
    i = argv.index("--")
    opts, cmd = argv[:i], argv[i + 1:]
    if not cmd:
        raise UsageError("`--` 뒤에 서버 실행 명령이 없습니다")
    server_id = server_dir = None
    it = iter(opts)
    for a in it:
        if a in ("--server-id", "--server-dir"):
            val = next(it, None)
            if val is None:
                raise UsageError(f"{a} 값이 없습니다")
            if a == "--server-id":
                server_id = val
            else:
                server_dir = val
        else:
            raise UsageError(f"모르는 옵션: {a}")
    if server_id is None:
        raise UsageError("--server-id가 필요합니다 (캐시·승인·신원 장부의 키)")
    if not SERVER_ID_RE.match(server_id):
        raise UsageError(f"--server-id 형식 위반: {server_id!r} (소문자·숫자·하이픈 1~40자)")
    if server_dir is not None:
        if not Path(server_dir).is_dir():
            raise UsageError(f"--server-dir 폴더가 없습니다: {server_dir}")
        server_dir = str(Path(server_dir).resolve())
    return server_id, server_dir, cmd


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # Windows는 stderr 기본 인코딩이 cp949라서 '⚠' 같은 문자를 로그에 쓰면 게이트웨이가 죽을 수 있다
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    try:
        server_id, server_dir, cmd = parse_args(argv)
    except UsageError as e:
        print(f"[gateway] {e}\n{USAGE}", file=sys.stderr)
        return 2

    logging.basicConfig(level=os.environ.get("LINKUD_LOG", "INFO"), stream=sys.stderr,
                        format="[gateway %(levelname)s] %(message)s")
    proto_in, proto_out = sys.stdin.buffer, sys.stdout.buffer
    sys.stdout = sys.stderr  # 이후 누가 print 해도 통신 선을 더럽히지 않게 (SPEC 2장)

    gw = Gateway(server_id, cmd, proto_in, proto_out, server_dir=server_dir)
    return gw.run()


if __name__ == "__main__":
    sys.exit(main())
