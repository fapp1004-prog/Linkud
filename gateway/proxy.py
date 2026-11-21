"""(A) proxy.py — 담당: A. 다른 사람은 고치지 않는다.

게이트웨이 본체. 도구 서버를 자식 프로세스로 실행하고, AI 앱과 서버 사이의
JSON-RPC 메시지(한 줄에 하나)를 중계하면서 tools/list·tools/call을 통제한다. (SPEC 2·6·7장)

실행:
    python -m gateway.proxy -- python testservers/calc_ok/server.py
    (`--` 뒤가 진짜 서버 실행 명령)

주의: 이 프로세스의 stdout은 곧 AI 앱과의 통신 선이다. print()가 섞이면 연결이 깨지므로
시작하자마자 sys.stdout을 stderr로 돌려놓는다. 프로토콜 출력은 _out()으로만 한다.
"""

import json
import logging
import os
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from gateway import audit
from gateway.cache import TrustStore, Verdict, tool_hash
from gateway.policy import SERVER_LEVEL, decide, load_checkers, load_policy, run_checker

log = logging.getLogger("gateway")

RESTRICTED_DESCRIPTION = "관리자 승인이 필요한 도구입니다."
BLOCK_MESSAGE = "보안 정책에 의해 사용할 수 없는 도구입니다. (참조: {ref})"
RESTRICT_MESSAGE = "관리자 승인이 필요한 도구입니다. 승인 후 다시 시도하세요. (참조: {ref})"


class Gateway:
    def __init__(self, server_cmd: list[str], client_in, client_out,
                 store: TrustStore | None = None, policy: dict | None = None):
        self.server_cmd = server_cmd
        self.client_in = client_in          # AI 앱 → 게이트웨이 (바이너리 스트림)
        self.client_out = client_out        # 게이트웨이 → AI 앱
        self.store = store or TrustStore()
        self.policy = policy or load_policy()
        self.checkers = load_checkers(self.policy)
        self.timeout = float(self.policy.get("checkers", {}).get("timeout_seconds", 10))

        self.proc: subprocess.Popen | None = None
        self._client_lock = threading.Lock()
        self._server_lock = threading.Lock()
        self._pending: dict[str, str] = {}          # 요청 id → method (응답에는 method가 없어서)
        self._pending_lock = threading.Lock()
        self._tools: dict[str, str] = {}            # 마지막 tools/list의 도구 이름 → 해시
        self._verify_locks: dict[str, threading.Lock] = {}
        self._verify_locks_guard = threading.Lock()
        self._server_results: dict | None = None    # 서버 단위 검사 결과 (프로세스당 한 번)
        self.server_info = {"name": "", "version": "", "dir": _server_dir(server_cmd),
                            "command": list(server_cmd)}

    # ── 서버 이름: initialize 응답의 serverInfo.name, 없으면 실행 파일 이름 ──
    @property
    def server_name(self) -> str:
        return self.server_info["name"] or Path(self.server_cmd[-1]).parent.name or self.server_cmd[0]

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
        self.proc = subprocess.Popen(
            [exe, *self.server_cmd[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=sys.stderr, bufsize=0,
        )
        log.info("서버 실행: %s (pid %s)", " ".join(self.server_cmd), self.proc.pid)
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
            with self._pending_lock:
                self._pending[_key(msg["id"])] = method
        if method == "tools/call":
            if self.guard_call(msg):
                self.to_server(msg)
            else:
                with self._pending_lock:
                    self._pending.pop(_key(msg["id"]), None)
            return
        self.to_server(msg)

    def guard_call(self, msg) -> bool:
        """tools/call 허용 여부. 검사기는 부르지 않고 캐시(SQLite)만 본다. False면 거부 응답까지 보낸다."""
        req_id = msg.get("id")
        name = (msg.get("params") or {}).get("name", "")
        h = self._tools.get(name)
        v = self.store.get(self.server_name, h) if h else None
        state = v.effective if v else "unknown"

        if state in ("allow", "approved"):
            audit.write("call_allowed", server=self.server_name, tool=name, hash=h, grade=state)
            return True

        ref = audit.new_ref()
        if state == "restrict":
            audit.write("call_denied", server=self.server_name, tool=name, hash=h, grade="restrict", ref=ref)
            self.to_client({"jsonrpc": "2.0", "id": req_id, "result": {
                "content": [{"type": "text", "text": RESTRICT_MESSAGE.format(ref=ref)}], "isError": True}})
        else:  # block, 목록에 없는 도구, 판정 기록 없음 → 모두 차단 (fail-closed)
            audit.write("call_denied", server=self.server_name, tool=name, hash=h,
                        grade=state if v else "unknown", ref=ref)
            self.to_client(_error(req_id, -32602, BLOCK_MESSAGE.format(ref=ref)))
        return False

    # ── 서버 → AI 앱 ──
    def handle_server(self, msg) -> None:
        if isinstance(msg, dict) and "id" in msg and "method" not in msg:  # 응답
            with self._pending_lock:
                method = self._pending.pop(_key(msg["id"]), None)
            if method == "initialize" and "result" in msg:
                info = msg["result"].get("serverInfo") or {}
                self.server_info["name"] = str(info.get("name", ""))
                self.server_info["version"] = str(info.get("version", ""))
                log.info("서버 신원(자기 신고): %s %s", self.server_info["name"], self.server_info["version"])
            elif method == "tools/list" and "result" in msg:
                msg = self.filter_tools_response(msg)
        self.to_client(msg)

    def filter_tools_response(self, msg: dict) -> dict:
        """tools/list 응답을 검사가 끝날 때까지 붙잡고, 등급대로 걸러서 돌려준다."""
        result = dict(msg["result"])
        tools = result.get("tools") or []
        try:
            verdicts = self.verify_tools(tools)
        except Exception as e:  # 검증 자체가 망가지면 아무 도구도 보여주지 않는다 (fail-closed)
            log.exception("도구 검증 실패")
            audit.write("checker_error", server=self.server_name, error=f"{type(e).__name__}: {e}")
            result["tools"] = []
            return {**msg, "result": result}

        shown = []
        for tool, v in zip(tools, verdicts):
            self._tools[tool.get("name", "")] = v.hash
            state = v.effective
            if state in ("allow", "approved"):
                shown.append(tool)
            elif state == "restrict":
                shown.append({**tool, "description": RESTRICTED_DESCRIPTION})
            # block → 목록에서 뺀다
        result["tools"] = shown
        return {**msg, "result": result}

    # ── 검증 ──
    def verify_tools(self, tools: list[dict]) -> list[Verdict]:
        with ThreadPoolExecutor(max_workers=4) as ex:
            return list(ex.map(self.verify_tool, tools))

    def _lock_for(self, h: str) -> threading.Lock:
        with self._verify_locks_guard:
            return self._verify_locks.setdefault(h, threading.Lock())

    def verify_tool(self, tool: dict) -> Verdict:
        h = tool_hash(tool)
        cached = self.store.get(self.server_name, h)
        if cached:
            return cached
        with self._lock_for(h):  # 같은 도구에 대한 검사는 한 번만
            cached = self.store.get(self.server_name, h)
            if cached:
                return cached
            results = {}
            for name, fn in self.checkers.items():
                if name not in SERVER_LEVEL:
                    results[name] = run_checker(name, fn, tool, self.server_info, self.timeout)
            results.update(self.server_level_results(tool))
            d = decide(results, self.policy)
            v = Verdict(
                server=self.server_name, tool=tool.get("name", ""), hash=h, grade=d.grade, score=d.score,
                signals=d.signals, reasons=d.reasons,
                results=[r if isinstance(r, dict) else {"checker": n, "error": f"{type(r).__name__}: {r}"}
                         for n, r in results.items()],
            )
            self.store.put(v)
            audit.write("verdict", server=v.server, tool=v.tool, hash=h, score=v.score, grade=v.grade,
                        signals=v.signals, reasons=v.reasons)
            log.info("판정 %s/%s → %s (%s점)", v.server, v.tool, v.grade, v.score)
            return v

    def server_level_results(self, tool: dict) -> dict:
        """공급망·신원 검사는 서버당 한 번만 돌린다. 에러 결과는 저장하지 않고 다음에 다시 시도한다."""
        if self._server_results is not None:
            return self._server_results
        results = {}
        for name, fn in self.checkers.items():
            if name in SERVER_LEVEL:
                results[name] = run_checker(name, fn, tool, self.server_info, self.timeout)
        if not any(isinstance(r, BaseException) for r in results.values()):
            self._server_results = results
        return results


# ── 도우미 ───────────────────────────────────────────

def _key(req_id) -> str:
    return json.dumps(req_id)  # 1과 "1"을 다른 id로 구분


def _error(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _server_dir(cmd: list[str]) -> str:
    for part in reversed(cmd):
        p = Path(part)
        if p.suffix in (".py", ".js", ".mjs", ".ts") and p.exists():
            return str(p.resolve().parent)
    return os.getcwd()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--" in argv:
        argv = argv[argv.index("--") + 1:]
    if not argv:
        print("사용법: python -m gateway.proxy -- <서버 실행 명령>", file=sys.stderr)
        return 2

    # Windows는 stderr 기본 인코딩이 cp949라서 '⚠' 같은 문자를 로그에 쓰면 게이트웨이가 죽을 수 있다
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    logging.basicConfig(level=os.environ.get("LINKUD_LOG", "INFO"), stream=sys.stderr,
                        format="[gateway %(levelname)s] %(message)s")
    proto_in, proto_out = sys.stdin.buffer, sys.stdout.buffer
    sys.stdout = sys.stderr  # 이후 누가 print 해도 통신 선을 더럽히지 않게

    gw = Gateway(argv, proto_in, proto_out)
    return gw.run()


if __name__ == "__main__":
    sys.exit(main())
