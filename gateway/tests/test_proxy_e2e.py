"""게이트웨이를 실제 프로세스로 띄워서 가짜 MCP 서버와 끝까지 주고받는 테스트.

기본은 개발용 가짜 검사기(LINKUD_DEV_CHECKERS=1). DB·로그는 임시 폴더.
"""

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from gateway.cache import TrustStore

ROOT = Path(__file__).resolve().parents[2]
FAKE = Path(__file__).with_name("fake_server.py")


def gateway_env(tmp: str, dev=True, **extra) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("LINKUD_", "FAKE_"))}
    env.update({"LINKUD_DB": f"{tmp}/t.db", "LINKUD_AUDIT": f"{tmp}/audit.jsonl", "PYTHONPATH": str(ROOT),
                "LINKUD_LOG": "WARNING"})
    if dev:
        env["LINKUD_DEV_CHECKERS"] = "1"
    env.update(extra)
    return env


class Session:
    def __init__(self, tmp: str, server_id="fake-calc", dev=True, args=None, server_cmd=None, **extra):
        args = ["--server-id", server_id] if args is None else args
        server_cmd = server_cmd or [sys.executable, str(FAKE)]
        self.p = subprocess.Popen([sys.executable, "-m", "gateway.proxy", *args, "--", *server_cmd],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  cwd=tmp, env=gateway_env(tmp, dev, **extra))
        self.q: queue.Queue = queue.Queue()
        self.bad_lines: list[bytes] = []
        threading.Thread(target=self._read, daemon=True).start()
        self.next_id = 0

    def _read(self):
        for line in iter(self.p.stdout.readline, b""):
            try:
                self.q.put(json.loads(line))
            except json.JSONDecodeError:  # 통신 선에 JSON이 아닌 줄이 섞임 (SPEC 2장 위반)
                self.bad_lines.append(line)

    def request(self, method, params=None):
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        return self.q.get(timeout=15)

    def send(self, msg):
        self.p.stdin.write((json.dumps(msg) + "\n").encode())
        self.p.stdin.flush()

    def start(self):
        init = self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                            "clientInfo": {"name": "test", "version": "0"}})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return init

    def tools(self) -> dict:
        return {t["name"]: t for t in self.request("tools/list")["result"]["tools"]}

    def call(self, name):
        return self.request("tools/call", {"name": name, "arguments": {}})

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)
        self.p.stdout.close()
        self.p.stderr.close()


def walk_keys(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from walk_keys(v)
    elif isinstance(node, list):
        for x in node:
            yield from walk_keys(x)


class ProxyE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def audit(self) -> list[dict]:
        p = self.dir / "audit.jsonl"
        if not p.exists():
            return []
        with open(p, encoding="utf-8") as f:
            return [json.loads(x) for x in f]

    def store(self) -> TrustStore:
        return TrustStore(self.dir / "t.db")

    def test_full_flow(self):
        s = Session(self.tmp.name)
        try:
            init = s.start()
            self.assertEqual(init["result"]["serverInfo"]["name"], "fake-calc")  # initialize는 그대로 통과

            tools = s.tools()
            self.assertIn("add", tools)                      # 허용 → 그대로
            self.assertEqual(tools["add"]["description"], "두 수를 더한다.")
            self.assertNotIn("steal", tools)                 # 차단 → 목록에서 제거
            self.assertNotIn("leaky", tools)                 # 제한 + 정제 불가 → 비노출

            ok = s.call("add")
            self.assertEqual(ok["result"]["content"][0]["text"], "called add")

            blocked = s.call("steal")
            self.assertEqual(blocked["error"]["code"], -32602)
            self.assertIn("참조: LK-", blocked["error"]["message"])
            self.assertNotIn("ssh", blocked["error"]["message"])  # 이유는 노출하지 않음

            for name in ("nope", "leaky"):  # 없는 도구와 숨긴 도구는 같은 응답 (떠보기 방지)
                r = s.call(name)
                self.assertEqual(r["error"]["code"], -32602)

            restricted = s.call("config")
            self.assertTrue(restricted["result"]["isError"])
            self.assertIn("승인", restricted["result"]["content"][0]["text"])

            # 대시보드 승인과 같은 동작 → 바로 다음 호출부터 통과
            store = self.store()
            pend = {v.tool: v for v in store.pending("dev")}
            self.assertEqual(set(pend), {"config", "leaky"})
            self.assertEqual(store.approve(pend["leaky"].rowid, "dev")[0], False)  # 정제 불가는 승인 불가
            self.assertEqual(store.approve(pend["config"].rowid, "dev")[0], True)
            after = s.call("config")
            self.assertEqual(after["result"]["content"][0]["text"], "called config")
            self.assertIn("error", s.call("leaky"))

            # 두 번째 목록: 캐시에서 바로 (판정 기록이 늘지 않음). 승인 후에도 정제본만 보인다
            tools2 = s.tools()
            self.assertEqual(tools2["config"]["description"], "관리자 승인이 필요한 도구입니다.")
            events = self.audit()
            self.assertEqual(sum(e["event"] == "verdict" for e in events), 4)
            self.assertTrue(all(e["mode"] == "dev" for e in events))
            self.assertTrue(all(e.get("server_id") == "fake-calc" for e in events if e["event"] != "approved"))
            self.assertEqual({v.key.mode for v in store.all()}, {"dev"})
            self.assertEqual(s.bad_lines, [])
        finally:
            s.close()

    def test_restricted_tool_is_sanitized(self):
        s = Session(self.tmp.name)
        try:
            s.start()
            cfg = s.tools()["config"]
            self.assertEqual(cfg["description"], "관리자 승인이 필요한 도구입니다.")
            self.assertNotIn("annotations", cfg)
            self.assertNotIn("title", cfg)
            keys = set(walk_keys(cfg["inputSchema"]))
            for banned in ("description", "title", "examples", "x-note"):
                self.assertNotIn(banned, keys)
            schema = cfg["inputSchema"]
            self.assertNotIn("default", schema["properties"]["key"])                # 문자열 기본값 제거
            inner = schema["properties"]["opts"]["items"]["properties"]["v"]
            self.assertEqual(inner, {"type": "integer", "minimum": 0, "default": 1})  # 구조·제약은 유지
            self.assertEqual(schema["required"], ["key"])
            self.assertEqual(schema["properties"]["unit"]["enum"], ["c", "f"])
        finally:
            s.close()

    def test_rugpull(self):
        s = Session(self.tmp.name, FAKE_RUGPULL="1")
        try:
            s.start()
            self.assertIn("add", s.tools())
            self.assertIn("result", s.call("add"))
            self.assertNotIn("add", s.tools())  # 설명이 바뀜 → 재검사 → 차단
            self.assertIn("error", s.call("add"))
        finally:
            s.close()

    def test_tool_gone_from_new_list_is_denied(self):
        s = Session(self.tmp.name, FAKE_DROP="1")
        try:
            s.start()
            self.assertIn("add", s.tools())
            self.assertIn("result", s.call("add"))
            self.assertNotIn("add", s.tools())          # 새 목록에 없음
            self.assertIn("error", s.call("add"))       # 지난 목록의 허용 판정으로 통과하면 안 된다
        finally:
            s.close()

    def test_duplicate_tool_name_hidden(self):
        s = Session(self.tmp.name, FAKE_DUP="1")
        try:
            s.start()
            self.assertNotIn("add", s.tools())
            self.assertIn("error", s.call("add"))
        finally:
            s.close()

    def test_batch_rejected(self):
        s = Session(self.tmp.name)
        try:
            s.start()
            s.send([{"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {"name": "steal"}}])
            resp = s.q.get(timeout=15)
            self.assertEqual(resp["error"]["code"], -32600)
        finally:
            s.close()

    def test_stdout_stays_clean(self):
        """검사기가 print 하고 서버가 잡음을 찍어도 AI 앱 쪽 stdout에는 JSON만 나간다 (SPEC 2장)."""
        s = Session(self.tmp.name, LINKUD_DEV_NOISY="1", FAKE_NOISY="1")
        try:
            s.start()
            self.assertIn("add", s.tools())
            self.assertIn("result", s.call("add"))
            self.assertEqual(s.bad_lines, [])
        finally:
            s.close()

    def test_checker_error_is_audited_and_restricts(self):
        s = Session(self.tmp.name, LINKUD_DEV_FAIL="supply_chain")
        try:
            s.start()
            tools = s.tools()
            self.assertEqual(tools["add"]["description"], "관리자 승인이 필요한 도구입니다.")  # 에러 → 제한
            self.assertNotIn("steal", tools)  # 차단이 에러보다 우선
            errs = [e for e in self.audit() if e["event"] == "checker_error"]
            self.assertEqual({e["checker"] for e in errs}, {"supply_chain"})
            self.assertEqual({e["tool"] for e in errs}, {"add", "steal", "config", "leaky"})
            self.assertTrue(all(isinstance(e["rowid"], int) and e["server_id"] == "fake-calc" for e in errs))
        finally:
            s.close()

    def test_same_server_name_different_id_not_shared(self):
        for sid in ("calc-a", "calc-b"):  # 둘 다 serverInfo.name = fake-calc
            s = Session(self.tmp.name, server_id=sid)
            try:
                s.start()
                s.tools()
            finally:
                s.close()
        verdicts = [e for e in self.audit() if e["event"] == "verdict"]
        self.assertEqual(len(verdicts), 8)  # 두 번째 서버도 처음부터 검사 (판정 공유 없음)
        self.assertEqual({v.server for v in self.store().all()}, {"calc-a", "calc-b"})

    def test_policy_change_invalidates(self):
        s = Session(self.tmp.name)
        try:
            s.start()
            s.tools()
        finally:
            s.close()
        pol = self.dir / "policy.yaml"
        shutil.copy(ROOT / "policy.yaml", pol)
        pol.write_text(pol.read_text(encoding="utf-8").replace("timeout_seconds: 10", "timeout_seconds: 9"),
                       encoding="utf-8")
        s = Session(self.tmp.name, LINKUD_POLICY=str(pol))
        try:
            s.start()
            s.tools()
        finally:
            s.close()
        self.assertEqual(sum(e["event"] == "verdict" for e in self.audit()), 8)  # 정책 지문이 달라 재판정
        self.assertEqual(len({v.key.policy_fp for v in self.store().all()}), 2)

    def test_real_mode_checker_errors_and_no_fingerprints_fail_closed(self):
        """실제 모드에서 검사기가 전부 에러이고 서버 지문도 못 구하면: 전부 제한, 원본은 절대 안 보이고,
        판정 재사용·승인도 안 된다 (결정 #26·#29).
        B·C가 레포에 있든 없든 같은 결과가 나오게: 정책은 없는 검사기만 가리키게 하고(→ 에러),
        서버는 모듈(-m)로 실행해 폴더를 모르게 만든다(→ C의 지문 함수가 있어도 빈 값)."""
        pol = self.dir / "policy.yaml"
        text = (ROOT / "policy.yaml").read_text(encoding="utf-8")
        text = text.replace("  injection: 0.6\n  supply_chain: 0.25\n  identity: 0.15",
                            "  missing_a: 0.6\n  missing_b: 0.4")
        self.assertIn("missing_a", text)
        pol.write_text(text, encoding="utf-8")
        s = Session(self.tmp.name, dev=False, server_cmd=[sys.executable, "-m", "gateway.tests.fake_server"],
                    LINKUD_POLICY=str(pol))
        try:
            s.start()
            shown = s.tools()
            # B의 scan이 있으면 정제본이 보이고, 없으면 숨겨진다. 어느 쪽이든 원본 설명은 절대 안 나간다
            self.assertTrue(all(t["description"] == "관리자 승인이 필요한 도구입니다." for t in shown.values()))
            r = s.call("add")
            self.assertTrue("error" in r or r["result"].get("isError"))   # 호출은 통과하지 않음
            s.tools()
        finally:
            s.close()
        store = self.store()
        vs = store.all("real")
        self.assertEqual({v.grade for v in vs}, {"restrict"})
        self.assertTrue(all(v.key.file_fp == "" for v in vs))
        self.assertFalse(store.approve(vs[0].rowid, "real")[0])
        self.assertEqual(sum(e["event"] == "verdict" for e in self.audit()), 8)  # 지문 없음 → 재사용 안 함
        self.assertEqual(len(vs), 4)  # 같은 키라 행은 덮어씀

    def test_outputschema_change_rechecks(self):
        """outputSchema만 바뀌어도 해시가 바뀌어 다시 검사한다 (결정 #35)."""
        s = Session(self.tmp.name, FAKE_RUGPULL_OUTPUT="1")
        try:
            s.start()
            s.tools()
            s.tools()
        finally:
            s.close()
        verdicts = [e for e in self.audit() if e["event"] == "verdict"]
        self.assertEqual(len(verdicts), 5)                      # 4개 + 바뀐 add 1개
        self.assertEqual([e["tool"] for e in verdicts[4:]], ["add"])

    def test_hash_churn_hides_and_denies(self):
        """목록마다 정의를 바꾸는 서버: 한도(여기선 1회)를 넘은 새 정의는 검사 없이 숨기고 호출도 거절 (결정 #38)."""
        pol = self.dir / "policy.yaml"
        text = (ROOT / "policy.yaml").read_text(encoding="utf-8").replace("max_changes_per_hour: 5", "max_changes_per_hour: 1")
        self.assertIn("max_changes_per_hour: 1", text)
        pol.write_text(text, encoding="utf-8")
        s = Session(self.tmp.name, FAKE_CHURN="1", LINKUD_POLICY=str(pol))
        try:
            s.start()
            self.assertIn("add", s.tools())              # 첫 목록: 세지 않음
            self.assertIn("add", s.tools())              # 1번째 변경: 한도 안 → 정상 검사
            self.assertNotIn("add", s.tools())           # 2번째 변경: 한도 초과 → 검사 없이 숨김
            self.assertIn("error", s.call("add"))        # 저장 안 한 판정 → '판정 없음'으로 거절
            self.assertIn("config", s.tools())           # 안 바뀐 도구는 그대로
        finally:
            s.close()
        churn = [e for e in self.audit() if e["event"] == "verdict" and "hash_churn" in e["signals"]]
        self.assertTrue(churn and all(e["rowid"] is None and e["tool"] == "add" for e in churn))
        self.assertFalse([v for v in self.store().all() if "hash_churn" in v.signals])  # DB에 저장 안 됨

    def test_child_env_withholds_secrets(self):
        """서버 프로세스에는 비밀처럼 보이는 변수·LINKUD_*를 넘기지 않고, --pass-env로 명시한 것만 넘긴다 (결정 #37)."""
        dump = self.dir / "env.json"
        s = Session(self.tmp.name, args=["--server-id", "fake-calc", "--pass-env", "GH_TOKEN"],
                    FAKE_ENV_DUMP=str(dump), MY_API_KEY="k", OPENAI_API_KEY="sk-x", DB_PASSWORD="p",
                    SSH_AUTH_SOCK="/tmp/agent", GH_TOKEN="t", PLAIN_VAR="z")
        try:
            s.start()
        finally:
            s.close()
        names = set(json.loads(dump.read_text(encoding="utf-8")))
        self.assertIn("PLAIN_VAR", names)
        self.assertIn("GH_TOKEN", names)                        # 명시해서 넘김
        for hidden in ("MY_API_KEY", "OPENAI_API_KEY", "DB_PASSWORD", "SSH_AUTH_SOCK"):
            self.assertNotIn(hidden, names)
        self.assertFalse([n for n in names if n.startswith("LINKUD_")])


class CliTest(unittest.TestCase):
    def run_gw(self, *args):
        tmp = tempfile.mkdtemp()
        try:
            return subprocess.run([sys.executable, "-m", "gateway.proxy", *args], capture_output=True,
                                  env=gateway_env(tmp), cwd=tmp, timeout=15, stdin=subprocess.DEVNULL)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_server_id_required(self):
        r = self.run_gw("--", sys.executable, str(FAKE))
        self.assertEqual(r.returncode, 2)
        self.assertIn("--server-id", r.stderr.decode("utf-8"))
        self.assertEqual(r.stdout, b"")

    def test_server_id_format(self):
        for bad in ("Calc", "calc_ok", "", "a" * 41, "../x"):
            r = self.run_gw("--server-id", bad, "--", sys.executable, str(FAKE))
            self.assertEqual(r.returncode, 2, bad)

    def test_server_dir_must_exist(self):
        r = self.run_gw("--server-id", "x", "--server-dir", "/no/such/dir", "--", sys.executable, str(FAKE))
        self.assertEqual(r.returncode, 2)

    def test_pass_env_name_checked(self):
        for bad in ("A-B", "LINKUD_DB", "1X"):
            r = self.run_gw("--server-id", "x", "--pass-env", bad, "--", sys.executable, str(FAKE))
            self.assertEqual(r.returncode, 2, bad)


class ChildEnvUnit(unittest.TestCase):
    def test_pass_env_case_insensitive(self):
        from gateway.proxy import child_env
        env, withheld = child_env({"GITHUB_TOKEN": "t"}, ["github_token"])
        self.assertEqual(env, {"GITHUB_TOKEN": "t"})
        self.assertEqual(withheld, [])

    def test_rules(self):
        from gateway.proxy import child_env
        env, withheld = child_env({"PATH": "/bin", "SYSTEMROOT": "C:\\Windows", "PYTHONPATH": "x",
                                   "AWS_SECRET_ACCESS_KEY": "s", "GITHUB_TOKEN": "t", "LINKUD_DB": "d",
                                   "KEYBOARD_LAYOUT": "us", "SESSIONNAME": "Console"}, ["GITHUB_TOKEN"])
        self.assertEqual(set(env), {"PATH", "SYSTEMROOT", "PYTHONPATH", "GITHUB_TOKEN", "KEYBOARD_LAYOUT",
                                    "SESSIONNAME"})
        self.assertEqual(set(withheld), {"AWS_SECRET_ACCESS_KEY", "LINKUD_DB"})


class ChurnUnit(unittest.TestCase):
    """결정 #38: 첫 목록 이후 '새 해시가 섞인 목록'이 시간당 한도를 넘으면 새 해시는 검사 없이 제한."""

    def gw(self, limit=2, window=3600):
        import threading
        from collections import deque
        from gateway.proxy import Gateway
        g = object.__new__(Gateway)
        g.churn_limit, g.churn_window = limit, window
        g._seen_hashes, g._change_times, g._first_list_done = set(), deque(), False
        g._in_first_listing = g._listing_counted = g._listing_over = False
        g._churn_lock = threading.Lock()
        return g

    def test_first_list_and_unchanged_lists_are_free(self):
        g = self.gw(limit=1)
        self.assertEqual(g._churn_check(["a", "b", "c", "d", "e", "f"]), set())
        for _ in range(10):
            self.assertEqual(g._churn_check(["a", "b", "c"]), set())

    def test_over_limit_new_hashes_skipped(self):
        g = self.gw(limit=2)
        g._churn_check(["a"])
        self.assertEqual(g._churn_check(["b"]), set())
        self.assertEqual(g._churn_check(["c"]), set())
        self.assertEqual(g._churn_check(["d", "c"]), {"d"})
        self.assertEqual(g._churn_check(["d"]), {"d"})          # 기억하지 않음

    def test_window_expires(self):
        import time
        g = self.gw(limit=1, window=0.05)
        g._churn_check(["a"])
        g._churn_check(["b"])
        self.assertEqual(g._churn_check(["c"]), {"c"})
        time.sleep(0.1)
        self.assertEqual(g._churn_check(["c"]), set())

    def test_pages_of_one_listing_count_once(self):
        """cursor로 나뉜 한 목록은 한 번만 센다. 첫 목록의 뒤 페이지는 세지 않는다."""
        g = self.gw(limit=1)
        self.assertEqual(g._churn_check(["a"], True), set())
        self.assertEqual(g._churn_check(["b", "c"], False), set())   # 첫 목록 2페이지 → 안 셈
        self.assertEqual(g._churn_check(["a", "d"], True), set())    # 새 목록, 1번째 변경
        self.assertEqual(g._churn_check(["e"], False), set())        # 같은 목록 2페이지 → 이미 셈
        self.assertEqual(g._churn_check(["f"], True), {"f"})         # 2번째 변경 → 한도 초과
        self.assertEqual(g._churn_check(["g"], False), {"g"})        # 같은 목록 뒤 페이지도 같은 처리


if __name__ == "__main__":
    unittest.main()
