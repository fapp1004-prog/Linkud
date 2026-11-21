"""게이트웨이를 실제 프로세스로 띄워서 가짜 MCP 서버와 끝까지 주고받는 테스트.

개발용 가짜 검사기(LINKUD_DEV_CHECKERS=1)를 쓴다. DB·로그는 임시 폴더.
"""

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from gateway.cache import TrustStore

ROOT = Path(__file__).resolve().parents[2]
FAKE = Path(__file__).with_name("fake_server.py")


class Session:
    def __init__(self, tmp: str, rugpull=False):
        env = {**os.environ, "LINKUD_DEV_CHECKERS": "1", "LINKUD_DB": f"{tmp}/t.db",
               "LINKUD_AUDIT": f"{tmp}/audit.jsonl", "PYTHONPATH": str(ROOT), "LINKUD_LOG": "WARNING"}
        if rugpull:
            env["FAKE_RUGPULL"] = "1"
        self.p = subprocess.Popen([sys.executable, "-m", "gateway.proxy", "--", sys.executable, str(FAKE)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  cwd=tmp, env=env)
        self.q: queue.Queue = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self.raw_lines: list[bytes] = []
        self.next_id = 0

    def _read(self):
        for line in iter(self.p.stdout.readline, b""):
            self.raw_lines.append(line)
            self.q.put(json.loads(line))  # JSON이 아닌 줄이 섞이면 여기서 터진다 (stdout 오염 검사)

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

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)
        self.p.stdout.close()
        self.p.stderr.close()


class ProxyE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_flow(self):
        s = Session(self.tmp.name)
        try:
            init = s.start()
            self.assertEqual(init["result"]["serverInfo"]["name"], "fake-calc")  # initialize는 그대로 통과

            tools = {t["name"]: t for t in s.request("tools/list")["result"]["tools"]}
            self.assertIn("add", tools)                                         # 허용
            self.assertNotIn("steal", tools)                                    # 차단 → 목록에서 제거
            self.assertEqual(tools["config"]["description"], "관리자 승인이 필요한 도구입니다.")  # 제한 → 설명 교체

            ok = s.request("tools/call", {"name": "add", "arguments": {"a": 1, "b": 2}})
            self.assertEqual(ok["result"]["content"][0]["text"], "called add")

            blocked = s.request("tools/call", {"name": "steal", "arguments": {}})
            self.assertEqual(blocked["error"]["code"], -32602)
            self.assertIn("참조: LK-", blocked["error"]["message"])
            self.assertNotIn("ssh", blocked["error"]["message"])               # 이유는 노출하지 않음

            unknown = s.request("tools/call", {"name": "nope", "arguments": {}})
            self.assertIn("error", unknown)

            restricted = s.request("tools/call", {"name": "config", "arguments": {}})
            self.assertTrue(restricted["result"]["isError"])
            self.assertIn("승인", restricted["result"]["content"][0]["text"])

            # 대시보드 승인과 같은 동작 → 바로 다음 호출부터 통과
            store = TrustStore(Path(self.tmp.name) / "t.db")
            pend = store.pending()
            self.assertEqual([v.tool for v in pend], ["config"])
            self.assertTrue(store.approve(pend[0].server, pend[0].hash))
            after = s.request("tools/call", {"name": "config", "arguments": {}})
            self.assertEqual(after["result"]["content"][0]["text"], "called config")

            # 두 번째 목록: 캐시에서 바로 (판정 기록이 늘지 않음)
            s.request("tools/list")
            with open(Path(self.tmp.name) / "audit.jsonl", encoding="utf-8") as f:
                events = [json.loads(x) for x in f]
            self.assertEqual(sum(e["event"] == "verdict" for e in events), 3)
            self.assertTrue(any(e["event"] == "approved" or e["event"] == "call_allowed" for e in events))
        finally:
            s.close()

    def test_rugpull(self):
        s = Session(self.tmp.name, rugpull=True)
        try:
            s.start()
            first = {t["name"] for t in s.request("tools/list")["result"]["tools"]}
            self.assertIn("add", first)
            self.assertIn("result", s.request("tools/call", {"name": "add", "arguments": {}}))

            second = {t["name"] for t in s.request("tools/list")["result"]["tools"]}  # 설명이 바뀜 → 재검사 → 차단
            self.assertNotIn("add", second)
            self.assertIn("error", s.request("tools/call", {"name": "add", "arguments": {}}))
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


if __name__ == "__main__":
    unittest.main()
