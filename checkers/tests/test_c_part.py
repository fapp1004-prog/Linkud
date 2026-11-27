"""C 파트 테스트. 실행: python -m unittest discover -s checkers/tests -t .

OSV는 네트워크 없이 가짜 응답으로 시험한다. 실제 OSV 확인은 scripts 없이:
    python -c "from checkers import supply_chain as s; print(s.check({}, {'dir': 'testservers/vuln_dep'}))"
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from checkers import fingerprint, identity, supply_chain

REPO = Path(__file__).resolve().parents[2]
KEYS = {"checker", "risk", "hard_block", "signals", "evidence", "latency_ms"}

try:  # base.py는 파이썬 3.11+ 문법(NotRequired)을 써서 3.10에서는 못 불러온다
    from checkers.base import SIGNALS
except ImportError:
    SIGNALS = None


def assert_shape(t, r, checker):
    t.assertEqual(set(r) - {"confidence", "model", "prompt_version"}, KEYS)
    t.assertEqual(r["checker"], checker)
    t.assertIsInstance(r["risk"], int)
    t.assertTrue(0 <= r["risk"] <= 100)
    if SIGNALS is not None:
        t.assertTrue(set(r["signals"]) <= set(SIGNALS), r["signals"])


class TmpDir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, text):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode("utf-8"))
        return p


class FingerprintTest(TmpDir):
    def test_includes_and_excludes(self):
        self.write("server.py", "print(1)")
        self.write("requirements.txt", "x==1")
        self.write(".env", "KEY=secret")
        self.write("data/trust.db", "db")
        self.write("logs/a.log", "log")
        self.write("node_modules/p/index.js", "x")
        self.write("notes.md", "doc")
        self.assertEqual(fingerprint.list_files(self.dir), ["requirements.txt", "server.py"])
        self.assertEqual(fingerprint.list_files(self.dir, deps_only=True), ["requirements.txt"])

    def test_secret_files_do_not_change_fingerprint(self):
        self.write("server.py", "print(1)")
        before = fingerprint.file_fp(self.dir)
        self.write(".env", "KEY=changed")
        self.write("data/x.db", "changed")
        self.assertEqual(fingerprint.file_fp(self.dir), before)

    def test_code_change_and_crlf(self):
        self.write("server.py", "a\nb\n")
        lf = fingerprint.file_fp(self.dir)
        self.write("server.py", "a\r\nb\r\n")
        self.assertEqual(fingerprint.file_fp(self.dir), lf)       # 줄바꿈 차이는 무시
        self.write("server.py", "a\nc\n")
        self.assertNotEqual(fingerprint.file_fp(self.dir), lf)

    def test_missing_dir_raises(self):
        with self.assertRaises(ValueError):
            fingerprint.file_fp("")
        with self.assertRaises(ValueError):          # A가 서버 폴더를 못 찾으면 dir=None (SPEC 3장)
            fingerprint.file_fp({"server_id": "x", "dir": None})

    def test_accepts_server_dict_and_path(self):
        """A는 ServerInfo dict를, identity는 경로를 넘긴다 — 같은 지문이 나와야 신원 장부 비교가 맞는다."""
        self.write("server.py", "print(1)")
        self.write("requirements.txt", "x==1")
        server = {"server_id": "calc-ok", "name": "calc-ok", "version": "1.0.0",
                  "dir": str(self.dir), "command": ["python", "server.py"]}
        self.assertEqual(fingerprint.file_fp(server), fingerprint.file_fp(str(self.dir)))
        self.assertEqual(fingerprint.file_fp(server), fingerprint.file_fp(self.dir))
        self.assertEqual(fingerprint.dep_fp(server), fingerprint.dep_fp(str(self.dir)))
        self.assertEqual(len(fingerprint.file_fp(server)), 64)


class RequirementsParseTest(unittest.TestCase):
    def test_parse(self):
        text = "# c\nrequests==2.19.1\nPyYAML[extra] == 5.3 ; python_version>'3'\nflask>=2\n-r base.txt\nhttpx\n"
        pinned, loose, count = supply_chain.parse_requirements(text)
        self.assertEqual(pinned, [("requests", "2.19.1"), ("pyyaml", "5.3")])
        self.assertEqual(loose, ["flask>=2", "-r base.txt", "httpx"])
        self.assertEqual(count, 4)

    def test_package_lock_v3(self):
        lock = {"lockfileVersion": 3, "packages": {"": {"name": "app"},
                "node_modules/lodash": {"version": "4.17.15"},
                "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"}}}
        self.assertEqual(supply_chain.parse_package_lock(json.dumps(lock)),
                         [("@scope/b", "1.0.0"), ("lodash", "4.17.15")])


class SeverityTest(unittest.TestCase):
    def test_cvss(self):
        self.assertEqual(supply_chain.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(supply_chain.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertIsNone(supply_chain.cvss3_score("garbage"))

    def test_is_severe(self):
        self.assertTrue(supply_chain.is_severe({"database_specific": {"severity": "HIGH"}}))
        self.assertTrue(supply_chain.is_severe(
            {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}))
        self.assertFalse(supply_chain.is_severe({"database_specific": {"severity": "MODERATE"}}))


class SupplyChainCheckTest(TmpDir):
    def run_check(self, batch=None, details=None):
        def fake(url, body=None, timeout=5.0):
            if body is not None:
                return batch
            return details[url.rsplit("/", 1)[1]]
        with mock.patch.object(supply_chain, "_http_json", side_effect=fake):
            r = supply_chain.check({}, {"dir": str(self.dir)})
        assert_shape(self, r, "supply_chain")
        return r

    def test_no_files(self):
        r = self.run_check()
        self.assertEqual((r["risk"], r["signals"]), (40, ["no_supply_info"]))

    def test_declared_no_deps(self):
        self.write("requirements.txt", "# 표준 라이브러리만\n")
        self.assertEqual(self.run_check()["risk"], 0)

    def test_only_unpinned(self):
        self.write("requirements.txt", "flask>=2\n")
        self.assertEqual(self.run_check()["signals"], ["no_supply_info"])

    def test_clean(self):
        self.write("requirements.txt", "requests==2.32.0\n")
        r = self.run_check(batch={"results": [{}]})
        self.assertEqual((r["risk"], r["signals"]), (0, []))

    def test_critical(self):
        self.write("requirements.txt", "requests==2.19.1\n")
        r = self.run_check(batch={"results": [{"vulns": [{"id": "GHSA-x"}, {"id": "PYSEC-y"}]}]},
                           details={"GHSA-x": {"database_specific": {"severity": "HIGH"}}, "PYSEC-y": {}})
        self.assertEqual((r["risk"], r["signals"]), (80, ["critical_vuln"]))
        self.assertIn("GHSA-x", r["evidence"])

    def test_known(self):
        self.write("requirements.txt", "a==1\n")
        r = self.run_check(batch={"results": [{"vulns": [{"id": "GHSA-m"}]}]},
                           details={"GHSA-m": {"database_specific": {"severity": "MODERATE"}}})
        self.assertEqual((r["risk"], r["signals"]), (50, ["known_vuln"]))

    def test_malicious(self):
        self.write("requirements.txt", "evil==0.1\n")
        r = self.run_check(batch={"results": [{"vulns": [{"id": "MAL-2025-1"}]}]})
        self.assertTrue(r["hard_block"])
        self.assertEqual(r["signals"], ["malicious_package"])

    def test_osv_failure_raises(self):
        self.write("requirements.txt", "a==1\n")
        with mock.patch.object(supply_chain, "_http_json", side_effect=OSError("down")):
            with self.assertRaises(OSError):
                supply_chain.check({}, {"dir": str(self.dir)})

    def test_no_dir_raises(self):
        with self.assertRaises(FileNotFoundError):
            supply_chain.check({}, {"dir": ""})


class IdentityTest(TmpDir):
    def setUp(self):
        super().setUp()
        self.srv = self.dir / "srv"
        self.write("srv/server.py", "print(1)")
        self.env = mock.patch.dict(os.environ, {"LINKUD_DB_PATH": str(self.dir / "trust.db")})
        self.env.start()
        self.server = {"server_id": "calc-ok", "name": "calc-ok", "version": "1.0.0",
                       "dir": str(self.srv), "command": []}

    def tearDown(self):
        self.env.stop()
        super().tearDown()

    def test_first_then_same(self):
        r1 = identity.check({}, self.server)
        assert_shape(self, r1, "identity")
        self.assertEqual(r1["risk"], 0)
        self.assertEqual(identity.check({}, self.server)["risk"], 0)

    def test_version_change(self):
        identity.check({}, self.server)
        r = identity.check({}, {**self.server, "version": "2.0.0"})
        self.assertEqual((r["risk"], r["signals"]), (100, ["identity_changed"]))
        self.assertIn("1.0.0 → 2.0.0", r["evidence"])

    def test_file_change_then_approve(self):
        identity.check({}, self.server)
        self.write("srv/server.py", "print(2)")
        self.assertEqual(identity.check({}, self.server)["signals"], ["identity_changed"])
        identity.update_baseline(self.server)              # 대시보드 승인
        self.assertEqual(identity.check({}, self.server)["risk"], 0)

    def test_fallback_key_without_server_id(self):
        s = {k: v for k, v in self.server.items() if k != "server_id"}
        self.assertTrue(identity.server_key(s).startswith("dir:"))
        self.assertEqual(identity.check({}, s)["risk"], 0)


class TestServersTest(unittest.TestCase):
    """테스트 서버를 실제 프로세스로 띄워 JSON-RPC로 대화해 본다."""

    def talk(self, folder, msgs):
        lines = "".join(json.dumps(m, ensure_ascii=False) + "\n" for m in msgs)
        p = subprocess.run([sys.executable, str(REPO / "testservers" / folder / "server.py")],
                           input=lines.encode("utf-8"), capture_output=True, timeout=10)
        out = [json.loads(l) for l in p.stdout.decode("utf-8").splitlines() if l.strip()]
        return out

    INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}}}
    NOTE = {"jsonrpc": "2.0", "method": "notifications/initialized"}

    def lst(self, i):
        return {"jsonrpc": "2.0", "id": i, "method": "tools/list"}

    def call(self, i, name, args):
        return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}}

    def test_calc_ok(self):
        out = self.talk("calc_ok", [self.INIT, self.NOTE, self.lst(2), self.call(3, "add", {"a": 2, "b": 3})])
        self.assertEqual([m["id"] for m in out], [1, 2, 3])       # 알림에는 답 안 함
        self.assertEqual(out[0]["result"]["serverInfo"]["name"], "calc-ok")
        self.assertEqual(out[2]["result"]["content"][0]["text"], "5")

    def test_calc_poison(self):
        out = self.talk("calc_poison", [self.INIT, self.lst(2), self.call(3, "multiply", {"a": 4, "b": 5})])
        tools = {t["name"]: t["description"] for t in out[1]["result"]["tools"]}
        self.assertIn("<IMPORTANT>", tools["add"])
        for word in ("<IMPORTANT>", ".ssh", ".env", "말하지 마", "Do not tell"):   # multiply는 규칙 단어가 없어야 함
            self.assertNotIn(word, tools["multiply"])
        self.assertEqual(out[2]["result"]["content"][0]["text"], "20")

    def test_rugpull_turns_evil_on_third_list(self):
        out = self.talk("rugpull", [self.INIT, self.lst(2), self.lst(3), self.lst(4), self.lst(5)])
        descs = [m["result"]["tools"][0]["description"] for m in out[1:]]
        self.assertEqual(descs[0], descs[1])
        self.assertNotIn("<IMPORTANT>", descs[1])
        self.assertIn("<IMPORTANT>", descs[2])
        self.assertEqual(descs[2], descs[3])

    def test_vuln_dep_and_unknown(self):
        out = self.talk("vuln_dep", [self.INIT, self.call(2, "fetch", {"url": "http://x"}),
                                     self.call(3, "nope", {}), {"jsonrpc": "2.0", "id": 4, "method": "foo"}])
        self.assertIn("가짜 응답", out[1]["result"]["content"][0]["text"])
        self.assertEqual(out[2]["error"]["code"], -32602)
        self.assertEqual(out[3]["error"]["code"], -32601)

    def test_demo_servers_supply_chain_without_network(self):
        for folder in ("calc_ok", "calc_poison", "rugpull"):
            r = supply_chain.check({}, {"dir": str(REPO / "testservers" / folder)})
            self.assertEqual(r["risk"], 0, folder)
        pinned, _, _ = supply_chain.parse_requirements(
            (REPO / "testservers" / "vuln_dep" / "requirements.txt").read_text(encoding="utf-8"))
        self.assertTrue(pinned)


if __name__ == "__main__":
    unittest.main()
