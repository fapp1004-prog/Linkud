import sqlite3
import tempfile
import unittest
from pathlib import Path

from gateway.cache import CacheKey, TrustStore, Verdict, tool_hash


def key(**over) -> CacheKey:
    base = dict(server_id="s", tool_hash="h1", file_fp="f", dep_fp="d", policy_fp="p", mode="dev")
    base.update(over)
    return CacheKey(**base)


class HashTest(unittest.TestCase):
    def test_key_order_does_not_matter(self):
        a = {"name": "add", "description": "d", "inputSchema": {"a": 1, "b": 2}}
        b = {"inputSchema": {"b": 2, "a": 1}, "description": "d", "name": "add"}
        self.assertEqual(tool_hash(a), tool_hash(b))

    def test_one_char_changes_hash(self):
        a = {"name": "add", "description": "두 수를 더한다."}
        self.assertNotEqual(tool_hash(a), tool_hash({**a, "description": "두 수를 더한다!"}))

    def test_unrelated_fields_ignored(self):
        a = {"name": "add", "description": "d"}
        self.assertEqual(tool_hash(a), tool_hash({**a, "title": "x"}))


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "t.db"
        self.store = TrustStore(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_key_part_separates(self):
        """server_id·해시·지문·정책·모드 중 하나라도 다르면 다른 판정 (SPEC 6장)."""
        self.store.put(Verdict(key(), "a", "allow", 100))
        self.assertIsNotNone(self.store.get(key()))
        for part in ("server_id", "tool_hash", "file_fp", "dep_fp", "policy_fp", "mode"):
            self.assertIsNone(self.store.get(key(**{part: "other"})), part)

    def test_incomplete_key_not_reused(self):
        k = key(file_fp="")
        self.store.put(Verdict(k, "a", "allow", 100))
        self.assertIsNone(self.store.get(k))            # 판정 재사용 안 함
        self.assertIsNotNone(self.store.lookup(k))      # tools/call 조회는 가능

    def test_rowid_stable_on_reput(self):
        k = key(file_fp="")
        r1 = self.store.put(Verdict(k, "a", "restrict", 70)).rowid
        r2 = self.store.put(Verdict(k, "a", "block", 10)).rowid
        self.assertEqual(r1, r2)
        self.assertEqual(self.store.by_rowid(r1).grade, "block")

    def test_approve_rules(self):
        ok = self.store.put(Verdict(key(tool_hash="h1"), "a", "restrict", 70)).rowid
        blk = self.store.put(Verdict(key(tool_hash="h2"), "b", "block", 10)).rowid
        hid = self.store.put(Verdict(key(tool_hash="h3"), "c", "restrict", 70, exposable=False)).rowid
        nofp = self.store.put(Verdict(key(tool_hash="h4", dep_fp=""), "d", "restrict", 70)).rowid
        self.assertFalse(self.store.approve(blk, "dev")[0])
        self.assertFalse(self.store.approve(hid, "dev")[0])
        self.assertFalse(self.store.approve(nofp, "dev")[0])
        self.assertFalse(self.store.approve(ok, "real")[0])     # 다른 모드
        self.assertFalse(self.store.approve(9999, "dev")[0])
        self.assertTrue(self.store.approve(ok, "dev")[0])
        self.assertEqual(self.store.get(key(tool_hash="h1")).effective, "approved")
        self.assertEqual(self.store.by_rowid(hid).effective, "restrict")
        self.assertEqual([v.tool for v in self.store.pending()], ["d", "c"])

    def test_approval_not_carried_to_new_key(self):
        rid = self.store.put(Verdict(key(), "a", "restrict", 70)).rowid
        self.store.approve(rid, "dev")
        self.assertIsNone(self.store.get(key(file_fp="f2")))  # 서버 파일이 바뀌면 이전 승인은 안 쓰인다

    def test_identity_approval_updates_baseline(self):
        """identity_changed 승인 → 신원 장부 갱신 + 같은 서버의 다른 미승인 identity_changed 판정 무효화 (결정 #27)."""
        sig = ["identity_changed"]
        a = self.store.put(Verdict(key(tool_hash="h1", file_fp="new"), "a", "restrict", 85, signals=sig,
                                   server_name="calc", server_version="2.0")).rowid
        self.store.put(Verdict(key(tool_hash="h2", file_fp="new"), "b", "restrict", 85, signals=sig))
        self.store.put(Verdict(key(tool_hash="h3", file_fp="new"), "c", "restrict", 70, signals=["known_vuln"]))
        self.store.put(Verdict(key(server_id="other", file_fp="new"), "x", "restrict", 85, signals=sig))
        self.store.put(Verdict(key(tool_hash="h5", file_fp="new", mode="real"), "r", "restrict", 85, signals=sig))
        with sqlite3.connect(self.db) as c:  # C가 처음 기록해 둔 신원
            c.execute("CREATE TABLE identity_baseline (server_id TEXT PRIMARY KEY, name TEXT, version TEXT, "
                      "file_fp TEXT, dep_fp TEXT, first_seen TEXT, updated_at TEXT)")
            c.execute("INSERT INTO identity_baseline VALUES ('s','calc','1.0','old','d','2026-11-20','2026-11-20')")

        self.assertTrue(self.store.approve(a, "dev")[0])
        with sqlite3.connect(self.db) as c:
            row = c.execute("SELECT name, version, file_fp, dep_fp, first_seen FROM identity_baseline "
                            "WHERE server_id='s'").fetchone()
        self.assertEqual(row, ("calc", "2.0", "new", "d", "2026-11-20"))  # first_seen 유지
        left = {(v.server, v.tool, v.key.mode) for v in self.store.all()}
        self.assertNotIn(("s", "b", "dev"), left)     # 같은 서버·모드의 다른 identity_changed → 지움(재검사)
        self.assertIn(("s", "a", "dev"), left)        # 승인한 것은 남음
        self.assertIn(("s", "c", "dev"), left)        # 다른 신호는 그대로
        self.assertIn(("other", "x", "dev"), left)    # 다른 서버는 그대로
        self.assertIn(("s", "r", "real"), left)       # 다른 모드는 그대로

    def test_identity_baseline_created_if_missing(self):
        a = self.store.put(Verdict(key(), "a", "restrict", 85, signals=["identity_changed"])).rowid
        self.assertTrue(self.store.approve(a, "dev")[0])
        with sqlite3.connect(self.db) as c:
            self.assertEqual(c.execute("SELECT file_fp FROM identity_baseline").fetchone(), ("f",))


if __name__ == "__main__":
    unittest.main()
