import tempfile
import unittest
from pathlib import Path

from gateway.cache import TrustStore, Verdict, tool_hash


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
        self.store = TrustStore(Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_approve_only_restrict(self):
        self.store.put(Verdict("s", "a", "h1", "restrict", 70))
        self.store.put(Verdict("s", "b", "h2", "block", 10))
        self.assertTrue(self.store.approve("s", "h1"))
        self.assertFalse(self.store.approve("s", "h2"))
        self.assertEqual(self.store.get("s", "h1").effective, "approved")
        self.assertEqual(self.store.get("s", "h2").effective, "block")
        self.assertEqual(self.store.pending(), [])


if __name__ == "__main__":
    unittest.main()
