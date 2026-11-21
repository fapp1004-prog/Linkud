import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from gateway import dashboard
from gateway.cache import TrustStore, Verdict


class DashboardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["LINKUD_AUDIT"] = str(Path(self.tmp.name) / "audit.jsonl")
        self.store = TrustStore(Path(self.tmp.name) / "t.db")
        self.store.put(Verdict("srv", "<script>alert(1)</script>", "h1", "restrict", 70,
                               reasons=["<img src=x onerror=alert(1)>"]))
        dashboard.Handler.store = self.store
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.Handler)
        self.port = self.httpd.server_address[1]
        dashboard.PORT = self.port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        os.environ.pop("LINKUD_AUDIT", None)
        self.tmp.cleanup()

    def test_page_escapes_attacker_text(self):
        body = urllib.request.urlopen(self.base + "/").read().decode()
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertNotIn("<img src=x", body)
        self.assertIn("&lt;script&gt;", body)

    def _post(self, origin):
        req = urllib.request.Request(self.base + "/approve", data=b"server=srv&hash=h1", method="POST")
        if origin:
            req.add_header("Origin", origin)
        try:
            return urllib.request.urlopen(req).status
        except urllib.error.HTTPError as e:
            return e.code

    def test_cross_origin_approve_rejected(self):
        self.assertEqual(self._post("http://evil.example"), 403)
        self.assertEqual(self._post(None), 403)
        self.assertFalse(self.store.get("srv", "h1").approved)

    def test_same_origin_approve(self):
        self.assertEqual(self._post(self.base), 200)  # 303 → 따라가서 200
        self.assertTrue(self.store.get("srv", "h1").approved)


if __name__ == "__main__":
    unittest.main()
