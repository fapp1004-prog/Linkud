import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from gateway import dashboard
from gateway.cache import CacheKey, TrustStore, Verdict


def key(h, mode="dev", file_fp="f"):
    return CacheKey("srv", h, file_fp, "d", "p", mode)


class DashboardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_env = {k: os.environ.get(k) for k in ("LINKUD_AUDIT", "LINKUD_DEV_CHECKERS", "LINKUD_DB")}
        os.environ["LINKUD_AUDIT"] = str(Path(self.tmp.name) / "audit.jsonl")
        os.environ["LINKUD_DB"] = str(Path(self.tmp.name) / "t.db")
        os.environ["LINKUD_DEV_CHECKERS"] = "1"
        self.store = TrustStore(Path(self.tmp.name) / "t.db")
        self.v = self.store.put(Verdict(key("h1"), "<script>alert(1)</script>", "restrict", 70,
                                        reasons=["<img src=x onerror=alert(1)>"]))
        self.nofp = self.store.put(Verdict(key("h2", file_fp=""), "nofp", "restrict", 70))
        self.real = self.store.put(Verdict(key("h3", mode="real"), "realtool", "restrict", 70))
        dashboard.Handler.store = self.store
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.Handler)
        self.port = self.httpd.server_address[1]
        dashboard.PORT = self.port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        for k, v in self.old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def page(self) -> str:
        return urllib.request.urlopen(self.base + "/").read().decode()

    def test_page_escapes_attacker_text(self):
        body = self.page()
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertNotIn("<img src=x", body)
        self.assertIn("&lt;script&gt;", body)

    def test_mode_banner_and_mode_filter(self):
        body = self.page()
        self.assertIn("개발 모드", body)
        self.assertNotIn("realtool", body)        # 다른 모드의 판정은 안 보인다
        self.assertIn("서버 지문 없음", body)      # 승인 못 하는 이유 표시

    def _post(self, origin, rowid):
        req = urllib.request.Request(self.base + "/approve", data=f"rowid={rowid}".encode(), method="POST")
        if origin:
            req.add_header("Origin", origin)
        try:
            return urllib.request.urlopen(req).status
        except urllib.error.HTTPError as e:
            return e.code

    def test_cross_origin_approve_rejected(self):
        self.assertEqual(self._post("http://evil.example", self.v.rowid), 403)
        self.assertEqual(self._post(None, self.v.rowid), 403)
        self.assertFalse(self.store.by_rowid(self.v.rowid).approved)

    def test_same_origin_approve(self):
        self.assertEqual(self._post(self.base, self.v.rowid), 200)  # 303 → 따라가서 200
        self.assertTrue(self.store.by_rowid(self.v.rowid).approved)

    def test_unapprovable_rejected(self):
        self._post(self.base, self.nofp.rowid)
        self._post(self.base, self.real.rowid)   # 개발 모드 대시보드에서 실제 모드 판정 승인 불가
        self.assertFalse(self.store.by_rowid(self.nofp.rowid).approved)
        self.assertFalse(self.store.by_rowid(self.real.rowid).approved)
        self.assertEqual(self._post(self.base, "abc"), 400)


if __name__ == "__main__":
    unittest.main()
