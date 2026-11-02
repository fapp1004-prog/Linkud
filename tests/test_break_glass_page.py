"""B-5: 브레이크 글래스 웹 페이지 보안 (CSP, textContent만, 토큰 저장 안 함), nginx 경로."""

import re
from pathlib import Path

import httpx

from tests.test_break_glass_api import make

ROOT = Path(__file__).resolve().parent.parent


async def test_page_served_with_strict_headers(monkeypatch):
    app, _, _ = make(monkeypatch)
    from tests.helpers import serve

    async with serve(app) as url, httpx.AsyncClient() as http:
        page = await http.get(f"{url}/override")
        assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
        csp = page.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "default-src 'none'" in csp
        assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
        assert "frame-ancestors 'none'" in csp
        assert page.headers["x-content-type-options"] == "nosniff"
        assert page.headers["referrer-policy"] == "no-referrer"
        assert "no-store" in page.headers["cache-control"]
        html = page.text
        # 인라인 스크립트·인라인 이벤트 핸들러·인라인 스타일 없음
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html)
        assert not re.search(r"\son\w+\s*=", html, re.I)
        assert "style=" not in html
        for asset, ctype in (("app.js", "javascript"), ("app.css", "text/css")):
            r = await http.get(f"{url}/override/{asset}")
            assert r.status_code == 200 and ctype in r.headers["content-type"]
            assert r.headers["x-content-type-options"] == "nosniff"


async def test_query_not_reflected(monkeypatch):
    app, _, _ = make(monkeypatch)
    from tests.helpers import serve

    async with serve(app) as url, httpx.AsyncClient() as http:
        page = await http.get(f"{url}/override", params={"ref": "<script>alert(1)</script>"})
        assert "<script>alert" not in page.text


def test_script_uses_text_content_and_stores_nothing():
    js = (ROOT / "src/linkud/admin/static/override.js").read_text()
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
                   "localStorage", "sessionStorage", "indexedDB", "document.cookie"):  # fmt: skip
        assert banned not in js, banned
    assert "textContent" in js
    assert "Authorization" in js and 'credentials: "omit"' in js


async def test_assets_absent_when_disabled(monkeypatch):
    app, _, _ = make(monkeypatch, enabled=False)
    from tests.helpers import serve

    async with serve(app) as url, httpx.AsyncClient() as http:
        for path in ("/override", "/override/app.js"):
            assert (await http.get(f"{url}{path}")).status_code in (401, 404)


def test_nginx_passes_override_paths():
    conf = (ROOT / "deploy/nginx/templates/linkud.conf.template").read_text()
    assert re.search(r"location = /override \{", conf)
    assert re.search(r"location \^~ /override/ \{", conf)
