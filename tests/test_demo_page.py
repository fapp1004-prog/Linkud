"""시연 페이지(demo/web)를 정적으로 검사한다.

브라우저에서 오염 문장이 실행되지 않는지는 demo/browser_check.mjs(Playwright)로 따로 확인한다.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "demo" / "web"
HTML = (WEB / "index.html").read_text(encoding="utf-8")
JS = (WEB / "app.js").read_text(encoding="utf-8")
CSS = (WEB / "app.css").read_text(encoding="utf-8")
ALL = HTML + JS + CSS

sys.path.insert(0, str(ROOT / "eval"))
import samples  # noqa: E402


def test_only_expected_files():
    assert sorted(p.name for p in WEB.iterdir()) == ["app.css", "app.js", "index.html"]


def test_html_has_no_inline_code():
    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", HTML, re.S | re.I)
    assert scripts == [(' src="app.js" defer', "")]
    assert not re.search(r"\son\w+\s*=", HTML, re.I)  # onclick 등
    assert not re.search(r"\sstyle\s*=", HTML, re.I)
    assert "javascript:" not in HTML.lower()


def test_works_offline_without_external_resources():
    assert not re.search(r"https?://", ALL)
    assert "@import" not in CSS and "@font-face" not in CSS
    assert not re.search(r"""(src|href)\s*=\s*["']//""", HTML)


def test_server_text_goes_through_text_nodes_only():
    banned = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "DOMParser",
        "createContextualFragment",
        "srcdoc",
    ]
    for word in banned:
        assert word not in JS, word
    assert "textContent" in JS
    # 문자열을 코드로 실행하는 타이머 금지
    assert not re.search(r"set(Timeout|Interval)\(\s*['\"`]", JS)


def test_no_tokens_or_storage_in_page():
    for word in ("Authorization", "Bearer", "localStorage", "sessionStorage", "document.cookie"):
        assert word not in ALL, word


def test_fetches_only_relative_demo_paths():
    targets = re.findall(r"fetch\(\s*([^,)]+)", JS)
    assert targets
    paths = re.findall(r"['\"`](/[^'\"`]*)", JS)
    assert paths and all(p.startswith(("/driver/", "/api/admin/")) for p in paths)


def test_real_vs_staged_badges_and_disconnect_notice():
    assert "재현 화면" in ALL and "실시간" in ALL
    assert "연결 끊김" in ALL
    assert "36.5%" in ALL and "MCPTox" in ALL  # 장면 1의 확률적 공격 주석
    assert "가짜" in ALL  # 장면 1의 키가 가짜임을 화면에 명시
    assert "AI 판사 꺼짐(규칙만)" in ALL


def test_keyboard_and_buttons_change_scenes():
    assert "ArrowRight" in JS and "ArrowLeft" in JS
    assert 'id="next"' in HTML and 'id="prev"' in HTML


def test_live_values_are_not_hardcoded():
    # 오염 문장은 페이지에 복사하지 않는다(드라이버가 서버에서 받아 온다)
    for s in samples.POISONED:
        assert s["tool"]["description"] not in ALL
    # 평가 수치도 페이지에 없다(드라이버가 results.json에서 읽음)
    data = json.loads((ROOT / "eval/results/results.json").read_text(encoding="utf-8"))
    rules = data["detection"]["summary"]["rules"]
    rug = data["rugpull"][0]
    for pair in [
        (rules["tp"], rules["p"]),
        (rules["fp"], rules["n"]),
        (rug["hidden_after_change"], rug["total"]),
    ]:
        assert f"{pair[0]}/{pair[1]}" not in ALL and f"{pair[0]} / {pair[1]}" not in ALL
    assert not re.search(r"LK-[0-9A-HJKMNP-TV-Z]{8}", ALL)  # 참조 번호도 지어내지 않음


def test_projector_friendly_large_text():
    m = re.search(r"html\s*\{[^}]*font-size:\s*([^;]+);", CSS)
    assert m and "clamp(" in m.group(1)
    assert 'lang="ko"' in HTML
