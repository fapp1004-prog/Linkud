"""시연 문서: 실행법·리허설 체크리스트·발표 멘트가 있고 루트 README에서 링크되는지 본다."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = (ROOT / "demo" / "README.md").read_text(encoding="utf-8")


def test_demo_readme_has_run_and_rehearsal_sections():
    assert "docker compose -f demo/docker-compose.yml up --build" in DOC
    assert "http://127.0.0.1:8080" in DOC
    for heading in ("## 실행", "## 리허설 체크리스트", "## 발표 멘트 예시", "## 진짜와 재현"):
        assert heading in DOC, heading
    for topic in ("인터넷", "미리 받아", "녹화"):
        assert topic in DOC, topic
    assert "오른쪽은 지금 실제로 돌아가는 Linkud" in DOC


def test_demo_readme_explains_judge_switch_and_checks():
    assert "ANTHROPIC_API_KEY" in DOC and "AI 판사 꺼짐(규칙만)" in DOC
    assert "demo/smoke.py" in DOC and "demo/browser_check.mjs" in DOC


def test_root_readme_links_demo():
    assert "(demo/README.md)" in (ROOT / "README.md").read_text(encoding="utf-8")
