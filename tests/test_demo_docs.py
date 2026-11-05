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
    # 채팅 앱 하나로 단순화: 실제 값은 '실제 Linkud 응답' 표시가 붙은 메시지뿐
    assert "'실제 Linkud 응답' 표시가 붙은 내용만 지금 실제로 돌아가는 Linkud" in DOC
    assert "`N` 키" in DOC
    for old in ("오른쪽은 지금", "오른쪽 (실시간)", "왼쪽 채팅", "노란 부분"):
        assert old not in DOC, old


def test_demo_readme_explains_judge_switch_and_checks():
    assert "ANTHROPIC_API_KEY" in DOC and "AI 판사 꺼짐(규칙만)" in DOC
    assert "demo/smoke.py" in DOC and "demo/browser_check.mjs" in DOC


def test_readme_screenshots_exist():
    import re

    names = re.findall(r"screenshots/([\w.-]+\.png)", DOC)
    assert names
    for n in names:
        assert (ROOT / "demo" / "screenshots" / n).exists(), n


def test_root_readme_links_demo():
    assert "(demo/README.md)" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_rehearsal_checklist_runs_browser_check():
    checklist = DOC.split("## 리허설 체크리스트", 1)[1].split("\n## ", 1)[0]
    assert "node demo/browser_check.mjs" in checklist


def test_egress_residual_risk_documented():
    line = "키가 없을 때도 게이트웨이는 egress 네트워크에 붙어 있지만 실제로 나가는 요청은 없다"
    assert line in DOC
    assert line in (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
