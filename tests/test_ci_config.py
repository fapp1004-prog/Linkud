"""3-2 · 3-5: CI·이미지 공급망 고정 규칙을 검사한다 (파일 정적 검사)."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)(.*)$")


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_actions_pinned_to_full_sha(path):
    found = 0
    for line in path.read_text().splitlines():
        m = USES.match(line)
        if not m:
            continue
        found += 1
        ref, rest = m.groups()
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), (
            f"{path.name}: SHA 고정 아님: {ref}"
        )
        assert re.search(r"#\s*v\d", rest), f"{path.name}: 버전 태그 주석 없음: {line.strip()}"
    assert found


def test_dependabot_covers_actions_and_python():
    import yaml

    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    assert cfg["version"] == 2
    ecosystems = {u["package-ecosystem"] for u in cfg["updates"]}
    assert {"github-actions", "uv"} <= ecosystems
    assert all(u.get("schedule", {}).get("interval") for u in cfg["updates"])
