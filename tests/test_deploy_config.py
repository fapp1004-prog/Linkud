"""4-1: 게이트웨이 컨테이너 자원 제한 (compose 정적 검사)."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSES = [
    ROOT / "deploy" / "docker-compose.yml",
    ROOT / "tests" / "fixtures" / "poisoned_servers" / "docker-compose.yml",
]


@pytest.mark.parametrize("path", COMPOSES, ids=lambda p: str(p.relative_to(ROOT)))
def test_gateway_has_resource_limits(path):
    gateway = yaml.safe_load(path.read_text())["services"]["gateway"]
    assert gateway["mem_limit"]
    assert 0 < float(gateway["cpus"]) <= 2
    assert 0 < int(gateway["pids_limit"]) <= 1024
