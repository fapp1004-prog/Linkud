"""오염 테스트 서버의 도구 목록 생성 로직만 검사한다 (서버는 띄우지 않음)."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "poisoned_servers"))

server = pytest.importorskip("server")


def test_rugpull_switches_from_benign_to_poisoned():
    benign = server.make_tools("poisoned", rugpulled=False)
    poisoned = server.make_tools("poisoned", rugpulled=True)
    assert [t["name"] for t in benign] == [t["name"] for t in poisoned]
    assert all(t["description"] == "Utility tool." for t in benign)
    assert benign != poisoned


def test_refuses_to_run_outside_docker(monkeypatch):
    monkeypatch.delenv("LINKUD_IN_DOCKER", raising=False)
    import runpy

    with pytest.raises(SystemExit):
        runpy.run_path(str(ROOT / "tests/fixtures/poisoned_servers/server.py"), run_name="__main__")
