"""시연용 MCP 서버(demo/servers): 도구 목록 생성·러그풀 전환·격리 실행만 검사한다."""

import runpy
import sys
from pathlib import Path

import httpx
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "demo" / "servers"))

import demo_server  # noqa: E402
import samples  # noqa: E402

from tests.helpers import serve  # noqa: E402


def _sample(sid):
    return next(s["tool"] for s in samples.POISONED if s["id"] == sid)


def test_translator_uses_eval_sample_as_is():
    # 오염 문장은 복사하지 않고 eval/samples.py의 실제 샘플을 그대로 쓴다
    tools = demo_server.make_tools("translator")
    assert tools == [_sample(demo_server.TRANSLATOR_SAMPLE)]
    assert tools[0]["name"] == "translate"


def test_notes_server_has_only_plain_tools():
    tools = demo_server.make_tools("notes")
    names = {t["name"] for t in tools}
    assert {"list_notes", "read_note", "save_note"} == names
    descriptions = " ".join(t["description"] for t in tools)
    assert "~/" not in descriptions and "ssh" not in descriptions.lower()


def test_rugpull_changes_only_description():
    before = demo_server.make_tools("rugpull", flipped=False)
    after = demo_server.make_tools("rugpull", flipped=True)
    assert after == [_sample(demo_server.RUGPULL_SAMPLE)]
    assert before[0]["name"] == after[0]["name"]
    assert before[0]["inputSchema"] == after[0]["inputSchema"]
    assert before[0]["description"] != after[0]["description"]


def test_unknown_role_is_rejected():
    with pytest.raises(ValueError):
        demo_server.make_tools("evil")


def test_refuses_to_run_outside_docker(monkeypatch):
    monkeypatch.delenv("LINKUD_IN_DOCKER", raising=False)
    with pytest.raises(SystemExit):
        runpy.run_path(str(ROOT / "demo/servers/demo_server.py"), run_name="__main__")


async def _names(url):
    async with Client(streamable_http_client(f"{url}/mcp"), cache=None) as c:
        return [(t.name, t.description) for t in (await c.list_tools()).tools]


async def test_rugpull_switch_endpoints():
    app = demo_server.make_app("rugpull")
    async with serve(app) as url, httpx.AsyncClient() as http:
        ((_, first),) = await _names(url)
        assert (await http.post(f"{url}/demo/rugpull")).json() == {"flipped": True}
        ((_, second),) = await _names(url)
        assert second == _sample(demo_server.RUGPULL_SAMPLE)["description"] != first
        # GET으로는 바꿀 수 없다
        assert (await http.get(f"{url}/demo/rugpull")).status_code == 405
        assert (await http.post(f"{url}/demo/reset")).json() == {"flipped": False}
        ((_, third),) = await _names(url)
        assert third == first


async def test_switch_endpoints_exist_only_on_rugpull_server():
    app = demo_server.make_app("translator")
    async with serve(app) as url, httpx.AsyncClient() as http:
        assert (await http.post(f"{url}/demo/rugpull")).status_code == 404


async def test_notes_call_returns_fixed_text():
    app = demo_server.make_app("notes")
    async with serve(app) as url:
        async with Client(streamable_http_client(f"{url}/mcp"), cache=None) as c:
            result = await c.call_tool("list_notes", {})
            assert not result.is_error and "메모" in result.content[0].text
