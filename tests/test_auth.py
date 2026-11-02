"""7단계: 게이트웨이 인증·공개 배포 보호."""

import httpx
import pytest
from mcp import Client

from linkud.config import ConfigError, parse_config
from linkud.proxy.gateway import create_app
from linkud.store.memory import MemoryStore
from tests.helpers import FakeDownstream, TrustingVerifier, make_gateway, serve, tool

TOKEN = "test-token-1234567890"


def app_with(monkeypatch, tokens: str | None, **gateway):
    if tokens is None:
        monkeypatch.delenv("LINKUD_AUTH_TOKENS", raising=False)
    else:
        monkeypatch.setenv("LINKUD_AUTH_TOKENS", tokens)
    cfg = parse_config({"gateway": gateway})
    return create_app(
        cfg,
        downstreams=[FakeDownstream("a", [tool("x")])],
        store=MemoryStore(),
        verifier=TrustingVerifier(),
    )


async def test_requests_without_valid_token_are_rejected(monkeypatch):
    async with serve(app_with(monkeypatch, f"other,{TOKEN}")) as url:
        async with httpx.AsyncClient() as http:
            body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            assert (await http.post(f"{url}/mcp", json=body)).status_code == 401
            bad = {"Authorization": "Bearer nope"}
            assert (await http.post(f"{url}/mcp", json=body, headers=bad)).status_code == 401
            assert (await http.get(f"{url}/healthz")).json()["status"] == "ok"


async def test_valid_token_works(monkeypatch):
    async with serve(app_with(monkeypatch, TOKEN)) as url:
        transport_headers = {"Authorization": f"Bearer {TOKEN}"}
        from mcp.client.streamable_http import streamable_http_client

        async with Client(
            streamable_http_client(f"{url}/mcp", http_client=_http(transport_headers)), cache=None
        ) as agent:
            assert [t.name for t in (await agent.list_tools()).tools] == ["a__x"]


def _http(headers):
    import httpx2

    return httpx2.AsyncClient(headers=headers)


def test_public_bind_without_tokens_refuses_to_start(monkeypatch):
    with pytest.raises(ConfigError):
        app_with(monkeypatch, None, host="0.0.0.0")


def test_public_bind_with_tokens_starts(monkeypatch):
    app_with(monkeypatch, TOKEN, host="0.0.0.0", allowed_hosts=["gw.example.com"])


async def test_oversized_result_is_not_forwarded():
    class Big(FakeDownstream):
        async def call_tool(self, name, arguments):
            import mcp.types as types

            return types.CallToolResult(content=[types.TextContent(type="text", text="x" * 5000)])

    gw, store = make_gateway([Big("a", [tool("x")])])
    gw.max_result_bytes = 1000
    await gw.list_tools()
    result = await gw.call_tool("a__x", {})
    # A-2: 가용성 오류도 고정 문구, 원인은 감사 로그(call_failed)에
    assert result.is_error and "too large" not in result.content[0].text
    ref = result.content[0].text.rsplit(" ", 1)[-1]
    assert (await store.find_by_ref(ref)).detail["code"] == "too_large"
