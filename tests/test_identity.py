"""B-1: 이름=토큰 형식의 사용자 신원과 게이트웨이까지의 전달."""

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from linkud.config import ConfigError, parse_config
from linkud.proxy.auth import parse_identities
from linkud.proxy.gateway import create_app
from linkud.store.memory import MemoryStore
from tests.helpers import FakeDownstream, TrustingVerifier, serve, tool


def test_parse_named_and_anonymous_tokens():
    ids = parse_identities("alice=tok-a1, tok-anon ,bob=tok-b,alice=tok-a2")
    assert ids == {"tok-a1": "alice", "tok-anon": None, "tok-b": "bob", "tok-a2": "alice"}
    assert parse_identities("") == {}


@pytest.mark.parametrize(
    "raw", ["Alice=tok", "=tok", "alice=", "a b=tok", "x" * 70 + "=tok", "alice=t,bob=t"]
)
def test_invalid_identities_refuse_to_start(raw):
    with pytest.raises(ConfigError):
        parse_identities(raw)


def _client(url, token):
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"})
    return Client(streamable_http_client(f"{url}/mcp", http_client=http), cache=None)


async def test_user_reaches_gateway(monkeypatch):
    monkeypatch.setenv("LINKUD_AUTH_TOKENS", "alice=tok-alice,tok-anon")
    store = MemoryStore()
    app = create_app(
        parse_config({}),
        downstreams=[FakeDownstream("s", [tool("x")])],
        store=store,
        verifier=TrustingVerifier(),
    )
    async with serve(app) as url:
        for token in ("tok-alice", "tok-anon"):
            async with _client(url, token) as agent:
                assert [t.name for t in (await agent.list_tools()).tools] == ["s__x"]
                await agent.call_tool("s__missing", {})
    denials = [e for e in store.events if e.kind == "call_denied"]
    assert [e.detail["user"] for e in denials] == ["alice", None]


async def test_unknown_token_still_rejected(monkeypatch):
    monkeypatch.setenv("LINKUD_AUTH_TOKENS", "alice=tok-alice")
    app = create_app(
        parse_config({}), downstreams=[FakeDownstream("s", [tool("x")])], store=MemoryStore()
    )
    async with serve(app) as url, httpx2.AsyncClient() as http:
        r = await http.post(f"{url}/mcp", json={}, headers={"Authorization": "Bearer alice"})
        assert r.status_code == 401
