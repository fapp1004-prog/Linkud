"""1-3: 재검증 횟수 상한(자원 고갈 방어)과 락 정리."""

import anyio

from linkud.models import Tier
from linkud.store.memory import MemoryCache, MemoryStore
from linkud.verify.service import VerificationService
from tests.helpers import FakeDownstream, TrustingVerifier, make_gateway, tool


def gateway_with_limit(ds, limit=3, window=600.0):
    gw, store = make_gateway([ds])
    service = gw.enforcer.service
    service.reverify_limit = limit
    service.reverify_window = window
    return gw, store, service


async def test_first_listing_does_not_count():
    ds = FakeDownstream("s", [tool(f"t{i}", "Tool.") for i in range(20)])
    gw, _, service = gateway_with_limit(ds, limit=3)
    assert len(await gw.list_tools()) == 20
    assert not service.is_throttled("s")


async def test_churning_server_goes_pending_after_limit():
    ds = FakeDownstream("s", [tool("echo", "v0")])
    other = FakeDownstream("o", [tool("x", "Fine.")])
    gw, store, service = gateway_with_limit(ds, limit=3)
    gw.downstreams["o"] = other
    await gw.list_tools()
    for i in range(1, 4):  # 상한 안의 재검증 3회
        ds.tools = [tool("echo", f"v{i}")]
        await gw.list_tools()
    assert not service.is_throttled("s")

    ds.tools = [tool("echo", "v4")]  # 4번째 재검증 → 상한 초과
    names = [t.name for t in await gw.list_tools()]
    assert service.is_throttled("s")
    assert names == ["o__x"]  # 다른 서버는 영향 없음
    assert gw.enforcer.server_tiers()["s"] is Tier.PENDING
    assert (await gw.call_tool("s__echo", {})).is_error
    limited = [e for e in store.events if e.kind == "reverify_limited"]
    assert len(limited) == 1 and limited[0].server == "s"

    # 상한을 넘은 뒤에는 검증기를 더 부르지 않는다
    before = len(store.verdicts)
    ds.tools = [tool("echo", "v5")]
    await gw.list_tools()
    assert len(store.verdicts) == before


async def test_new_tool_names_after_first_listing_count():
    ds = FakeDownstream("s", [tool("a")])
    gw, _, service = gateway_with_limit(ds, limit=2)
    await gw.list_tools()
    for i in range(3):
        ds.tools.append(tool(f"new{i}"))
        await gw.list_tools()
    assert service.is_throttled("s")


async def test_release_restores_server():
    ds = FakeDownstream("s", [tool("echo", "v0")])
    gw, store, service = gateway_with_limit(ds, limit=1)
    await gw.list_tools()
    ds.tools = [tool("echo", "v1")]
    await gw.list_tools()  # 재검증 1회 (상한 안)
    ds.tools = [tool("echo", "v2")]
    assert await gw.list_tools() == []
    assert service.is_throttled("s")
    await service.release("s", actor="admin")
    assert not service.is_throttled("s")
    assert [t.name for t in await gw.list_tools()] == ["s__echo"]
    assert any(e.kind == "reverify_released" for e in store.events)


async def test_locks_are_cleaned_up():
    service = VerificationService(TrustingVerifier(), MemoryCache(), MemoryStore())
    tools = [tool(f"t{i}") for i in range(50)]
    async with anyio.create_task_group() as tg:
        for _ in range(5):
            tg.start_soon(service.verdicts, "s", tools)
    assert service._locks == {}


async def test_config_and_admin_release(monkeypatch):
    import httpx

    from linkud.config import parse_config
    from linkud.proxy.gateway import create_app
    from tests.helpers import serve

    monkeypatch.setenv("LINKUD_AUTH_TOKENS", "agent")
    monkeypatch.setenv("LINKUD_ADMIN_TOKENS", "admin")
    ds = FakeDownstream("s", [tool("echo", "v0")])
    cfg = parse_config({"gateway": {"reverify_limit": 0, "reverify_window": 60}})
    app = create_app(cfg, downstreams=[ds], store=MemoryStore(), verifier=TrustingVerifier())
    service = app.state.gateway.enforcer.service
    assert (service.reverify_limit, service.reverify_window) == (0, 60)

    await app.state.gateway.list_tools()
    ds.tools = [tool("echo", "v1")]
    await app.state.gateway.list_tools()
    assert service.is_throttled("s")
    async with serve(app) as url, httpx.AsyncClient() as http:
        h = {"Authorization": "Bearer admin"}
        assert (await http.get(f"{url}/admin/servers", headers=h)).json()["s"] == "pending"
        resp = await http.post(f"{url}/admin/servers/s/release", headers=h)
        assert resp.status_code == 200
        assert (await http.post(f"{url}/admin/servers/nope/release", headers=h)).status_code == 404
    assert not service.is_throttled("s")
