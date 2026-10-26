"""1단계: 투명 프록시."""

from mcp import Client

from linkud.config import parse_config
from linkud.proxy.gateway import Gateway, create_app
from tests.fixtures.benign_servers import make_math_server, make_notes_server
from tests.helpers import FakeDownstream, serve, tool


async def test_aggregates_and_prefixes_tools():
    gw = Gateway([FakeDownstream("a", [tool("x")]), FakeDownstream("b", [tool("x"), tool("y")])])
    names = [t.name for t in await gw.list_tools()]
    assert names == ["a__x", "b__x", "b__y"]


async def test_routes_call_to_owning_downstream():
    a, b = FakeDownstream("a", [tool("x")]), FakeDownstream("b", [tool("x")])
    gw = Gateway([a, b])
    result = await gw.call_tool("b__x", {"k": 1})
    assert not result.is_error
    assert b.calls == [("x", {"k": 1})] and a.calls == []


async def test_unknown_tool_is_error():
    gw = Gateway([FakeDownstream("a", [tool("x")])])
    for name in ["nope", "zz__x", "a__"]:
        assert (await gw.call_tool(name, None)).is_error


async def test_failed_downstream_hides_its_tools():
    gw = Gateway([FakeDownstream("a", [tool("x")], fail=True), FakeDownstream("b", [tool("y")])])
    assert [t.name for t in await gw.list_tools()] == ["b__y"]


async def test_end_to_end_over_http():
    """에이전트가 게이트웨이 하나로 두 서버의 도구를 보고 호출할 수 있다."""
    async with (
        serve(make_math_server().streamable_http_app()) as math_url,
        serve(make_notes_server().streamable_http_app()) as notes_url,
    ):
        cfg = parse_config(
            {
                "downstreams": [
                    {"name": "math", "url": f"{math_url}/mcp"},
                    {"name": "notes", "url": f"{notes_url}/mcp"},
                ]
            }
        )
        async with serve(create_app(cfg)) as gw_url, Client(f"{gw_url}/mcp", cache=None) as agent:
            names = {t.name for t in (await agent.list_tools()).tools}
            assert {
                "math__add",
                "math__multiply",
                "notes__list_notes",
                "notes__create_note",
            } <= names

            result = await agent.call_tool("math__add", {"a": 2, "b": 3})
            assert result.content[0].text == "5"

            await agent.call_tool("notes__create_note", {"title": "t", "content": "c"})
            result = await agent.call_tool("notes__read_note", {"title": "t"})
            assert result.content[0].text == "c"


async def test_unreachable_downstream_is_hidden_over_http():
    async with serve(make_math_server().streamable_http_app()) as math_url:
        cfg = parse_config(
            {
                "gateway": {"connect_timeout": 0.5},
                "downstreams": [
                    {"name": "math", "url": f"{math_url}/mcp"},
                    {"name": "dead", "url": "http://127.0.0.1:1/mcp"},
                ],
            }
        )
        async with serve(create_app(cfg)) as gw_url, Client(f"{gw_url}/mcp", cache=None) as agent:
            names = {t.name for t in (await agent.list_tools()).tools}
            assert names == {"math__add", "math__multiply"}
            assert (await agent.call_tool("dead__x", {})).is_error
