"""A-2: 정책 거부·가용성 오류는 원인과 상관없이 같은 문구 + 참조 번호만 돌려준다."""

import re

import mcp.types as types
import pytest
from mcp.shared.exceptions import MCPError

from linkud.enforcement.refs import REF_PATTERN
from linkud.models import Tier, ToolVerdict
from linkud.proxy.downstream import DownstreamUnavailable
from linkud.verify.judge.base import JudgeLabel, JudgeVerdict
from linkud.verify.judge.fake import FakeJudge
from tests.helpers import FakeDownstream, make_gateway, pipeline, tool

TEMPLATE = re.compile(
    r"\[Linkud\] 이 도구는 지금 사용할 수 없습니다\. 관리자 문의 시 참조 번호: (LK-[0-9A-Z]{8})"
)
SUSPICIOUS = FakeJudge(
    decide=lambda d: (
        JudgeVerdict(JudgeLabel.SUSPICIOUS, False, ["odd"], 0.6) if d["name"] == "odd" else None
    )
)


class Broken(FakeDownstream):
    def __init__(self, name, tools, error):
        super().__init__(name, tools)
        self.error = error

    async def call_tool(self, name, arguments):
        if isinstance(self.error, str):
            return types.CallToolResult(content=[types.TextContent(type="text", text=self.error)])
        raise self.error


class FailingVerifier:
    async def verify(self, req):
        raise RuntimeError("boom")


async def _gateway():
    ok = FakeDownstream("ok", [tool("read_file", "Read a file.")])
    pending = FakeDownstream("pend", [tool("odd", "Odd."), tool("fine", "Fine.")])
    gone = Broken("gone", [tool("x", "X.")], DownstreamUnavailable("gone"))
    err = Broken("err", [tool("x", "X.")], MCPError(-32000, "SECRET downstream detail: server=err"))
    big = Broken("big", [tool("x", "X.")], "y" * 5000)
    gw, store = make_gateway([ok, pending, gone, err, big], verifier=pipeline(SUSPICIOUS))
    gw.max_result_bytes = 1000
    await gw.list_tools()
    return gw, store


def _ref(result: types.CallToolResult) -> str:
    assert result.is_error
    assert len(result.content) == 1
    m = TEMPLATE.fullmatch(result.content[0].text)
    assert m, result.content[0].text
    return m.group(1)


CASES = [
    ("bad_name", "nope", None),
    ("unknown_server", "zz__x", None),
    ("not_listed", "ok__missing", None),
    ("tier", "pend__fine", None),  # 서버 등급 승인 대기
    ("dangerous_args", "ok__read_file", {"path": "~/.ssh/id_rsa"}),
    ("unavailable", "gone__x", None),
    ("downstream_error", "err__x", None),
    ("too_large", "big__x", None),
]


async def test_all_denials_are_byte_identical_except_ref():
    gw, store = await _gateway()
    texts, refs = [], []
    for _, name, args in CASES:
        result = await gw.call_tool(name, args)
        ref = _ref(result)
        refs.append(ref)
        texts.append(result.content[0].text.replace(ref, "").encode())
    assert len(set(texts)) == 1
    assert len(set(refs)) == len(refs)  # 거부마다 새 번호
    for (code, _, _), ref in zip(CASES, refs, strict=True):
        event = await store.find_by_ref(ref)
        assert event is not None, code
        assert event.kind in ("call_denied", "call_failed")
        assert event.detail["code"] == code
        assert event.detail["reason"]  # 원래 이유는 감사 로그에만


async def test_response_leaks_nothing():
    gw, _ = await _gateway()
    for _, name, args in CASES:
        text = (await gw.call_tool(name, args)).content[0].text
        for leak in (
            "SECRET",
            "pend",
            "err",
            "승인 대기",
            "pending",
            "dangerous",
            "등급",
            "ssh",
            "gone",
        ):
            assert leak not in text, (name, leak)


async def test_no_verdict_and_throttled_use_same_text():
    ds = FakeDownstream("s", [tool("a", "A.")])
    gw, store = make_gateway([ds], verifier=FailingVerifier())
    await gw.list_tools()
    no_verdict = await gw.call_tool("s__a", {})

    ds2 = FakeDownstream("t", [tool("a", "v0")])
    gw2, store2 = make_gateway([ds2])
    gw2.enforcer.service.reverify_limit = 0
    await gw2.list_tools()
    ds2.tools = [tool("a", "v1")]
    await gw2.list_tools()
    throttled = await gw2.call_tool("t__a", {})

    r1, r2 = _ref(no_verdict), _ref(throttled)
    assert no_verdict.content[0].text.replace(r1, "") == throttled.content[0].text.replace(r2, "")
    assert (await store.find_by_ref(r1)).detail["code"] == "no_verdict"
    assert (await store2.find_by_ref(r2)).detail["code"] == "throttled"


async def test_allowed_call_and_tool_error_pass_through():
    ds = Broken("s", [tool("x", "X.")], "tool says: not found")
    gw, store = make_gateway([ds])
    await gw.list_tools()
    result = await gw.call_tool("s__x", {})
    assert result.content[0].text == "tool says: not found"  # 허용된 도구 결과는 그대로
    assert not any(e.ref for e in store.events if e.kind == "call_allowed")


async def test_ref_retried_on_collision(monkeypatch):
    from linkud.enforcement import guard

    seq = iter(["LK-AAAAAAAA", "LK-AAAAAAAA", "LK-BBBBBBBB"])
    monkeypatch.setattr(guard, "new_ref", lambda: next(seq))
    gw, store = make_gateway([FakeDownstream("s", [tool("x")])])
    await gw.list_tools()
    assert _ref(await gw.call_tool("s__nope", {})) == "LK-AAAAAAAA"
    assert _ref(await gw.call_tool("s__nope2", {})) == "LK-BBBBBBBB"


def test_ref_pattern_matches_template():
    assert REF_PATTERN.fullmatch("LK-ABCDEFGH")


@pytest.mark.parametrize("tier", [Tier.UNTRUSTED, Tier.PENDING])
async def test_tier_denial_records_tier(tier):
    class FixedVerifier:
        async def verify(self, req):
            return ToolVerdict(req.server, req.tool.name, req.tool_hash, tier, False, ["fixed"])

    gw, store = make_gateway([FakeDownstream("s", [tool("x")])], verifier=FixedVerifier())
    await gw.list_tools()
    ref = _ref(await gw.call_tool("s__x", {}))
    detail = (await store.find_by_ref(ref)).detail
    assert (
        detail["code"] == "tier"
        and detail["tier"] == tier.value
        and detail["tool_tier"] == tier.value
    )


async def test_same_text_over_http_for_unknown_and_blocked():
    """SDK가 없는 도구 이름을 먼저 가로채 다른 문구를 내지 않는지 HTTP 종단 간으로 확인."""
    from mcp import Client

    from linkud.config import parse_config
    from linkud.proxy.gateway import create_app
    from linkud.store.memory import MemoryStore
    from tests.helpers import serve

    ds = FakeDownstream("pend", [tool("odd", "Odd."), tool("fine", "Fine.")])
    app = create_app(
        parse_config({}), downstreams=[ds], store=MemoryStore(), verifier=pipeline(SUSPICIOUS)
    )
    async with serve(app) as url, Client(f"{url}/mcp", cache=None) as agent:
        assert (await agent.list_tools()).tools == []
        texts = []
        for name, args in (("pend__fine", {}), ("nope__x", {}), ("garbage", {"a": 1})):
            result = await agent.call_tool(name, args)
            ref = _ref(result)
            texts.append(result.content[0].text.replace(ref, ""))
        assert len(set(texts)) == 1


async def test_duplicate_named_server_blocks_calls_to_other_tools():
    """이름이 겹치는 도구가 있는 서버는 목록에서 전부 숨기므로, 다른 도구도 이름으로 호출할 수 없어야 한다."""
    ds = FakeDownstream("s", [tool("a", "1"), tool("a", "2"), tool("b", "B.")])
    gw, store = make_gateway([ds])
    assert await gw.list_tools() == []
    result = await gw.call_tool("s__b", {})
    ref = _ref(result)
    assert ds.calls == []
    assert (await store.find_by_ref(ref)).detail["code"] == "tier"
