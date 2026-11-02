"""B-3: 임시 허용이 런타임 경로(목록 필터·호출 가드)에 적용되는 범위."""

from linkud.enforcement.overrides import Override, OverrideRegistry
from linkud.models import Tier, ToolVerdict
from linkud.verify.hashing import tool_hash
from linkud.verify.judge.base import JudgeLabel, JudgeVerdict
from linkud.verify.judge.fake import FakeJudge
from tests.helpers import FakeDownstream, make_gateway, pipeline, tool

NOW = 1_000_000.0
RO = {"readOnlyHint": True}
SUSPICIOUS = FakeJudge(
    decide=lambda d: (
        JudgeVerdict(JudgeLabel.SUSPICIOUS, False, ["odd"], 0.6) if d["name"] == "get_odd" else None
    )
)


async def setup(allow_write=False, tools=None):
    tools = tools or [
        tool("get_odd", "Get odd.", annotations=RO),
        tool("get_fine", "Get fine.", annotations=RO),
    ]
    ds = FakeDownstream("s", tools)
    gw, store = make_gateway([ds], verifier=pipeline(SUSPICIOUS))
    reg = OverrideRegistry()
    gw.enforcer.overrides = reg
    gw.enforcer.allow_write_override = allow_write
    gw.enforcer.clock = lambda: NOW
    assert await gw.list_tools("alice") == []  # 서버 승인 대기 → 전부 숨김
    return gw, store, ds, reg


def grant(reg, ds, name="get_odd", user="alice", ttl=3600):
    t = next(t for t in ds.tools if t.name == name)
    reg.add(
        Override(
            "o1", user, "s", name, tool_hash(t), "LK-AAAAAAAA", "reason here", NOW - 1, NOW + ttl
        )
    )


async def test_only_that_user_sees_only_that_tool():
    gw, _, ds, reg = await setup()
    grant(reg, ds)
    assert [t.name for t in await gw.list_tools("alice")] == ["s__get_odd"]
    assert await gw.list_tools("bob") == []
    assert await gw.list_tools(None) == []
    assert not (await gw.call_tool("s__get_odd", {}, "alice")).is_error
    assert (await gw.call_tool("s__get_odd", {}, "bob")).is_error
    assert (await gw.call_tool("s__get_fine", {}, "alice")).is_error  # 다른 도구는 그대로 숨김


async def test_hash_change_invalidates():
    gw, _, ds, reg = await setup()
    grant(reg, ds)
    ds.tools[0] = tool("get_odd", "Get odd, changed.", annotations=RO)
    assert await gw.list_tools("alice") == []
    assert (await gw.call_tool("s__get_odd", {}, "alice")).is_error


async def test_expiry_judged_at_lookup_and_logged_once():
    gw, store, ds, reg = await setup()
    grant(reg, ds, ttl=60)
    assert await gw.list_tools("alice") != []
    gw.enforcer.clock = lambda: NOW + 61
    assert await gw.list_tools("alice") == []
    assert (await gw.call_tool("s__get_odd", {}, "alice")).is_error
    expired = [e for e in store.events if e.kind == "override_expired"]
    assert len(expired) == 1 and expired[0].detail["user"] == "alice"


async def test_not_applied_when_server_untrusted_or_throttled():
    gw, _, ds, reg = await setup()
    grant(reg, ds)
    gw.enforcer.service._throttled["s"] = NOW
    assert await gw.list_tools("alice") == []
    assert (await gw.call_tool("s__get_odd", {}, "alice")).is_error
    gw.enforcer.service._throttled.clear()

    class Untrusted:
        async def verify(self, req):
            return ToolVerdict(
                req.server, req.tool.name, req.tool_hash, Tier.UNTRUSTED, True, ["bad"]
            )

    ds.tools.append(tool("get_bad", "Bad.", annotations=RO))
    gw.enforcer.service.verifier = Untrusted()
    assert await gw.list_tools("alice") == []  # 서버가 불신이 됨
    assert (await gw.call_tool("s__get_odd", {}, "alice")).is_error


async def test_dangerous_args_still_blocked():
    gw, _, ds, reg = await setup()
    grant(reg, ds)
    assert (await gw.call_tool("s__get_odd", {"path": "~/.ssh/id_rsa"}, "alice")).is_error


async def test_write_tool_needs_allow_write():
    write_tools = [tool("get_odd", "Get odd.")]  # readOnlyHint 없음 → 쓰기로 판별
    gw, _, ds, reg = await setup(tools=write_tools)
    grant(reg, ds)
    assert await gw.list_tools("alice") == []
    gw.enforcer.allow_write_override = True
    assert [t.name for t in await gw.list_tools("alice")] == ["s__get_odd"]


async def test_allowed_call_records_override():
    gw, store, ds, reg = await setup()
    grant(reg, ds)
    await gw.call_tool("s__get_odd", {}, "alice")
    allowed = [e for e in store.events if e.kind == "call_allowed"][-1]
    assert allowed.detail["override"] == "o1" and allowed.detail["user"] == "alice"
