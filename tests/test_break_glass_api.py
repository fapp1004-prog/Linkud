"""B-4: POST /override 허용 조건·사람 전용 토큰·횟수·사유, 설정 검증."""

import httpx
import pytest

from linkud.config import ConfigError, parse_config
from linkud.models import Tier, ToolVerdict
from linkud.proxy.gateway import create_app
from linkud.store.memory import MemoryStore
from linkud.verify.judge.base import JudgeLabel, JudgeVerdict
from linkud.verify.judge.fake import FakeJudge
from tests.helpers import FakeDownstream, make_gateway, pipeline, serve, tool  # noqa: F401

RO = {"readOnlyHint": True}
DENY = "이 참조 번호로는 임시 허용할 수 없습니다."
SUSPICIOUS = FakeJudge(
    decide=lambda d: (
        JudgeVerdict(JudgeLabel.SUSPICIOUS, False, ["odd"], 0.6) if d["name"] == "get_odd" else None
    )
)


def env(monkeypatch, override="alice=human-alice,bob=human-bob", slack=None):
    monkeypatch.setenv("LINKUD_AUTH_TOKENS", "alice=agent-alice,bob=agent-bob,anon-token")
    monkeypatch.setenv("LINKUD_ADMIN_TOKENS", "admin")
    if override is None:
        monkeypatch.delenv("LINKUD_OVERRIDE_TOKENS", raising=False)
    else:
        monkeypatch.setenv("LINKUD_OVERRIDE_TOKENS", override)
    for k in ("SLACK_WEBHOOK_URL", "SLACK_SIGNING_SECRET"):
        monkeypatch.delenv(k, raising=False)
    if slack:
        monkeypatch.setenv("SLACK_WEBHOOK_URL", slack)


def make(monkeypatch, *, enabled=True, extra=None, tools=None, verifier=None, **gw):
    env(monkeypatch, **(extra or {}))
    ds = FakeDownstream(
        "s",
        tools
        or [
            tool("get_odd", "Get odd.", annotations=RO),
            tool("get_fine", "Get fine.", annotations=RO),
        ],
    )
    cfg = parse_config({"gateway": {"break_glass_enabled": enabled, **gw}})
    store = MemoryStore()
    app = create_app(cfg, downstreams=[ds], store=store, verifier=verifier or pipeline(SUSPICIOUS))
    return app, ds, store


async def deny_ref(app, name, user, args=None):
    gw = app.state.gateway
    await gw.list_tools(user)
    text = (await gw.call_tool(name, args or {}, user)).content[0].text
    return text.rsplit(" ", 1)[-1]


def post(http, url, token, ref, reason="오탐으로 보입니다. 설명을 직접 확인했습니다."):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return http.post(f"{url}/override", json={"ref": ref, "reason": reason}, headers=headers)


async def test_disabled_by_default_has_no_route(monkeypatch):
    env(monkeypatch)
    app = create_app(
        parse_config({}), downstreams=[FakeDownstream("s", [tool("x")])], store=MemoryStore()
    )
    assert not any(getattr(r, "path", "").startswith("/override") for r in app.routes)
    async with serve(app) as url, httpx.AsyncClient() as http:
        assert (await http.get(f"{url}/override")).status_code in (401, 404)
        assert (await post(http, url, "human-alice", "LK-AAAAAAAA")).status_code in (401, 404)


async def test_grant_shows_tool_to_that_user_only(monkeypatch):
    app, _, store = make(monkeypatch)
    ref = await deny_ref(app, "s__get_odd", "alice")
    async with serve(app) as url, httpx.AsyncClient() as http:
        r = await post(http, url, "human-alice", ref)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["granted"] is True and body["tool"] == "s__get_odd" and body["expires_at"]
    gw = app.state.gateway
    assert [t.name for t in await gw.list_tools("alice")] == ["s__get_odd"]
    assert await gw.list_tools("bob") == []
    granted = [e for e in store.events if e.kind == "override_granted"]
    assert (
        len(granted) == 1 and granted[0].detail["user"] == "alice" and granted[0].detail["reason"]
    )


async def test_mcp_tools_have_no_bypass(monkeypatch):
    app, _, _ = make(monkeypatch)
    names = [t.name for t in await app.state.gateway.list_tools("alice")]
    assert all(n.startswith("s__") for n in names)
    assert not any(w in n.lower() for n in names for w in ("override", "break", "glass", "allow"))


async def test_other_users_ref_rejected(monkeypatch):
    app, _, _ = make(monkeypatch)
    ref = await deny_ref(app, "s__get_odd", "alice")
    async with serve(app) as url, httpx.AsyncClient() as http:
        r = await post(http, url, "human-bob", ref)
        assert r.status_code == 403 and r.json()["error"] == DENY


async def test_anonymous_agent_ref_rejected(monkeypatch):
    app, _, _ = make(monkeypatch)
    ref = await deny_ref(app, "s__get_odd", None)  # 익명 토큰으로 받은 거부
    async with serve(app) as url, httpx.AsyncClient() as http:
        assert (await post(http, url, "human-alice", ref)).status_code == 403


async def test_mcp_token_cannot_override(monkeypatch):
    app, _, _ = make(monkeypatch)
    ref = await deny_ref(app, "s__get_odd", "alice")
    async with serve(app) as url, httpx.AsyncClient() as http:
        for token in ("agent-alice", "anon-token", None, "admin"):
            assert (await post(http, url, token, ref)).status_code == 401


@pytest.mark.parametrize(
    "case", ["untrusted", "dangerous", "not_listed", "unknown", "throttled", "bad_ref", "made_up"]
)
async def test_ineligible_refs_rejected_with_same_text(monkeypatch, case):
    class Untrusted:
        async def verify(self, req):
            return ToolVerdict(
                req.server, req.tool.name, req.tool_hash, Tier.UNTRUSTED, True, ["bad"]
            )

    app, ds, _ = make(monkeypatch, verifier=Untrusted() if case == "untrusted" else None)
    gw = app.state.gateway
    if case == "untrusted":
        ref = await deny_ref(app, "s__get_odd", "alice")
    elif case == "dangerous":
        app2, _, _ = make(monkeypatch, verifier=pipeline())  # 신뢰 서버
        app, gw = app2, app2.state.gateway
        ref = await deny_ref(app, "s__get_odd", "alice", {"path": "~/.ssh/id_rsa"})
    elif case == "not_listed":
        ref = await deny_ref(app, "s__nope", "alice")
    elif case == "unknown":
        ref = await deny_ref(app, "zz__nope", "alice")
    elif case == "throttled":
        await gw.list_tools("alice")
        gw.enforcer.service._throttled["s"] = 1.0
        ref = await deny_ref(app, "s__get_odd", "alice")
    elif case == "bad_ref":
        ref = "LK-0000000O"  # 형식 틀림
    else:
        ref = "LK-ZZZZZZZZ"  # 없는 번호
    async with serve(app) as url, httpx.AsyncClient() as http:
        r = await post(http, url, "human-alice", ref)
        assert r.status_code == 403 and r.json() == {"error": DENY}


async def test_hash_changed_since_denial_rejected(monkeypatch):
    app, ds, _ = make(monkeypatch)
    ref = await deny_ref(app, "s__get_odd", "alice")
    ds.tools[0] = tool("get_odd", "Get odd, changed.", annotations=RO)
    await app.state.gateway.list_tools("alice")
    async with serve(app) as url, httpx.AsyncClient() as http:
        assert (await post(http, url, "human-alice", ref)).status_code == 403


async def test_ref_used_once(monkeypatch):
    app, _, _ = make(monkeypatch)
    ref = await deny_ref(app, "s__get_odd", "alice")
    async with serve(app) as url, httpx.AsyncClient() as http:
        assert (await post(http, url, "human-alice", ref)).status_code == 200
        assert (await post(http, url, "human-alice", ref)).status_code == 403


@pytest.mark.parametrize("reason", [None, "", "짧음", "x" * 501, 123])
async def test_reason_required(monkeypatch, reason):
    app, _, _ = make(monkeypatch)
    ref = await deny_ref(app, "s__get_odd", "alice")
    async with serve(app) as url, httpx.AsyncClient() as http:
        body = {"ref": ref} if reason is None else {"ref": ref, "reason": reason}
        r = await http.post(
            f"{url}/override", json=body, headers={"Authorization": "Bearer human-alice"}
        )
        assert r.status_code == 400


async def test_daily_limit(monkeypatch):
    app, _, _ = make(monkeypatch, break_glass_daily_limit=1)
    ref1 = await deny_ref(app, "s__get_odd", "alice")
    async with serve(app) as url, httpx.AsyncClient() as http:
        assert (await post(http, url, "human-alice", ref1)).status_code == 200
        ref2 = await deny_ref(app, "s__get_fine", "alice")
        assert (await post(http, url, "human-alice", ref2)).status_code == 429


async def test_write_tool_needs_allow_write(monkeypatch):
    write = [tool("get_odd", "Get odd.")]  # readOnlyHint 없음 → 쓰기
    app, _, _ = make(monkeypatch, tools=write)
    ref = await deny_ref(app, "s__get_odd", "alice")
    async with serve(app) as url, httpx.AsyncClient() as http:
        assert (await post(http, url, "human-alice", ref)).status_code == 403
    app2, _, _ = make(monkeypatch, tools=write, break_glass_allow_write=True)
    ref2 = await deny_ref(app2, "s__get_odd", "alice")
    async with serve(app2) as url, httpx.AsyncClient() as http:
        assert (await post(http, url, "human-alice", ref2)).status_code == 200


@pytest.mark.parametrize(
    ("override", "gw"),
    [
        (None, {}),  # 켜져 있는데 사람 전용 토큰 없음
        ("human-alice", {}),  # 익명 사람 전용 토큰
        ("carol=human-carol", {}),  # MCP 토큰에 없는 이름
        ("alice=agent-alice", {}),  # MCP 토큰과 같은 값
        ("alice=human-alice", {"break_glass_ttl_hours": 25}),
        ("alice=human-alice", {"break_glass_ttl_hours": 0}),
        ("alice=human-alice", {"break_glass_daily_limit": 0}),
    ],
)
def test_config_validation(monkeypatch, override, gw):
    with pytest.raises(ConfigError):
        make(monkeypatch, extra={"override": override}, **gw)
