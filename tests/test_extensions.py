"""8단계(확장): 관리 API·Slack 승인·인자 검사."""

import hashlib
import hmac
import json
import time
from urllib.parse import urlencode

import httpx
import pytest

from linkud.admin.slack import SlackNotifier, build_message, escape, verify_signature
from linkud.config import parse_config
from linkud.enforcement.arguments import dangerous_arguments
from linkud.models import Tier
from linkud.proxy.gateway import create_app
from linkud.store.memory import MemoryStore
from linkud.verify.judge.base import JudgeLabel, JudgeVerdict
from linkud.verify.judge.fake import FakeJudge
from tests.helpers import FakeDownstream, make_gateway, pipeline, serve, tool

AGENT, ADMIN, SECRET = "agent-token", "admin-token", "slack-signing-secret"
SUSPICIOUS = FakeJudge(
    decide=lambda d: (
        JudgeVerdict(JudgeLabel.SUSPICIOUS, False, ["odd"], 0.6) if d["name"] == "odd" else None
    )
)


# --- 인자 검사 -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "blocked"),
    [
        ({"path": "~/.ssh/id_rsa"}, True),
        ({"path": "/home/u/.aws/credentials"}, True),
        ({"files": ["README.md", "/etc/shadow"]}, True),
        ({"nested": {"p": "../../../etc/hosts"}}, True),
        ({"body": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc"}, True),
        ({"path": "project/.env"}, True),
        ({"path": "src/main.py"}, False),
        ({"text": "how do I set up ssh keys?"}, False),
        ({"path": "../README.md"}, False),
        ({"password": "hunter2"}, False),  # 키 이름은 보지 않는다
        (None, False),
    ],
)
def test_dangerous_arguments(args, blocked):
    assert bool(dangerous_arguments(args)) is blocked


async def test_dangerous_call_blocked_even_for_trusted_tool():
    ds = FakeDownstream("s", [tool("read_file", "Read a file.")])
    gw, store = make_gateway([ds])
    await gw.list_tools()
    result = await gw.call_tool("s__read_file", {"path": "~/.ssh/id_rsa"})
    assert result.is_error and "dangerous argument" in result.content[0].text
    assert ds.calls == []
    denied = [e for e in store.events if e.kind == "call_denied"][-1]
    assert "ssh" in denied.detail["reason"] and "id_rsa" not in json.dumps(denied.detail)
    assert not (await gw.call_tool("s__read_file", {"path": "README.md"})).is_error


# --- 결정 적용 -------------------------------------------------------------------


async def test_decision_promotes_pending_tool_and_rugpull_reverts_it():
    ds = FakeDownstream("s", [tool("odd", "Odd tool.")])
    gw, store = make_gateway([ds], verifier=pipeline(SUSPICIOUS))
    assert await gw.list_tools() == []
    pending = gw.enforcer.service.pending()
    assert [v.tool for v in pending] == ["odd"]

    await gw.enforcer.service.apply_decision(
        "s", "odd", pending[0].tool_hash, Tier.TRUSTED, actor="t"
    )
    assert [t.name for t in await gw.list_tools()] == ["s__odd"]
    assert any(e.kind == "decision" for e in store.events)

    # 승인 뒤 정의를 바꾸면 해시가 달라져 다시 승인 대기
    ds.tools = [tool("odd", "Odd tool, changed.")]
    assert await gw.list_tools() == []


async def test_decision_with_stale_hash_is_rejected():
    gw, _ = make_gateway(
        [FakeDownstream("s", [tool("odd", "Odd.")])], verifier=pipeline(SUSPICIOUS)
    )
    await gw.list_tools()
    with pytest.raises(LookupError):
        await gw.enforcer.service.apply_decision("s", "odd", "0" * 64, Tier.TRUSTED, actor="t")


# --- 관리 API·인증 ----------------------------------------------------------------


def make_app(monkeypatch, ds, **env):
    monkeypatch.setenv("LINKUD_AUTH_TOKENS", AGENT)
    monkeypatch.setenv("LINKUD_ADMIN_TOKENS", ADMIN)
    for k in ("SLACK_WEBHOOK_URL", "SLACK_SIGNING_SECRET", "SLACK_APPROVERS"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return create_app(
        parse_config({}), downstreams=[ds], store=MemoryStore(), verifier=pipeline(SUSPICIOUS)
    )


async def _mcp_list(http, url):
    # 최소 JSON-RPC로 tools/list를 불러 검증 경로를 돌린다
    headers = {
        "Authorization": f"Bearer {AGENT}",
        "Accept": "application/json, text/event-stream",
        "Mcp-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/list",
    }
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }
    return await http.post(f"{url}/mcp", json=body, headers=headers)


async def test_admin_api_flow(monkeypatch):
    app = make_app(monkeypatch, FakeDownstream("s", [tool("odd", "Odd."), tool("get_x", "Get x.")]))
    async with serve(app) as url, httpx.AsyncClient() as http:
        await app.state.gateway.list_tools()
        admin = {"Authorization": f"Bearer {ADMIN}"}

        assert (await http.get(f"{url}/admin/pending")).status_code == 401
        agent_hdr = {"Authorization": f"Bearer {AGENT}"}
        assert (await http.get(f"{url}/admin/pending", headers=agent_hdr)).status_code == 401

        pending = (await http.get(f"{url}/admin/pending", headers=admin)).json()
        assert [p["tool"] for p in pending] == ["odd"]
        assert (await http.get(f"{url}/admin/servers", headers=admin)).json() == {"s": "pending"}

        bad = await http.post(
            f"{url}/admin/decisions", headers=admin, json={**pending[0], "tier": "pending"}
        )
        assert bad.status_code == 400
        stale = await http.post(
            f"{url}/admin/decisions",
            headers=admin,
            json={**pending[0], "tool_hash": "x", "tier": "trusted"},
        )
        assert stale.status_code == 409
        ok = await http.post(
            f"{url}/admin/decisions",
            headers=admin,
            json={**pending[0], "tier": "trusted", "note": "검토함"},
        )
        assert ok.status_code == 200 and ok.json()["tier"] == "trusted"

        assert (await http.get(f"{url}/admin/pending", headers=admin)).json() == []
        await app.state.gateway.list_tools()
        assert (await http.get(f"{url}/admin/servers", headers=admin)).json() == {"s": "trusted"}
        audit = (await http.get(f"{url}/admin/audit?limit=50", headers=admin)).json()
        assert any(e["kind"] == "decision" and e["detail"]["note"] == "검토함" for e in audit)


async def test_admin_api_closed_without_admin_tokens(monkeypatch):
    monkeypatch.setenv("LINKUD_AUTH_TOKENS", AGENT)
    monkeypatch.delenv("LINKUD_ADMIN_TOKENS", raising=False)
    app = create_app(
        parse_config({}),
        downstreams=[FakeDownstream("s", [tool("x")])],
        store=MemoryStore(),
        verifier=pipeline(),
    )
    async with serve(app) as url, httpx.AsyncClient() as http:
        for token in (ADMIN, AGENT):
            resp = await http.get(
                f"{url}/admin/pending", headers={"Authorization": f"Bearer {token}"}
            )
            assert resp.status_code == 401


# --- Slack ----------------------------------------------------------------------


def sign(body: bytes, ts: int | None = None) -> dict[str, str]:
    ts = ts or int(time.time())
    sig = "v0=" + hmac.new(SECRET.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    return {
        "x-slack-request-timestamp": str(ts),
        "x-slack-signature": sig,
        "content-type": "application/x-www-form-urlencoded",
    }


def test_signature_verification():
    body = b"payload=x"
    h = sign(body)
    assert verify_signature(SECRET, h["x-slack-request-timestamp"], body, h["x-slack-signature"])
    assert not verify_signature(
        SECRET, h["x-slack-request-timestamp"], b"payload=y", h["x-slack-signature"]
    )
    old = sign(body, int(time.time()) - 1000)
    assert not verify_signature(
        SECRET, old["x-slack-request-timestamp"], body, old["x-slack-signature"]
    )


def test_message_escapes_untrusted_text():
    from linkud.models import ToolVerdict

    v = ToolVerdict(
        "s", "t", "h" * 64, Tier.PENDING, False, ["<!channel> <https://evil|click> & more"]
    )
    msg = json.dumps(build_message(v))
    assert "<!channel>" not in msg and "&lt;!channel&gt;" in msg
    assert escape("a<b>&") == "a&lt;b&gt;&amp;"


async def test_notifier_sends_only_pending():
    sent = []
    http = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: sent.append(json.loads(r.content)) or httpx.Response(200)
        )
    )
    notifier = SlackNotifier("https://hooks.slack.com/services/x", http)
    gw, _ = make_gateway(
        [FakeDownstream("s", [tool("odd", "Odd."), tool("fine", "Fine.")])],
        verifier=pipeline(SUSPICIOUS),
    )
    gw.enforcer.service.on_verdict.append(notifier.notify)
    await gw.list_tools()
    import asyncio

    await asyncio.gather(*notifier._tasks)
    assert len(sent) == 1 and "odd" in sent[0]["text"]
    assert {b["action_id"] for b in sent[0]["blocks"][2]["elements"]} == {
        "linkud_trusted",
        "linkud_partial",
        "linkud_untrusted",
    }


async def test_slack_button_applies_decision(monkeypatch):
    app = make_app(
        monkeypatch,
        FakeDownstream("s", [tool("odd", "Odd.")]),
        SLACK_SIGNING_SECRET=SECRET,
        SLACK_APPROVERS="U1",
    )
    async with serve(app) as url, httpx.AsyncClient() as http:
        await app.state.gateway.list_tools()
        v = app.state.gateway.enforcer.service.pending()[0]

        def payload(user, tier):
            value = json.dumps({"server": "s", "tool": "odd", "hash": v.tool_hash, "tier": tier})
            p = {
                "user": {"id": user},
                "actions": [{"value": value}],
                "response_url": "https://evil.example/x",
            }
            return urlencode({"payload": json.dumps(p)}).encode()

        body = payload("U1", "partial")
        assert (
            await http.post(
                f"{url}/slack/actions",
                content=body,
                headers={**sign(body), "x-slack-signature": "v0=bad"},
            )
        ).status_code == 401

        intruder = payload("U2", "trusted")
        assert (
            await http.post(f"{url}/slack/actions", content=intruder, headers=sign(intruder))
        ).status_code == 200
        assert app.state.gateway.enforcer.service.pending()  # 권한 없는 사용자는 확정 못 함

        assert (
            await http.post(f"{url}/slack/actions", content=body, headers=sign(body))
        ).status_code == 200
        assert app.state.gateway.enforcer.service.pending() == []
        latest = app.state.gateway.enforcer.service.latest()[0]
        assert latest.tier is Tier.PARTIAL and latest.details["decided_by"] == "slack:U1"
