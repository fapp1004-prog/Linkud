"""B-6: 관리 API(목록·회수), override_revoked 기록, Slack 알림 이스케이프."""

import json

import httpx

from linkud.admin.slack import SlackNotifier, build_override_message
from linkud.enforcement.overrides import Override
from tests.helpers import serve
from tests.test_break_glass_api import deny_ref, make, post

ADMIN = {"Authorization": "Bearer admin"}


async def test_admin_lists_and_revokes(monkeypatch):
    app, _, store = make(monkeypatch)
    ref = await deny_ref(app, "s__get_odd", "alice")
    gw = app.state.gateway
    async with serve(app) as url, httpx.AsyncClient() as http:
        assert (await post(http, url, "human-alice", ref)).status_code == 200
        listed = (await http.get(f"{url}/admin/overrides", headers=ADMIN)).json()
        assert len(listed) == 1
        o = listed[0]
        assert (
            o["user"] == "alice"
            and o["tool"] == "get_odd"
            and o["active"] is True
            and o["ref"] == ref
        )
        agent = await http.get(
            f"{url}/admin/overrides", headers={"Authorization": "Bearer agent-alice"}
        )
        assert agent.status_code == 401

        assert (
            await http.delete(f"{url}/admin/overrides/{o['id']}", headers=ADMIN)
        ).status_code == 200
        assert (
            await http.delete(f"{url}/admin/overrides/{o['id']}", headers=ADMIN)
        ).status_code == 404
        assert (await http.delete(f"{url}/admin/overrides/nope", headers=ADMIN)).status_code == 404
        listed = (await http.get(f"{url}/admin/overrides", headers=ADMIN)).json()
        assert listed[0]["active"] is False and listed[0]["revoked_at"]
    assert await gw.list_tools("alice") == []  # 회수 즉시 다시 숨김
    revoked = [e for e in store.events if e.kind == "override_revoked"]
    assert (
        len(revoked) == 1
        and revoked[0].detail["user"] == "alice"
        and revoked[0].detail["actor"] == "admin-api"
    )
    assert (await store.load_overrides(since=0))[0].revoked_at  # 저장소에도 회수 기록


async def test_admin_overrides_absent_when_disabled(monkeypatch):
    app, _, _ = make(monkeypatch, enabled=False)
    async with serve(app) as url, httpx.AsyncClient() as http:
        assert (await http.get(f"{url}/admin/overrides", headers=ADMIN)).status_code == 404


def test_override_message_escapes_reason():
    o = Override("o1", "alice", "s", "get_odd", "h" * 64, "LK-AAAAAAAA",
                 "<!channel> <https://evil.example|click> & 확인", 0.0, 3600.0)  # fmt: skip
    msg = json.dumps(build_override_message(o), ensure_ascii=False)
    assert "<!channel>" not in msg and "&lt;!channel&gt;" in msg
    assert "<https://evil" not in msg and "&amp;" in msg
    assert "alice" in msg and "s__get_odd" in msg


async def test_slack_notified_on_grant(monkeypatch):
    sent = []

    async def fake_send(self, message):
        sent.append(message)

    monkeypatch.setattr(SlackNotifier, "_send", fake_send)
    app, _, _ = make(monkeypatch, extra={"slack": "https://hooks.slack.com/services/x"})
    ref = await deny_ref(app, "s__get_odd", "alice")
    async with serve(app) as url, httpx.AsyncClient() as http:
        r = await post(
            http, url, "human-alice", ref, reason="<!here> 오탐으로 보여 확인 후 허용합니다"
        )
        assert r.status_code == 200
    import asyncio

    for _ in range(20):
        if any("임시 허용" in m.get("text", "") for m in sent):
            break
        await asyncio.sleep(0.05)
    override_msgs = [m for m in sent if "임시 허용" in m.get("text", "")]
    assert len(override_msgs) == 1
    assert "<!here>" not in json.dumps(override_msgs[0], ensure_ascii=False)


async def test_override_survives_gateway_restart_with_sqlite(monkeypatch, tmp_path):
    from linkud.config import parse_config
    from linkud.proxy.gateway import create_app
    from linkud.store.sqlite import SqliteStore
    from tests.helpers import FakeDownstream, pipeline, tool
    from tests.test_break_glass_api import RO, SUSPICIOUS, env

    env(monkeypatch)
    cfg = parse_config({"gateway": {"break_glass_enabled": True}})

    def build():
        ds = FakeDownstream("s", [tool("get_odd", "Get odd.", annotations=RO)])
        return create_app(
            cfg,
            downstreams=[ds],
            store=SqliteStore(tmp_path / "g.db"),
            verifier=pipeline(SUSPICIOUS),
        )

    first = build()
    async with serve(first) as url, httpx.AsyncClient() as http:
        ref = await deny_ref(first, "s__get_odd", "alice")
        assert (await post(http, url, "human-alice", ref)).status_code == 200

    second = build()  # 재시작: 새 프로세스처럼 메모리는 비어 있고 SQLite만 남음
    async with serve(second):
        gw = second.state.gateway
        assert [t.name for t in await gw.list_tools("alice")] == ["s__get_odd"]
        assert await gw.list_tools("bob") == []
