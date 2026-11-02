"""A-1: 참조 번호 생성과 저장소의 ref 유일성·검색."""

import re
import sqlite3

import pytest

from linkud.enforcement.refs import REF_PATTERN, new_ref
from linkud.store.base import AuditEvent, DuplicateRef
from linkud.store.memory import MemoryStore
from linkud.store.sqlite import SqliteStore


def test_ref_format():
    for _ in range(100):
        assert re.fullmatch(r"LK-[0-9A-HJKMNP-TV-Z]{8}", new_ref())
        assert REF_PATTERN.fullmatch(new_ref())


def test_refs_do_not_repeat():
    refs = {new_ref() for _ in range(20000)}
    assert len(refs) == 20000


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    return MemoryStore() if request.param == "memory" else SqliteStore(tmp_path / "t.db")


async def test_ref_stored_and_found(store):
    await store.log(AuditEvent("call_denied", "s", "t", {"reason": "x"}, ref="LK-ABCDEFGH"))
    await store.log(AuditEvent("call_allowed", "s", "t", {}))
    found = await store.find_by_ref("LK-ABCDEFGH")
    assert found is not None and found.kind == "call_denied" and found.detail == {"reason": "x"}
    assert found.ref == "LK-ABCDEFGH"
    assert await store.find_by_ref("LK-ZZZZZZZZ") is None
    assert (await store.audit_log())[-1].ref == "LK-ABCDEFGH"


async def test_duplicate_ref_rejected(store):
    await store.log(AuditEvent("call_denied", "s", "t", {}, ref="LK-ABCDEFGH"))
    with pytest.raises(DuplicateRef):
        await store.log(AuditEvent("call_denied", "s", "u", {}, ref="LK-ABCDEFGH"))
    # ref가 없는 기록은 몇 개든 된다
    await store.log(AuditEvent("verdict", "s", "t", {}))
    await store.log(AuditEvent("verdict", "s", "t", {}))


async def test_sqlite_migrates_old_audit_table(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, kind TEXT NOT NULL,"
        " server TEXT NOT NULL, tool TEXT NOT NULL, detail TEXT NOT NULL);"
        "INSERT INTO audit (ts, kind, server, tool, detail) VALUES (1, 'verdict', 's', 't', '{}');"
    )
    conn.commit()
    conn.close()
    store = SqliteStore(path)
    await store.log(AuditEvent("call_denied", "s", "t", {}, ref="LK-ABCDEFGH"))
    assert (await store.find_by_ref("LK-ABCDEFGH")) is not None
    assert len(await store.audit_log()) == 2


async def test_admin_audit_search_by_ref(monkeypatch):
    import httpx

    from linkud.config import parse_config
    from linkud.proxy.gateway import create_app
    from tests.helpers import FakeDownstream, TrustingVerifier, serve, tool

    monkeypatch.setenv("LINKUD_AUTH_TOKENS", "agent")
    monkeypatch.setenv("LINKUD_ADMIN_TOKENS", "admin")
    app = create_app(
        parse_config({}),
        downstreams=[FakeDownstream("s", [tool("x")])],
        store=MemoryStore(),
        verifier=TrustingVerifier(),
    )
    gw = app.state.gateway
    await gw.list_tools()
    text = (await gw.call_tool("s__missing", {})).content[0].text
    ref = text.rsplit(" ", 1)[-1]
    admin = {"Authorization": "Bearer admin"}
    async with serve(app) as url, httpx.AsyncClient() as http:
        found = await http.get(f"{url}/admin/audit", params={"ref": ref}, headers=admin)
        assert found.status_code == 200
        [event] = found.json()
        assert event["ref"] == ref and event["kind"] == "call_denied"
        assert event["detail"]["code"] == "not_listed" and event["tool"] == "missing"

        missing = await http.get(f"{url}/admin/audit", params={"ref": "LK-ZZZZZZZZ"}, headers=admin)
        assert missing.status_code == 404
        bad = await http.get(f"{url}/admin/audit", params={"ref": "x' OR 1=1"}, headers=admin)
        assert bad.status_code == 400
        agent = await http.get(
            f"{url}/admin/audit", params={"ref": ref}, headers={"Authorization": "Bearer agent"}
        )
        assert agent.status_code == 401
