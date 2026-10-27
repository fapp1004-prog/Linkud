"""4-2: 감사 로그 보존 기간 정리."""

import time

import pytest

from linkud.config import parse_config
from linkud.store.base import AuditEvent
from linkud.store.memory import MemoryStore
from linkud.store.retention import purge_once
from linkud.store.sqlite import SqliteStore

DAY = 86400


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    return MemoryStore() if request.param == "memory" else SqliteStore(tmp_path / "t.db")


async def test_purge_removes_only_old_rows(store):
    now = time.time()
    await store.log(AuditEvent("old", "s", "t", {}, now - 100 * DAY))
    await store.log(AuditEvent("recent", "s", "t", {}, now - 10 * DAY))
    removed = await store.purge_audit(before=now - 90 * DAY)
    assert removed == 1
    assert [e.kind for e in await store.audit_log()] == ["recent"]


async def test_purge_once_logs_and_respects_retention(store):
    now = time.time()
    await store.log(AuditEvent("old", "s", "t", {}, now - 40 * DAY))
    removed = await purge_once(store, retention_days=30)
    assert removed == 1
    kinds = [e.kind for e in await store.audit_log()]
    assert kinds == ["audit_purged"]  # 정리 자체도 기록한다


async def test_retention_disabled_with_zero(store):
    await store.log(AuditEvent("old", "s", "t", {}, time.time() - 1000 * DAY))
    assert await purge_once(store, retention_days=0) == 0
    assert len(await store.audit_log()) == 1


async def test_gateway_purges_on_startup(tmp_path):
    from linkud.proxy.gateway import create_app
    from tests.helpers import FakeDownstream, TrustingVerifier, serve, tool

    db = SqliteStore(tmp_path / "g.db")
    await db.log(AuditEvent("old", "s", "t", {}, time.time() - 400 * DAY))
    cfg = parse_config({"gateway": {"audit_retention_days": 365}})
    assert cfg.audit_retention_days == 365
    app = create_app(
        cfg, downstreams=[FakeDownstream("a", [tool("x")])], store=db, verifier=TrustingVerifier()
    )
    async with serve(app):
        pass
    assert [e.kind for e in await db.audit_log()] == ["audit_purged"]
