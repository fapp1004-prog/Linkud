"""B-2: 임시 허용 기록 저장(Memory·SQLite)·복원과 메모리 레지스트리."""

import time

import pytest

from linkud.enforcement.overrides import Override, OverrideRegistry
from linkud.store.memory import MemoryStore
from linkud.store.sqlite import SqliteStore

NOW = 1_000_000.0


def ov(id="o1", user="alice", tool="t", tool_hash="h1", created=NOW, ttl=8 * 3600, **kw):
    return Override(
        id,
        user,
        "s",
        tool,
        tool_hash,
        "LK-AAAAAAAA",
        "오탐으로 보임, 확인함",
        created,
        created + ttl,
        **kw,
    )


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    return MemoryStore() if request.param == "memory" else SqliteStore(tmp_path / "t.db")


async def test_save_load_revoke(store):
    await store.save_override(ov("o1"))
    await store.save_override(ov("o2", created=NOW - 3 * 86400))  # 오래된 기록
    loaded = await store.load_overrides(since=NOW - 86400)
    assert [o.id for o in loaded] == ["o1"]
    assert loaded[0] == ov("o1")
    assert await store.revoke_override("o1", NOW + 10) is True
    assert await store.revoke_override("nope", NOW + 10) is False
    [o] = await store.load_overrides(since=NOW - 86400)
    assert o.revoked_at == NOW + 10


async def test_sqlite_restores_after_restart(tmp_path):
    first = SqliteStore(tmp_path / "t.db")
    await first.save_override(ov("o1"))
    first.close()
    registry = OverrideRegistry()
    await registry.restore(SqliteStore(tmp_path / "t.db"), now=NOW)
    assert registry.active_for("alice", "s", "t", "h1", now=NOW + 60) is not None


def test_registry_scope_and_expiry():
    r = OverrideRegistry()
    r.add(ov("o1"))
    assert r.active_for("alice", "s", "t", "h1", now=NOW + 1) is not None
    assert r.active_for("bob", "s", "t", "h1", now=NOW + 1) is None  # 다른 사용자
    assert r.active_for("alice", "s", "t", "h2", now=NOW + 1) is None  # 해시 변경
    assert r.active_for("alice", "s", "other", "h1", now=NOW + 1) is None
    assert r.active_for(None, "s", "t", "h1", now=NOW + 1) is None  # 익명
    assert r.active_for("alice", "s", "t", "h1", now=NOW + 8 * 3600) is None  # 만료
    assert [o.id for o in r.newly_expired(now=NOW + 8 * 3600)] == ["o1"]
    assert r.newly_expired(now=NOW + 9 * 3600) == []  # 만료 기록은 한 번만


def test_registry_revoke_and_count():
    r = OverrideRegistry()
    r.add(ov("o1"))
    r.add(ov("o2", tool="u", created=NOW - 3600))
    r.add(ov("o3", tool="v", created=NOW - 2 * 86400))
    assert r.count_recent("alice", since=NOW - 86400) == 2
    assert r.revoke("o1", at=NOW + 5) is not None
    assert r.active_for("alice", "s", "t", "h1", now=NOW + 6) is None
    assert r.count_recent("alice", since=NOW - 86400) == 2  # 회수해도 사용 횟수는 그대로
    assert r.used_ref("LK-AAAAAAAA")


def test_override_active_flag():
    o = ov("o1")
    assert o.active(NOW + 1) and not o.active(NOW + 8 * 3600)
    assert not ov("o2", revoked_at=time.time()).active(NOW + 1)
