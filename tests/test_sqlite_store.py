"""2-1: SqliteStore는 DB 작업을 스레드로 넘겨 이벤트 루프를 막지 않는다."""

import anyio
import anyio.lowlevel

from linkud.models import Tier, ToolVerdict
from linkud.store.base import AuditEvent
from linkud.store.sqlite import SqliteStore


async def _ticks_during(work) -> tuple[int, int]:
    ticks = 0
    done = False

    async def ticker():
        nonlocal ticks
        while not done:
            ticks += 1
            await anyio.lowlevel.checkpoint()

    async with anyio.create_task_group() as tg:
        tg.start_soon(ticker)
        await anyio.lowlevel.checkpoint()
        before = ticks
        await work()
        after = ticks
        done = True
    return before, after


async def test_db_writes_do_not_block_event_loop(tmp_path):
    store = SqliteStore(tmp_path / "t.db")

    async def work():
        for i in range(20):
            await store.log(AuditEvent("x", "s", f"t{i}", {}))
            await store.save_verdict(ToolVerdict("s", f"t{i}", "h", Tier.TRUSTED, False, []))
        await store.audit_log(10)
        await store.latest_verdicts()

    before, after = await _ticks_during(work)
    assert after > before  # DB 작업 중에도 다른 태스크가 돌았다


async def test_roundtrip_still_works(tmp_path):
    store = SqliteStore(tmp_path / "t.db")
    await store.save_verdict(ToolVerdict("s", "t", "h", Tier.PARTIAL, True, ["r"], {"k": 1}))
    await store.log(AuditEvent("verdict", "s", "t", {"a": "한글"}))
    [v] = await store.latest_verdicts()
    assert (v.tier, v.is_read, v.details) == (Tier.PARTIAL, True, {"k": 1})
    [e] = await store.audit_log()
    assert e.detail == {"a": "한글"}
