"""파이썬 메모리 캐시·저장소."""

from __future__ import annotations

import time

from linkud.models import ToolVerdict
from linkud.store.base import AuditEvent, verdict_key


class MemoryCache:
    def __init__(self) -> None:
        self._data: dict[str, ToolVerdict] = {}

    async def get(self, key: str) -> ToolVerdict | None:
        return self._data.get(key)

    async def set(self, key: str, verdict: ToolVerdict) -> None:
        self._data[key] = verdict

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)


class MemoryStore:
    """테스트용 저장소. 프로세스가 끝나면 사라진다."""

    def __init__(self) -> None:
        self.verdicts: list[ToolVerdict] = []
        self.events: list[AuditEvent] = []

    async def save_verdict(self, verdict: ToolVerdict) -> None:
        self.verdicts.append(verdict)

    async def latest_verdicts(self) -> list[ToolVerdict]:
        latest: dict[str, ToolVerdict] = {}
        for v in self.verdicts:
            latest[verdict_key(v.server, v.tool_hash)] = v
        return list(latest.values())

    async def log(self, event: AuditEvent) -> None:
        if not event.ts:
            event = AuditEvent(event.kind, event.server, event.tool, event.detail, time.time())
        self.events.append(event)

    async def audit_log(self, limit: int = 100) -> list[AuditEvent]:
        return list(reversed(self.events))[:limit]
