"""SQLite 저장소.

호출이 짧고 로컬 디스크라 동기 sqlite3를 락으로 감싸 쓴다. 부하가 커지면
PostgreSQL 구현으로 바꾼다(`Store` 인터페이스 유지).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from linkud.models import Tier, ToolVerdict
from linkud.store.base import AuditEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    tool_hash TEXT NOT NULL,
    tier TEXT NOT NULL,
    is_read INTEGER NOT NULL,
    reasons TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS verdicts_key ON verdicts (server, tool_hash);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    detail TEXT NOT NULL
);
"""


class SqliteStore:
    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    async def save_verdict(self, verdict: ToolVerdict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO verdicts (server, tool, tool_hash, tier, is_read, reasons, details, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    verdict.server,
                    verdict.tool,
                    verdict.tool_hash,
                    verdict.tier.value,
                    int(verdict.is_read),
                    json.dumps(verdict.reasons, ensure_ascii=False),
                    json.dumps(verdict.details, ensure_ascii=False),
                    verdict.created_at,
                ),
            )

    async def latest_verdicts(self) -> list[ToolVerdict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT server, tool, tool_hash, tier, is_read, reasons, details, created_at"
                " FROM verdicts WHERE id IN (SELECT MAX(id) FROM verdicts GROUP BY server, tool_hash)"
            ).fetchall()
        return [
            ToolVerdict(
                server=r[0],
                tool=r[1],
                tool_hash=r[2],
                tier=Tier(r[3]),
                is_read=bool(r[4]),
                reasons=json.loads(r[5]),
                details=json.loads(r[6]),
                created_at=r[7],
            )
            for r in rows
        ]

    async def log(self, event: AuditEvent) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO audit (ts, kind, server, tool, detail) VALUES (?, ?, ?, ?, ?)",
                (
                    event.ts or time.time(),
                    event.kind,
                    event.server,
                    event.tool,
                    json.dumps(event.detail, ensure_ascii=False),
                ),
            )

    async def audit_log(self, limit: int = 100) -> list[AuditEvent]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT kind, server, tool, detail, ts FROM audit ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [AuditEvent(r[0], r[1], r[2], json.loads(r[3]), r[4]) for r in rows]
