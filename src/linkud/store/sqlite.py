"""SQLite 저장소.

동기 sqlite3 호출은 `anyio.to_thread.run_sync`로 작업 스레드에 넘겨 이벤트 루프를 막지 않는다.
연결 하나를 여러 스레드가 나눠 쓰므로 `threading.Lock`으로 직렬화한다. 부하가 커지면
PostgreSQL 구현으로 바꾼다(`Store` 인터페이스 유지).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

import anyio

from linkud.enforcement.overrides import Override
from linkud.models import Tier, ToolVerdict
from linkud.store.base import AuditEvent, DuplicateRef

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
CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts);
CREATE TABLE IF NOT EXISTS overrides (
    id TEXT PRIMARY KEY,
    user TEXT NOT NULL,
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    tool_hash TEXT NOT NULL,
    ref TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    revoked_at REAL
);
CREATE INDEX IF NOT EXISTS overrides_created ON overrides (created_at);
"""


class SqliteStore:
    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        """이전 버전 DB에 없는 칸·인덱스를 더한다."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(audit)")}
        if "ref" not in cols:
            self._conn.execute("ALTER TABLE audit ADD COLUMN ref TEXT")
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS audit_ref ON audit (ref) WHERE ref IS NOT NULL"
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    async def save_verdict(self, verdict: ToolVerdict) -> None:
        await anyio.to_thread.run_sync(self._save_verdict, verdict)

    def _save_verdict(self, verdict: ToolVerdict) -> None:
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
        return await anyio.to_thread.run_sync(self._latest_verdicts)

    def _latest_verdicts(self) -> list[ToolVerdict]:
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
        await anyio.to_thread.run_sync(self._log, event)

    def _log(self, event: AuditEvent) -> None:
        try:
            with self._lock, self._conn:
                self._conn.execute(
                    "INSERT INTO audit (ts, kind, server, tool, detail, ref) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        event.ts or time.time(),
                        event.kind,
                        event.server,
                        event.tool,
                        json.dumps(event.detail, ensure_ascii=False),
                        event.ref,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateRef(event.ref) from exc

    async def audit_log(self, limit: int = 100) -> list[AuditEvent]:
        return await anyio.to_thread.run_sync(self._audit_log, limit)

    def _audit_log(self, limit: int) -> list[AuditEvent]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT kind, server, tool, detail, ts, ref FROM audit ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [AuditEvent(r[0], r[1], r[2], json.loads(r[3]), r[4], r[5]) for r in rows]

    async def find_by_ref(self, ref: str) -> AuditEvent | None:
        return await anyio.to_thread.run_sync(self._find_by_ref, ref)

    def _find_by_ref(self, ref: str) -> AuditEvent | None:
        with self._lock:
            r = self._conn.execute(
                "SELECT kind, server, tool, detail, ts, ref FROM audit WHERE ref = ?", (ref,)
            ).fetchone()
        return None if r is None else AuditEvent(r[0], r[1], r[2], json.loads(r[3]), r[4], r[5])

    async def purge_audit(self, before: float) -> int:
        return await anyio.to_thread.run_sync(self._purge_audit, before)

    def _purge_audit(self, before: float) -> int:
        with self._lock, self._conn:
            return self._conn.execute("DELETE FROM audit WHERE ts < ?", (before,)).rowcount

    async def save_override(self, override: Override) -> None:
        await anyio.to_thread.run_sync(self._save_override, override)

    def _save_override(self, o: Override) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO overrides (id, user, server, tool, tool_hash, ref, reason, created_at,"
                " expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (o.id, o.user, o.server, o.tool, o.tool_hash, o.ref, o.reason, o.created_at,
                 o.expires_at, o.revoked_at),
            )  # fmt: skip

    async def revoke_override(self, override_id: str, at: float) -> bool:
        return await anyio.to_thread.run_sync(self._revoke_override, override_id, at)

    def _revoke_override(self, override_id: str, at: float) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE overrides SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (at, override_id),
            )
            return cur.rowcount == 1

    async def load_overrides(self, since: float) -> list[Override]:
        return await anyio.to_thread.run_sync(self._load_overrides, since)

    def _load_overrides(self, since: float) -> list[Override]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, user, server, tool, tool_hash, ref, reason, created_at, expires_at,"
                " revoked_at FROM overrides WHERE created_at >= ? ORDER BY created_at",
                (since,),
            ).fetchall()
        return [Override(*r) for r in rows]
