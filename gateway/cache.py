"""(A) cache.py — 담당: A. 다른 사람은 고치지 않는다.

도구 정의를 정규화해 해시를 뜨고, SQLite 신뢰 캐시(해시 → 등급)와 승인 대기열을 관리한다. (SPEC 6장)
게이트웨이 여러 개와 대시보드가 같은 DB 파일을 같이 쓴다.
"""

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from gateway import paths
from gateway.audit import KST

HASH_FIELDS = ("name", "description", "inputSchema", "annotations")


def tool_hash(tool: dict) -> str:
    """도구 정의의 지문. 키 순서·공백이 달라도 같은 내용이면 같은 값이 나오도록 정규화한다."""
    subset = {k: tool[k] for k in HASH_FIELDS if k in tool}
    canonical = json.dumps(subset, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class Verdict:
    server: str
    tool: str
    hash: str
    grade: str                      # "allow" / "restrict" / "block"
    score: int
    signals: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    results: list[dict] = field(default_factory=list)
    approved: bool = False
    created_at: str = ""

    @property
    def effective(self) -> str:
        """실제로 적용되는 상태: allow / restrict / approved / block"""
        if self.grade == "restrict" and self.approved:
            return "approved"
        return self.grade


_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    server     TEXT NOT NULL,
    hash       TEXT NOT NULL,
    tool       TEXT NOT NULL,
    grade      TEXT NOT NULL,
    score      INTEGER NOT NULL,
    signals    TEXT NOT NULL,
    reasons    TEXT NOT NULL,
    results    TEXT NOT NULL,
    approved   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    PRIMARY KEY (server, hash)
);
"""


class TrustStore:
    def __init__(self, db_file: Path | None = None):
        self.db_file = Path(db_file or paths.db_path())
        self.db_file.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("PRAGMA journal_mode=WAL")  # 여러 프로세스가 동시에 읽고 쓰기
            c.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_file, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(r: sqlite3.Row) -> Verdict:
        return Verdict(
            server=r["server"], tool=r["tool"], hash=r["hash"], grade=r["grade"], score=r["score"],
            signals=json.loads(r["signals"]), reasons=json.loads(r["reasons"]),
            results=json.loads(r["results"]), approved=bool(r["approved"]), created_at=r["created_at"],
        )

    def get(self, server: str, h: str) -> Verdict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM verdicts WHERE server=? AND hash=?", (server, h)).fetchone()
        return self._row(r) if r else None

    def put(self, v: Verdict) -> None:
        v.created_at = v.created_at or datetime.now(KST).isoformat(timespec="seconds")
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO verdicts VALUES (?,?,?,?,?,?,?,?,?,?)",
                (v.server, v.hash, v.tool, v.grade, v.score,
                 json.dumps(v.signals, ensure_ascii=False), json.dumps(v.reasons, ensure_ascii=False),
                 json.dumps(v.results, ensure_ascii=False, default=str), int(v.approved), v.created_at),
            )

    def approve(self, server: str, h: str) -> bool:
        """제한 도구를 승인한다. 그 해시에만 적용된다. 차단 도구는 승인할 수 없다."""
        with self._conn() as c:
            cur = c.execute(
                "UPDATE verdicts SET approved=1 WHERE server=? AND hash=? AND grade='restrict'",
                (server, h),
            )
            return cur.rowcount == 1

    def all(self) -> list[Verdict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM verdicts ORDER BY created_at DESC").fetchall()
        return [self._row(r) for r in rows]

    def pending(self) -> list[Verdict]:
        return [v for v in self.all() if v.grade == "restrict" and not v.approved]
