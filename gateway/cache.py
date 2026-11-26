"""(A) cache.py — 담당: A. 다른 사람은 고치지 않는다.

도구 정의를 정규화해 해시를 뜨고, SQLite에 **판정과 승인만** 캐시한다. (SPEC 6장, 결정 #28·#31)
B의 LLM 결과는 B의 저장소(data/llm_cache.db)가 맡는다.
게이트웨이 여러 개와 대시보드가 같은 DB 파일을 같이 쓴다.

캐시 키 = (server_id, 도구 해시, 서버 파일 지문, 의존성 지문, 정책 지문, 실행 모드)
→ 하나라도 다르면 다른 판정이다. 그래서 서버 코드·의존성·정책·모드가 바뀌면 이전 판정과 승인은 쓰이지 않는다.
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
UNAVAILABLE = ""  # 지문을 못 구했을 때. 이런 판정은 재사용·승인하지 않는다 (fail-closed)


def tool_hash(tool: dict) -> str:
    """도구 정의의 지문. 키 순서·공백이 달라도 같은 내용이면 같은 값이 나오도록 정규화한다.
    B도 LLM 결과 저장 키로 이 함수를 import해서 쓴다 (결정 #28)."""
    subset = {k: tool[k] for k in HASH_FIELDS if k in tool}
    canonical = json.dumps(subset, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def now() -> str:
    return datetime.now(KST).isoformat(timespec="seconds")


@dataclass(frozen=True)
class CacheKey:
    server_id: str
    tool_hash: str
    file_fp: str
    dep_fp: str
    policy_fp: str
    mode: str

    @property
    def complete(self) -> bool:
        """필수 지문이 다 있어야 판정을 재사용하고 승인할 수 있다."""
        return all([self.server_id, self.tool_hash, self.file_fp, self.dep_fp, self.policy_fp, self.mode])


@dataclass
class Verdict:
    key: CacheKey
    tool: str
    grade: str                      # "allow" / "restrict" / "block"
    score: int
    signals: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    results: list[dict] = field(default_factory=list)
    exposable: bool = True          # 제한일 때 정제해서 보여줄 수 있나 (SPEC 7장). False면 비노출·호출 거절
    server_name: str = ""           # 서버 자기 신고 이름·버전 (표시·신원 장부 갱신용)
    server_version: str = ""
    approved: bool = False
    created_at: str = ""
    approved_at: str = ""
    rowid: int | None = None

    @property
    def server(self) -> str:
        return self.key.server_id

    @property
    def hash(self) -> str:
        return self.key.tool_hash

    @property
    def effective(self) -> str:
        """실제로 적용되는 상태: allow / restrict / approved / block"""
        if self.grade == "restrict" and self.approved and self.approvable:
            return "approved"
        return self.grade

    @property
    def approvable(self) -> bool:
        return self.grade == "restrict" and self.exposable and self.key.complete


# 이전 형식(verdicts)과 섞이지 않게 새 표를 쓴다 — 지문·모드가 없는 옛 기록은 재사용하지 않는다 (SPEC 6장)
_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts_v2 (
    server_id      TEXT NOT NULL,
    tool_hash      TEXT NOT NULL,
    file_fp        TEXT NOT NULL,
    dep_fp         TEXT NOT NULL,
    policy_fp      TEXT NOT NULL,
    mode           TEXT NOT NULL,
    tool           TEXT NOT NULL,
    grade          TEXT NOT NULL,
    score          INTEGER NOT NULL,
    signals        TEXT NOT NULL,
    reasons        TEXT NOT NULL,
    results        TEXT NOT NULL,
    exposable      INTEGER NOT NULL DEFAULT 1,
    server_name    TEXT NOT NULL DEFAULT '',
    server_version TEXT NOT NULL DEFAULT '',
    approved       INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL,
    approved_at    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (server_id, tool_hash, file_fp, dep_fp, policy_fp, mode)
);
"""

# 신원 장부: 주인은 C(checkers/identity.py). 스키마는 결정 #27과 같다.
# A는 대시보드 승인 때 갱신만 한다. 캐시 무효화 대상이 아니다.
IDENTITY_SCHEMA = """
CREATE TABLE IF NOT EXISTS identity_baseline (
    server_id  TEXT PRIMARY KEY,
    name       TEXT,
    version    TEXT,
    file_fp    TEXT,
    dep_fp     TEXT,
    first_seen TEXT,
    updated_at TEXT
);
"""

_COLS = ("server_id, tool_hash, file_fp, dep_fp, policy_fp, mode, tool, grade, score, signals, reasons, "
         "results, exposable, server_name, server_version, approved, created_at, approved_at")


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
        key = CacheKey(r["server_id"], r["tool_hash"], r["file_fp"], r["dep_fp"], r["policy_fp"], r["mode"])
        return Verdict(
            key=key, tool=r["tool"], grade=r["grade"], score=r["score"],
            signals=json.loads(r["signals"]), reasons=json.loads(r["reasons"]), results=json.loads(r["results"]),
            exposable=bool(r["exposable"]), server_name=r["server_name"], server_version=r["server_version"],
            approved=bool(r["approved"]), created_at=r["created_at"], approved_at=r["approved_at"],
            rowid=r["rowid"],
        )

    def get(self, key: CacheKey) -> Verdict | None:
        """키가 완전히 같은 판정만 돌려준다. 지문이 빠진 키는 재사용하지 않는다."""
        if not key.complete:
            return None
        with self._conn() as c:
            r = c.execute(
                f"SELECT rowid, {_COLS} FROM verdicts_v2 WHERE server_id=? AND tool_hash=? AND file_fp=? "
                "AND dep_fp=? AND policy_fp=? AND mode=?",
                (key.server_id, key.tool_hash, key.file_fp, key.dep_fp, key.policy_fp, key.mode),
            ).fetchone()
        return self._row(r) if r else None

    def by_rowid(self, rowid: int) -> Verdict | None:
        with self._conn() as c:
            r = c.execute(f"SELECT rowid, {_COLS} FROM verdicts_v2 WHERE rowid=?", (rowid,)).fetchone()
        return self._row(r) if r else None

    def lookup(self, key: CacheKey) -> Verdict | None:
        """tools/call 때 쓰는 조회. 지문이 빠진 키도 찾는다(그 판정은 승인될 수 없어서 허용으로 바뀌지 않는다)."""
        with self._conn() as c:
            r = c.execute(
                f"SELECT rowid, {_COLS} FROM verdicts_v2 WHERE server_id=? AND tool_hash=? AND file_fp=? "
                "AND dep_fp=? AND policy_fp=? AND mode=?",
                (key.server_id, key.tool_hash, key.file_fp, key.dep_fp, key.policy_fp, key.mode),
            ).fetchone()
        return self._row(r) if r else None

    def put(self, v: Verdict) -> Verdict:
        """새 판정을 저장한다. 같은 키가 이미 있으면(지문이 없어 재검사한 경우) 내용을 덮어쓰고 승인은 풀린다.
        rowid는 유지된다 → 감사 로그·대시보드가 rowid로 판정을 가리킬 수 있다."""
        v.created_at = v.created_at or now()
        k = v.key
        vals = (k.server_id, k.tool_hash, k.file_fp, k.dep_fp, k.policy_fp, k.mode, v.tool, v.grade, v.score,
                json.dumps(v.signals, ensure_ascii=False), json.dumps(v.reasons, ensure_ascii=False),
                json.dumps(v.results, ensure_ascii=False, default=str), int(v.exposable), v.server_name,
                v.server_version, int(v.approved), v.created_at, v.approved_at)
        update = ", ".join(f"{c}=excluded.{c}" for c in _COLS.replace(" ", "").split(",")[6:])
        with self._conn() as c:
            c.execute(
                f"INSERT INTO verdicts_v2 ({_COLS}) VALUES ({','.join('?' * len(vals))}) "
                f"ON CONFLICT(server_id, tool_hash, file_fp, dep_fp, policy_fp, mode) DO UPDATE SET {update}",
                vals,
            )
            v.rowid = c.execute(
                "SELECT rowid FROM verdicts_v2 WHERE server_id=? AND tool_hash=? AND file_fp=? AND dep_fp=? "
                "AND policy_fp=? AND mode=?",
                (k.server_id, k.tool_hash, k.file_fp, k.dep_fp, k.policy_fp, k.mode)).fetchone()[0]
        return v

    def approve(self, rowid: int, mode: str) -> tuple[bool, str]:
        """제한 판정을 승인한다 (SPEC 8장). (성공 여부, 이유)를 돌려준다.

        - 제한 등급, 정제해서 보여줄 수 있는 도구, 지문이 다 있는 판정, 현재 모드와 같은 판정만 승인한다.
        - identity_changed 판정을 승인하면 신원 장부를 그 판정 때의 값으로 갱신하고,
          같은 서버의 승인 안 된 identity_changed 판정은 지워서 다음 tools/list 때 다시 검사하게 한다 (결정 #27).
        """
        v = self.by_rowid(rowid)
        if v is None:
            return False, "판정을 찾을 수 없습니다"
        if v.key.mode != mode:
            return False, f"현재 모드({mode})와 다른 모드({v.key.mode})의 판정은 승인할 수 없습니다"
        if v.grade != "restrict":
            return False, "제한 등급만 승인할 수 있습니다"
        if not v.exposable:
            return False, "안전하게 정제할 수 없는 도구라 승인할 수 없습니다"
        if not v.key.complete:
            return False, "서버 지문이 없는 판정은 승인할 수 없습니다"
        with self._conn() as c:
            c.execute("UPDATE verdicts_v2 SET approved=1, approved_at=? WHERE rowid=?", (now(), rowid))
            if "identity_changed" in v.signals:
                c.executescript(IDENTITY_SCHEMA)
                c.execute(
                    "INSERT INTO identity_baseline (server_id, name, version, file_fp, dep_fp, first_seen, updated_at) "
                    "VALUES (?,?,?,?,?,?,?) ON CONFLICT(server_id) DO UPDATE SET name=excluded.name, "
                    "version=excluded.version, file_fp=excluded.file_fp, dep_fp=excluded.dep_fp, "
                    "updated_at=excluded.updated_at",
                    (v.key.server_id, v.server_name, v.server_version, v.key.file_fp, v.key.dep_fp, now(), now()),
                )
                c.execute(
                    "DELETE FROM verdicts_v2 WHERE server_id=? AND mode=? AND approved=0 AND rowid<>? "
                    "AND signals LIKE '%\"identity_changed\"%'",
                    (v.key.server_id, v.key.mode, rowid),
                )
        return True, "승인했습니다"

    def all(self, mode: str | None = None) -> list[Verdict]:
        q, args = f"SELECT rowid, {_COLS} FROM verdicts_v2", ()
        if mode:
            q, args = q + " WHERE mode=?", (mode,)
        with self._conn() as c:
            rows = c.execute(q + " ORDER BY created_at DESC, rowid DESC", args).fetchall()
        return [self._row(r) for r in rows]

    def pending(self, mode: str | None = None) -> list[Verdict]:
        return [v for v in self.all(mode) if v.grade == "restrict" and not v.approved]
