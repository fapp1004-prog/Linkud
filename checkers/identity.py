"""(C) identity.py — 신원 고정. 담당: C. 다른 사람은 고치지 않는다.

서버를 처음 볼 때 이름·버전·파일 지문을 장부(identity_baseline)에 적어두고,
다음부터 하나라도 달라졌으면 identity_changed(risk 100)를 낸다. policy.yaml이 '최소 제한'으로 처리한다.
(SPEC 4장, 결정안 ②)

- 장부는 신뢰 캐시와 같은 SQLite 파일의 '별도 테이블'이다. 캐시가 무효화돼도 지워지지 않는다.
- 서버 구분 키: server_id(A가 --server-id로 넘김). 아직 없으면 서버 폴더 절대경로를 쓴다.
  서버가 스스로 말한 이름은 거짓일 수 있어서 키로 쓰지 않는다.
- 대시보드에서 '신원 변경'을 승인하면 A가 update_baseline(server)를 불러 장부를 현재 값으로 바꾼다.
  (안 그러면 정상 업데이트 뒤에도 계속 '제한'으로 남음)
"""

import os
import sqlite3
from contextlib import closing
import time
from datetime import datetime, timezone
from pathlib import Path

from checkers.fingerprint import dep_fp, file_fp

REPO_ROOT = Path(__file__).resolve().parent.parent

SCHEMA = """CREATE TABLE IF NOT EXISTS identity_baseline (
    server_id  TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL,
    file_fp    TEXT NOT NULL,
    dep_fp     TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL
)"""


def db_path() -> Path:
    """A가 넣어주는 LINKUD_DB_PATH → A의 LINKUD_DB → 기본 data/trust.db 순서."""
    p = os.environ.get("LINKUD_DB_PATH") or os.environ.get("LINKUD_DB")
    return Path(p) if p else REPO_ROOT / "data" / "trust.db"


def server_key(server: dict) -> str:
    if server.get("server_id"):
        return str(server["server_id"])
    d = server.get("dir")
    if not d:
        raise ValueError("server_id도 서버 폴더(dir)도 없어서 서버를 구분할 수 없음")
    return "dir:" + str(Path(d).resolve())


def _connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=5)   # 게이트웨이 여러 개가 같은 파일을 쓰므로 잠금 대기
    con.execute(SCHEMA)
    return con


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _current(server: dict) -> dict:
    d = server.get("dir")
    return {"name": str(server.get("name", "")), "version": str(server.get("version", "")),
            "file_fp": file_fp(d), "dep_fp": dep_fp(d)}


def update_baseline(server: dict) -> None:
    """장부를 현재 값으로 덮어쓴다. 사람이 '신원 변경'을 승인했을 때만 부른다 (A의 대시보드)."""
    cur, key, now = _current(server), server_key(server), _now()
    with closing(_connect()) as con, con:
        con.execute(
            "INSERT INTO identity_baseline VALUES (?,?,?,?,?,?,?) ON CONFLICT(server_id) DO UPDATE SET "
            "name=excluded.name, version=excluded.version, file_fp=excluded.file_fp, "
            "dep_fp=excluded.dep_fp, updated_at=excluded.updated_at",
            (key, cur["name"], cur["version"], cur["file_fp"], cur["dep_fp"], now, now))


def check(tool: dict, server: dict) -> dict:
    started = time.monotonic()
    cur, key, now = _current(server), server_key(server), _now()
    with closing(_connect()) as con, con:
        con.execute("INSERT OR IGNORE INTO identity_baseline VALUES (?,?,?,?,?,?,?)",
                    (key, cur["name"], cur["version"], cur["file_fp"], cur["dep_fp"], now, now))
        row = con.execute("SELECT name, version, file_fp, dep_fp, first_seen FROM identity_baseline "
                          "WHERE server_id=?", (key,)).fetchone()
    base = dict(zip(("name", "version", "file_fp", "dep_fp", "first_seen"), row))

    changes = []
    for field, label in (("name", "이름"), ("version", "버전")):
        if base[field] != cur[field]:
            changes.append(f"{label} {base[field] or '(없음)'} → {cur[field] or '(없음)'}")
    if base["dep_fp"] != cur["dep_fp"]:
        changes.append(f"의존성 지문 {base['dep_fp'][:12]} → {cur['dep_fp'][:12]}")
    elif base["file_fp"] != cur["file_fp"]:
        changes.append(f"파일 지문 {base['file_fp'][:12]} → {cur['file_fp'][:12]}")

    ms = int((time.monotonic() - started) * 1000)
    if changes:
        return {"checker": "identity", "risk": 100, "hard_block": False, "signals": ["identity_changed"],
                "evidence": f"[{key}] 처음 등록({base['first_seen']})과 다름: " + "; ".join(changes),
                "latency_ms": ms}
    first = base["first_seen"] == now
    return {"checker": "identity", "risk": 0, "hard_block": False, "signals": [],
            "evidence": (f"[{key}] 첫 등록: {cur['name']} {cur['version']} 지문 {cur['file_fp'][:12]}"
                         if first else f"[{key}] 처음 등록({base['first_seen']})과 같음"),
            "latency_ms": ms}
