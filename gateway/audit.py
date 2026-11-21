"""(A) audit.py — 담당: A. 다른 사람은 고치지 않는다.

모든 판정과 근거를 JSONL 감사 로그에 남긴다. (SPEC 9장)
모든 게이트웨이 프로세스가 같은 파일에 한 줄씩 덧붙인다.
"""

import json
import secrets
import threading
from collections import deque
from datetime import datetime, timezone, timedelta
from pathlib import Path

from gateway import paths

KST = timezone(timedelta(hours=9))
_lock = threading.Lock()


def new_ref() -> str:
    """거부 응답에 붙이는 참조번호. 예: LK-ab12cd34"""
    return "LK-" + secrets.token_hex(4)


def write(event: str, **fields) -> dict:
    """감사 로그에 한 줄 쓴다. 쓰기에 실패해도 게이트웨이를 멈추지 않는다(stderr에 남김)."""
    record = {"ts": datetime.now(KST).isoformat(timespec="seconds"), "event": event, **fields}
    line = json.dumps(record, ensure_ascii=False, default=str)
    path: Path = paths.audit_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _lock, path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as e:
        import sys
        print(f"[audit] 로그 쓰기 실패: {e}", file=sys.stderr)
    return record


def read_recent(limit: int = 100) -> list[dict]:
    """최근 기록을 최신순으로 돌려준다 (대시보드용)."""
    path = paths.audit_path()
    if not path.exists():
        return []
    tail: deque[str] = deque(maxlen=limit)
    with path.open(encoding="utf-8") as f:
        for line in f:
            tail.append(line)
    out = []
    for line in reversed(tail):
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def find_ref(ref: str) -> list[dict]:
    """참조번호로 기록을 찾는다."""
    path = paths.audit_path()
    if not path.exists():
        return []
    found = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if ref in line:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("ref") == ref:
                    found.append(rec)
    return found
