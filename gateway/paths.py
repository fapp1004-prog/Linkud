"""(A) paths.py — 게이트웨이가 쓰는 파일 위치와 실행 모드. 담당: A.

Claude Desktop은 게이트웨이를 아무 작업 폴더에서나 실행할 수 있어서,
상대 경로 대신 레포 루트 기준 절대 경로를 쓴다. 환경변수로 바꿀 수 있다(테스트용).
"""

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def mode() -> str:
    """실행 모드. 개발용 가짜 검사기를 쓰면 'dev', 아니면 'real'. 판정·캐시·대시보드에 같이 기록한다."""
    return "dev" if os.environ.get("LINKUD_DEV_CHECKERS") == "1" else "real"


def policy_path() -> Path:
    return Path(os.environ.get("LINKUD_POLICY", REPO_ROOT / "policy.yaml"))


def db_path() -> Path:
    """현재 모드의 신뢰 DB. 실제 data/trust.db, 개발 data/trust-dev.db (SPEC 12장).
    LINKUD_DB로 경로를 바꿔도 판정에 모드가 기록되므로 다른 모드의 판정은 재사용되지 않는다."""
    if "LINKUD_DB" in os.environ:
        return Path(os.environ["LINKUD_DB"])
    name = "trust-dev.db" if mode() == "dev" else "trust.db"
    return REPO_ROOT / "data" / name


def audit_path() -> Path:
    return Path(os.environ.get("LINKUD_AUDIT", REPO_ROOT / "logs" / "audit.jsonl"))
