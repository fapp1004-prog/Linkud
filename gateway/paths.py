"""(A) paths.py — 게이트웨이가 쓰는 파일 위치. 담당: A.

Claude Desktop은 게이트웨이를 아무 작업 폴더에서나 실행할 수 있어서,
상대 경로 대신 레포 루트 기준 절대 경로를 쓴다. 환경변수로 바꿀 수 있다(테스트용).
"""

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def policy_path() -> Path:
    return Path(os.environ.get("LINKUD_POLICY", REPO_ROOT / "policy.yaml"))


def db_path() -> Path:
    return Path(os.environ.get("LINKUD_DB", REPO_ROOT / "data" / "trust.db"))


def audit_path() -> Path:
    return Path(os.environ.get("LINKUD_AUDIT", REPO_ROOT / "logs" / "audit.jsonl"))
