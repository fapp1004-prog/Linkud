"""저장소 인터페이스.

1차 구현은 메모리 캐시 + SQLite이고, 나중에 Redis/PostgreSQL로 바꿀 수 있도록
게이트웨이 코드는 이 인터페이스에만 의존한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from linkud.models import ToolVerdict


def verdict_key(server: str, tool_hash: str) -> str:
    """같은 정의라도 서버가 다르면 공급망 등 판정이 달라질 수 있어 서버를 키에 넣는다."""
    return f"{server}:{tool_hash}"


class Cache(Protocol):
    """해시 → 판정 캐시 (런타임 경로가 조회하는 유일한 곳)."""

    async def get(self, key: str) -> ToolVerdict | None: ...

    async def set(self, key: str, verdict: ToolVerdict) -> None: ...

    async def delete(self, key: str) -> None: ...


@dataclass(frozen=True)
class AuditEvent:
    kind: str  # verdict, rugpull, verify_failed, call_allowed, call_denied ...
    server: str
    tool: str
    detail: dict[str, Any] = field(default_factory=dict)
    ts: float = 0.0


class Store(Protocol):
    """판정 이력·감사 로그 영구 저장소."""

    async def save_verdict(self, verdict: ToolVerdict) -> None: ...

    async def latest_verdicts(self) -> list[ToolVerdict]:
        """(서버, 해시)마다 가장 최근 판정. 시작 시 캐시를 채우는 데 쓴다."""
        ...

    async def log(self, event: AuditEvent) -> None: ...

    async def audit_log(self, limit: int = 100) -> list[AuditEvent]: ...
