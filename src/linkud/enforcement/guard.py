"""집행 계층: 목록 필터와 호출 가드.

목록 필터는 캐시에 판정이 없으면 검증 경로를 부른다. 호출 가드는 캐시만 조회하며
LLM·네트워크를 부르지 않는다(런타임 경로 분리).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import mcp.types as types

from linkud.models import Tier, ToolVerdict
from linkud.store.base import AuditEvent, Cache, Store, verdict_key
from linkud.verify.hashing import tool_hash
from linkud.verify.service import VerificationService


def permits(verdict: ToolVerdict | None) -> bool:
    """도구를 보여주고 실행시켜도 되는가. 판정이 없으면 항상 거부."""
    return verdict is not None and verdict.tier is Tier.TRUSTED


@dataclass(frozen=True)
class CallDecision:
    allowed: bool
    reason: str


class Enforcer:
    def __init__(self, service: VerificationService, cache: Cache, store: Store) -> None:
        self.service = service
        self.cache = cache
        self.store = store
        # (서버, 도구 이름) → 마지막 목록 요청에서 본 정의 해시. 호출 가드가 쓴다
        self._seen: dict[tuple[str, str], str] = {}

    async def visible_tools(self, server: str, tools: Sequence[types.Tool]) -> list[types.Tool]:
        names = [t.name for t in tools]
        duplicated = {n for n in names if names.count(n) > 1}
        unique = [t for t in tools if t.name not in duplicated]
        # 이름이 겹치는 도구는 어떤 정의가 호출될지 알 수 없으므로 모두 숨기고 호출도 막는다.
        # 목록에서 사라진 도구도 더는 호출할 수 없게 이 서버의 기록을 새 목록으로 갈아 끼운다
        for key in [k for k in self._seen if k[0] == server]:
            del self._seen[key]

        verdicts = await self.service.verdicts(server, unique)
        visible = []
        for tool in unique:
            self._seen[(server, tool.name)] = tool_hash(tool)
            if permits(verdicts.get(tool.name)):
                visible.append(tool)
        return visible

    async def check_call(self, server: str, tool: str) -> CallDecision:
        h = self._seen.get((server, tool))
        verdict = await self.cache.get(verdict_key(server, h)) if h else None
        if h is None:
            decision = CallDecision(False, "목록에서 확인되지 않은 도구")
        elif verdict is None:
            decision = CallDecision(False, "판정 없음 (검증 실패 또는 진행 중)")
        elif not permits(verdict):
            decision = CallDecision(False, f"등급 {verdict.tier.label}: 호출 불가")
        else:
            decision = CallDecision(True, f"등급 {verdict.tier.label}")
        await self.store.log(
            AuditEvent(
                "call_allowed" if decision.allowed else "call_denied",
                server,
                tool,
                {"reason": decision.reason, "hash": h},
            )
        )
        return decision
