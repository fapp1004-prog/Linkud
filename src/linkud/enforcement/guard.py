"""집행 계층: 목록 필터와 호출 가드.

권한은 서버 등급(가장 위험한 도구 기준)에 따라 도구 단위로 준다:
신뢰 = 전부, 부분신뢰 = 읽기 도구만, 불신·승인 대기 = 없음.

목록 필터는 캐시에 판정이 없으면 검증 경로를 부른다. 호출 가드는 캐시만 조회하며
LLM·네트워크를 부르지 않는다(런타임 경로 분리).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import mcp.types as types

from linkud.enforcement.arguments import dangerous_arguments
from linkud.models import Tier, ToolVerdict
from linkud.store.base import AuditEvent, Cache, Store, verdict_key
from linkud.verify.decision import permits, server_tier
from linkud.verify.hashing import tool_hash
from linkud.verify.service import VerificationService


@dataclass(frozen=True)
class CallDecision:
    allowed: bool
    reason: str


class Enforcer:
    def __init__(
        self,
        service: VerificationService,
        cache: Cache,
        store: Store,
        *,
        inspect_arguments: bool = True,
    ) -> None:
        self.service = service
        self.inspect_arguments = inspect_arguments
        self.cache = cache
        self.store = store
        # 서버 → (도구 이름 → 마지막 목록 요청에서 본 정의 해시). 호출 가드가 쓴다
        self._seen: dict[str, dict[str, str]] = {}
        # 서버 → 마지막으로 계산한 등급 (변경 시 감사 로그용)
        self._tiers: dict[str, Tier | None] = {}

    async def visible_tools(self, server: str, tools: Sequence[types.Tool]) -> list[types.Tool]:
        names = [t.name for t in tools]
        duplicated = {n for n in names if names.count(n) > 1}
        # 이름이 겹치는 도구는 어떤 정의가 호출될지 알 수 없으므로 서버 전체를 승인 대기로 본다.
        # 목록에서 사라진 도구도 더는 호출할 수 없게 이 서버의 기록을 새 목록으로 갈아 끼운다
        unique = [t for t in tools if t.name not in duplicated]
        verdicts = await self.service.verdicts(server, unique)
        self._seen[server] = {t.name: tool_hash(t) for t in unique}

        listed: list[ToolVerdict | None] = [verdicts.get(t.name) for t in unique]
        tier = self._effective_tier(server, server_tier(listed + [None] * len(duplicated)))
        await self._note_tier(server, tier)
        return [t for t in unique if permits(tier, verdicts.get(t.name))]

    def _effective_tier(self, server: str, tier: Tier | None) -> Tier | None:
        """재검증 상한으로 묶인 서버는 판정과 관계없이 승인 대기 (메모리 조회만)."""
        if self.service.is_throttled(server):
            return Tier.PENDING
        return tier

    async def _note_tier(self, server: str, tier: Tier | None) -> None:
        if self._tiers.get(server, "unset") != tier:
            self._tiers[server] = tier
            await self.store.log(
                AuditEvent("server_tier", server, "*", {"tier": tier.value if tier else None})
            )

    async def _cached_verdicts(self, server: str) -> dict[str, ToolVerdict | None]:
        seen = self._seen.get(server, {})
        return {name: await self.cache.get(verdict_key(server, h)) for name, h in seen.items()}

    async def check_call(
        self, server: str, tool: str, arguments: dict[str, Any] | None = None
    ) -> CallDecision:
        verdicts = await self._cached_verdicts(server)
        tier = self._effective_tier(server, server_tier(verdicts.values()))
        verdict = verdicts.get(tool)
        if tool not in verdicts:
            decision = CallDecision(False, "목록에서 확인되지 않은 도구")
        elif verdict is None:
            decision = CallDecision(False, "판정 없음 (검증 실패 또는 진행 중)")
        elif not permits(tier, verdict):
            label = tier.label if tier else "없음"
            kind = "읽기" if verdict.is_read else "쓰기"
            decision = CallDecision(False, f"서버 등급 {label}: {kind} 도구 호출 불가")
        elif self.inspect_arguments and (danger := dangerous_arguments(arguments)):
            decision = CallDecision(False, f"위험한 인자: {', '.join(danger)}")
        else:
            decision = CallDecision(True, f"서버 등급 {tier.label if tier else ''}")
        await self.store.log(
            AuditEvent(
                "call_allowed" if decision.allowed else "call_denied",
                server,
                tool,
                {"reason": decision.reason, "hash": self._seen.get(server, {}).get(tool)},
            )
        )
        return decision

    def server_tiers(self) -> dict[str, Tier | None]:
        return dict(self._tiers)
