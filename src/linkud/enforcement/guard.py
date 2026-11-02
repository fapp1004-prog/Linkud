"""집행 계층: 목록 필터와 호출 가드.

권한은 서버 등급(가장 위험한 도구 기준)에 따라 도구 단위로 준다:
신뢰 = 전부, 부분신뢰 = 읽기 도구만, 불신·승인 대기 = 없음.

목록 필터는 캐시에 판정이 없으면 검증 경로를 부른다. 호출 가드는 캐시만 조회하며
LLM·네트워크를 부르지 않는다(런타임 경로 분리).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import mcp.types as types

from linkud.enforcement.arguments import dangerous_arguments
from linkud.enforcement.refs import new_ref
from linkud.models import Tier, ToolVerdict
from linkud.store.base import AuditEvent, Cache, DuplicateRef, Store, verdict_key
from linkud.verify.decision import permits, server_tier
from linkud.verify.hashing import tool_hash
from linkud.verify.service import VerificationService

logger = logging.getLogger(__name__)


# 에이전트에게 돌려주는 유일한 거부 문구. 원인(거부 코드·등급·이유)은 감사 로그에만 남긴다
DENY_TEMPLATE = "[Linkud] 이 도구는 지금 사용할 수 없습니다. 관리자 문의 시 참조 번호: {ref}"
_REF_ATTEMPTS = 5


@dataclass(frozen=True)
class CallDecision:
    allowed: bool
    reason: str
    # 거부 코드 (docs/deny-response.md 3장). 허용이면 None
    code: str | None = None
    ref: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


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

    async def record_denial(
        self,
        server: str,
        tool: str,
        code: str,
        reason: str,
        *,
        kind: str = "call_denied",
        detail: dict[str, Any] | None = None,
    ) -> str:
        """거부를 감사 로그에 남기고 참조 번호를 돌려준다. 번호가 겹치면 새로 뽑아 다시 기록한다."""
        body = {"code": code, "reason": reason, **(detail or {})}
        for _ in range(_REF_ATTEMPTS):
            ref = new_ref()
            try:
                await self.store.log(AuditEvent(kind, server, tool[:200], body, ref=ref))
                return ref
            except DuplicateRef:
                continue
        # 저장소가 계속 겹친다고 하면 기록 없이도 거부는 그대로 한다(fail-closed)
        logger.error("참조 번호를 기록하지 못함: %s/%s", server, tool[:200])
        return ref

    async def _deny(
        self, server: str, tool: str, code: str, reason: str, detail: dict[str, Any]
    ) -> CallDecision:
        ref = await self.record_denial(server, tool, code, reason, detail=detail)
        return CallDecision(False, reason, code, ref, detail)

    async def check_call(
        self, server: str, tool: str, arguments: dict[str, Any] | None = None
    ) -> CallDecision:
        verdicts = await self._cached_verdicts(server)
        verdict = verdicts.get(tool)
        h = self._seen.get(server, {}).get(tool)
        raw_tier = server_tier(verdicts.values())
        tier = self._effective_tier(server, raw_tier)
        detail: dict[str, Any] = {
            "hash": h,
            "tier": tier.value if tier else None,
            "tool_tier": verdict.tier.value if verdict else None,
        }
        if tool not in verdicts:
            return await self._deny(
                server, tool, "not_listed", "목록에서 확인되지 않은 도구", detail
            )
        # 묶인 서버는 검증을 건너뛰어 판정이 비어 있을 수 있으므로 판정 없음보다 먼저 본다
        if self.service.is_throttled(server):
            return await self._deny(server, tool, "throttled", "재검증 상한으로 묶인 서버", detail)
        if verdict is None:
            return await self._deny(
                server, tool, "no_verdict", "판정 없음 (검증 실패 또는 진행 중)", detail
            )
        if not permits(tier, verdict):
            label = tier.label if tier else "없음"
            kind = "읽기" if verdict.is_read else "쓰기"
            detail["is_read"] = verdict.is_read
            return await self._deny(
                server, tool, "tier", f"서버 등급 {label}: {kind} 도구 호출 불가", detail
            )
        if self.inspect_arguments and (danger := dangerous_arguments(arguments)):
            return await self._deny(
                server, tool, "dangerous_args", f"위험한 인자: {', '.join(danger)}", detail
            )
        decision = CallDecision(True, f"서버 등급 {tier.label if tier else ''}")
        await self.store.log(
            AuditEvent("call_allowed", server, tool, {"reason": decision.reason, "hash": h})
        )
        return decision

    def server_tiers(self) -> dict[str, Tier | None]:
        return dict(self._tiers)
