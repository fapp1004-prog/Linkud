"""검증 파이프라인: 규칙 필터 → LLM 판별 → 공급망 조회 → 결정 테이블 → 판정."""

from __future__ import annotations

import logging
from typing import Protocol

from linkud.models import ToolVerdict
from linkud.verify.analyze import analyze
from linkud.verify.decision import Policy, SupplySignals, decide, is_read_tool
from linkud.verify.hashing import canonical_tool
from linkud.verify.judge.base import Judge
from linkud.verify.service import VerifyRequest
from linkud.verify.supply.annotations import annotation_mismatch

logger = logging.getLogger(__name__)


class SupplyChecker(Protocol):
    async def check(self, server: str) -> SupplySignals: ...


class PipelineVerifier:
    def __init__(
        self,
        judge: Judge,
        supply: SupplyChecker | None = None,
        policy: Policy | None = None,
    ) -> None:
        self.judge = judge
        self.supply = supply
        self.policy = policy or Policy()

    async def _supply(self, server: str) -> SupplySignals:
        if self.supply is None:
            return SupplySignals(reasons=["공급망 검증 꺼짐"])
        try:
            return await self.supply.check(server)
        except Exception as exc:
            # 공급망 조회 실패는 '정보 없음'으로 처리한다 (기획서 10장 리스크 완화)
            logger.warning("공급망 조회 실패: %s (%s)", server, type(exc).__name__)
            return SupplySignals(reasons=[f"공급망 조회 실패: {type(exc).__name__}"])

    async def verify(self, req: VerifyRequest) -> ToolVerdict:
        definition = canonical_tool(req.tool)
        analysis = await analyze(definition, self.judge)
        supply = await self._supply(req.server)
        mismatch = annotation_mismatch(definition)
        decision = decide(analysis, supply, annotation_mismatch=mismatch, policy=self.policy)
        is_read, read_reasons = is_read_tool(definition, analysis)

        reasons = decision.reasons + read_reasons
        if req.previous is not None:
            reasons.append(f"정의 변경 후 재검증 (이전 등급: {req.previous.tier.label})")
        return ToolVerdict(
            server=req.server,
            tool=req.tool.name,
            tool_hash=req.tool_hash,
            tier=decision.tier,
            is_read=is_read,
            reasons=reasons,
            details={
                "decision_row": decision.row,
                "annotation_mismatch": mismatch,
                "analysis": analysis.to_dict(),
                "supply": {
                    "available": supply.available,
                    "malicious_package": supply.malicious_package,
                    "severe_vulnerability": supply.severe_vulnerability,
                },
            },
        )
