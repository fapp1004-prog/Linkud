"""기준선 검증기 (2단계 임시): 처음 본 도구는 신뢰, 정의가 바뀐 도구는 승인 대기.

규칙 필터·LLM 판별·결정 테이블을 붙이는 단계에서 파이프라인 검증기로 대체된다.
"""

from __future__ import annotations

from linkud.models import Tier, ToolVerdict
from linkud.verify.service import VerifyRequest


class BaselineVerifier:
    async def verify(self, req: VerifyRequest) -> ToolVerdict:
        if req.previous is not None:
            return ToolVerdict(
                req.server,
                req.tool.name,
                req.tool_hash,
                Tier.PENDING,
                is_read=False,
                reasons=["도구 정의가 이전 판정 이후 변경됨 (러그풀 의심)"],
            )
        return ToolVerdict(
            req.server,
            req.tool.name,
            req.tool_hash,
            Tier.TRUSTED,
            is_read=False,
            reasons=["처음 등록된 도구 (기준선)"],
        )
