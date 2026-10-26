"""여러 모듈이 함께 쓰는 판정 모델."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Tier(StrEnum):
    """신뢰 등급 (기획서 5장)."""

    TRUSTED = "trusted"  # 신뢰: 전체 허용
    PARTIAL = "partial"  # 부분신뢰: 읽기만
    UNTRUSTED = "untrusted"  # 불신: 차단
    PENDING = "pending"  # 승인 대기: 숨김, 사람이 확정

    @property
    def label(self) -> str:
        return _LABELS[self]

    @property
    def risk(self) -> int:
        """서버 등급을 '가장 위험한 도구' 기준으로 고를 때 쓰는 위험도 순서."""
        return _RISK[self]


_LABELS = {
    Tier.TRUSTED: "신뢰",
    Tier.PARTIAL: "부분신뢰",
    Tier.UNTRUSTED: "불신",
    Tier.PENDING: "승인 대기",
}
_RISK = {Tier.TRUSTED: 0, Tier.PARTIAL: 1, Tier.PENDING: 2, Tier.UNTRUSTED: 3}


@dataclass(frozen=True)
class ToolVerdict:
    """도구 정의 하나(해시 단위)에 대한 판정. 근거(reasons)는 항상 남긴다."""

    server: str
    tool: str
    tool_hash: str
    tier: Tier
    is_read: bool
    reasons: list[str]
    details: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
