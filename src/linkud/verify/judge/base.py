"""LLM 판별기 인터페이스와 출력 파싱.

판별기 출력은 정해진 JSON(verdict, is_write, reasons, confidence)만 받는다.
형식이 틀리면 내용과 상관없이 "의심"으로 처리한다(CLAUDE.md 원칙 6).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol


class JudgeLabel(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"


@dataclass(frozen=True)
class JudgeVerdict:
    label: JudgeLabel
    # 쓰기·삭제 등 상태를 바꾸는 도구인가. 판단 못 하면 None(→ 쓰기로 취급)
    is_write: bool | None
    reasons: list[str]
    confidence: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


class Judge(Protocol):
    async def judge(self, definition: dict[str, Any]) -> JudgeVerdict:
        """정규화된 도구 정의(`hashing.canonical_tool`)를 판별한다."""
        ...


# 구조화 출력 스키마 (어댑터가 모델에 요구하는 형식과 같음)
OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": [label.value for label in JudgeLabel]},
        "is_write": {"type": "boolean"},
        "reasons": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number"},
    },
    "required": ["verdict", "is_write", "reasons", "confidence"],
    "additionalProperties": False,
}

_MAX_REASONS = 5
_MAX_REASON_LEN = 300


def _suspicious(reason: str) -> JudgeVerdict:
    return JudgeVerdict(JudgeLabel.SUSPICIOUS, None, [reason], 0.0, {"parse_error": True})


def parse_output(text: str) -> JudgeVerdict:
    """모델 출력 문자열을 엄격하게 파싱한다. 실패하면 '의심'."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return _suspicious("판별기 출력이 JSON이 아님")
    if not isinstance(data, dict) or set(data) != set(OUTPUT_SCHEMA["required"]):
        return _suspicious("판별기 출력 필드가 스키마와 다름")
    verdict, is_write, reasons, confidence = (
        data["verdict"],
        data["is_write"],
        data["reasons"],
        data["confidence"],
    )
    if verdict not in {label.value for label in JudgeLabel}:
        return _suspicious("판별기 verdict 값이 허용 목록 밖")
    if not isinstance(is_write, bool):
        return _suspicious("판별기 is_write가 boolean이 아님")
    if not isinstance(reasons, list) or not all(isinstance(r, str) for r in reasons):
        return _suspicious("판별기 reasons가 문자열 목록이 아님")
    if isinstance(confidence, bool) or not isinstance(confidence, int | float):
        return _suspicious("판별기 confidence가 숫자가 아님")
    if not 0.0 <= float(confidence) <= 1.0:
        return _suspicious("판별기 confidence가 0~1 범위 밖")
    # 근거는 감사 로그에 문자열로만 남긴다. 길이를 잘라 로그 오염을 막는다
    clean = [r[:_MAX_REASON_LEN] for r in reasons[:_MAX_REASONS]]
    return JudgeVerdict(JudgeLabel(verdict), is_write, clean, float(confidence))
