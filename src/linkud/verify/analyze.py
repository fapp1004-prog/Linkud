"""검증 경로 분석: 규칙 필터 → LLM 판별.

결과(근거 포함)는 결정 테이블의 입력이 된다. 판별기 API 오류·타임아웃은 예외로
올려 보내 검증 실패(→ 도구 숨김)로 처리한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from linkud.verify.judge.base import Judge, JudgeVerdict
from linkud.verify.rules import RuleResult, Severity, scan


@dataclass(frozen=True)
class Analysis:
    rules: RuleResult
    judge: JudgeVerdict | None  # 규칙이 치명이면 LLM을 부르지 않는다(None)

    def reasons(self) -> list[str]:
        out = self.rules.reasons()
        if self.judge is None:
            out.append("규칙 필터 치명 패턴: LLM 판별 생략")
        else:
            out += [
                f"LLM {self.judge.label} ({self.judge.confidence:.2f}): {r}"
                for r in self.judge.reasons
            ]
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "rules": {
                "severity": self.rules.severity,
                "matches": [vars(m) for m in self.rules.matches],
            },
            "judge": None
            if self.judge is None
            else {
                "label": self.judge.label,
                "is_write": self.judge.is_write,
                "confidence": self.judge.confidence,
                "reasons": self.judge.reasons,
                **self.judge.details,
            },
        }


async def analyze(definition: dict[str, Any], judge: Judge) -> Analysis:
    rules = scan(definition)
    if rules.severity is Severity.CRITICAL:
        return Analysis(rules, None)
    return Analysis(rules, await judge.judge(definition))
