"""결정 테이블 → 등급, 읽기 도구 판별, 서버 등급 (기획서 5장).

점수 합산이 아니라 위에서부터 차례로 검사해 처음 맞는 줄의 등급을 준다.

| 순서 | 조건 (도구 단위)                                                         | 판정     |
| 1    | LLM 악성 고확신 / 규칙 치명 패턴 / OSV 악성 패키지(MAL-)                    | 불신     |
| 2    | LLM 의심(또는 저확신 악성) / 규칙 일반 패턴 / annotations 불일치            | 승인 대기 |
| 3    | Critical·High CVE / 공급망 정보 없음(정책에 따라)                          | 부분신뢰 |
| 4    | 해당 없음                                                                 | 신뢰     |
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from linkud.models import Tier, ToolVerdict
from linkud.verify.analyze import Analysis
from linkud.verify.judge.base import JudgeLabel
from linkud.verify.rules import Severity


class NoSupplyInfo(StrEnum):
    """공급망 정보가 없을 때의 처리 (기획서 미결 사항 → 기본값 부분신뢰)."""

    PARTIAL = "partial"  # 부분신뢰(읽기만)
    RECORD = "record"  # 불이익 없이 근거만 기록


@dataclass(frozen=True)
class SupplySignals:
    """공급망 검증 결과 중 결정 테이블이 쓰는 신호 (서버 단위)."""

    available: bool = False  # Registry에서 패키지를 찾아 조회까지 했는가
    malicious_package: bool = False  # OSV MAL- 기록
    severe_vulnerability: bool = False  # Critical·High CVE
    reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Policy:
    high_confidence: float = 0.8  # 이 이상이면 LLM "악성"을 고확신으로 본다
    no_supply_info: NoSupplyInfo = NoSupplyInfo.PARTIAL


@dataclass(frozen=True)
class Decision:
    tier: Tier
    row: int  # 몇 번째 줄에서 결정됐는가
    reasons: list[str]


def decide(
    analysis: Analysis,
    supply: SupplySignals,
    *,
    annotation_mismatch: list[str] | None = None,
    policy: Policy | None = None,
) -> Decision:
    policy = policy or Policy()
    judge = analysis.judge
    evidence = analysis.reasons() + supply.reasons + (annotation_mismatch or [])

    row1 = []
    if judge is not None and judge.label is JudgeLabel.MALICIOUS:
        if judge.confidence >= policy.high_confidence:
            row1.append(f"LLM 악성 고확신 ({judge.confidence:.2f})")
    if analysis.rules.severity is Severity.CRITICAL:
        row1.append("규칙 필터 치명 패턴")
    if supply.malicious_package:
        row1.append("OSV 악성 패키지 기록")
    if row1:
        return Decision(Tier.UNTRUSTED, 1, row1 + evidence)

    row2 = []
    if judge is not None and judge.label is JudgeLabel.SUSPICIOUS:
        row2.append("LLM 의심")
    if judge is not None and judge.label is JudgeLabel.MALICIOUS:
        row2.append(f"LLM 악성 저확신 ({judge.confidence:.2f})")
    if analysis.rules.severity is Severity.GENERAL:
        row2.append("규칙 필터 일반 패턴")
    if annotation_mismatch:
        row2.append("annotations 불일치")
    if row2:
        return Decision(Tier.PENDING, 2, row2 + evidence)

    row3 = []
    if supply.severe_vulnerability:
        row3.append("Critical·High CVE")
    if not supply.available and policy.no_supply_info is NoSupplyInfo.PARTIAL:
        row3.append("공급망 정보 없음")
    if row3:
        return Decision(Tier.PARTIAL, 3, row3 + evidence)

    if not supply.available:
        evidence = evidence + ["공급망 정보 없음 (기록만)"]
    return Decision(Tier.TRUSTED, 4, ["결정 테이블 해당 없음"] + evidence)


# --- 읽기 도구 판별 -------------------------------------------------------------

_READ_PREFIXES = (
    "get", "list", "read", "search", "find", "fetch", "query", "describe", "show",
    "view", "lookup", "count", "check", "inspect", "browse", "retrieve",
)  # fmt: skip
_WRITE_WORDS = {
    "create", "delete", "write", "update", "set", "remove", "send", "post", "put", "patch",
    "insert", "exec", "execute", "run", "kill", "move", "rename", "upload", "modify", "edit",
    "add", "drop", "push", "merge", "commit", "deploy", "install", "approve", "pay", "transfer",
    "publish", "save", "store", "clear", "reset", "restart", "stop", "start", "invoke", "call",
}  # fmt: skip


def name_words(name: str) -> list[str]:
    """getUserInfo / get-user_info → ['get', 'user', 'info']"""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if w]


def name_says_read(name: str) -> bool:
    words = name_words(name)
    return bool(words) and words[0] in _READ_PREFIXES and not (set(words) & _WRITE_WORDS)


def name_says_write(name: str) -> bool:
    return bool(set(name_words(name)) & _WRITE_WORDS)


def is_read_tool(definition: dict[str, Any], analysis: Analysis) -> tuple[bool, list[str]]:
    """세 신호(readOnlyHint, 이름 패턴, LLM)가 모두 '읽기'일 때만 읽기. 하나라도 애매하면 쓰기."""
    annotations = definition.get("annotations") or {}
    signals = {
        "readOnlyHint": annotations.get("readOnlyHint") is True,
        "이름 패턴": name_says_read(definition.get("name", "")),
        "LLM": analysis.judge is not None and analysis.judge.is_write is False,
    }
    is_read = all(signals.values())
    detail = ", ".join(f"{k}={'읽기' if v else '쓰기/불명'}" for k, v in signals.items())
    return is_read, [f"읽기 판별 {'읽기' if is_read else '쓰기'}: {detail}"]


# --- 서버 등급 -----------------------------------------------------------------


def server_tier(verdicts: Iterable[ToolVerdict | None]) -> Tier | None:
    """가장 위험한 도구 기준. 판정이 없는 도구(검증 실패)가 하나라도 있으면 승인 대기로 본다.

    도구가 하나도 없으면 None.
    """
    tiers = [v.tier if v is not None else Tier.PENDING for v in verdicts]
    if not tiers:
        return None
    return max(tiers, key=lambda t: t.risk)


def permits(tier: Tier | None, verdict: ToolVerdict | None) -> bool:
    """서버 등급에 따른 도구 단위 권한 (기획서 5장 표)."""
    if tier is None or verdict is None:
        return False
    if tier is Tier.TRUSTED:
        return True
    if tier is Tier.PARTIAL:
        return verdict.is_read
    return False  # 불신·승인 대기: 숨김·거부
