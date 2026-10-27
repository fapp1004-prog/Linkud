"""annotations 불일치 (기획서 6장 5단계).

"읽기 전용"이라고 자기 신고했는데 이름·설명이 쓰기·삭제를 말하면 의심 신호로 남긴다.
"""

from __future__ import annotations

import re
from typing import Any

from linkud.verify.decision import name_says_write

# commit·push처럼 명사로도 흔히 쓰이는 단어("staged for commit")는 오탐이 많아 넣지 않는다
_WRITE_VERBS = re.compile(
    r"\b(deletes?|removes?|overwrites?|creates?|sends?|writes?|updates?|modif(?:y|ies)|uploads?|"
    r"executes?|runs?\s+(?:a\s+)?(?:command|script|shell)|drops?|kills?|purges?|erases?|wipes?|"
    r"transfers?|publish(?:es)?)\b",
    re.IGNORECASE,
)


def annotation_mismatch(definition: dict[str, Any]) -> list[str]:
    annotations = definition.get("annotations") or {}
    if annotations.get("readOnlyHint") is not True:
        return []
    out = []
    name = definition.get("name") or ""
    if name_says_write(name):
        out.append(f"readOnlyHint=true인데 이름이 쓰기 동작: {name!r}")
    if m := _WRITE_VERBS.search(definition.get("description") or ""):
        out.append(f"readOnlyHint=true인데 설명이 쓰기 동작: {m.group()!r}")
    if annotations.get("destructiveHint") is True:
        out.append("readOnlyHint=true와 destructiveHint=true가 함께 있음")
    return out
