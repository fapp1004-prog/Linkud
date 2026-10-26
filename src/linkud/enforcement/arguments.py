"""인자 검사 (확장): 허용된 도구라도 위험한 값으로 부르면 막는다.

런타임 경로라 정규식만 쓴다(LLM·네트워크 없음). 인자 값(중첩 포함)만 보고 키 이름은 보지 않는다.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (name, re.compile(p, re.IGNORECASE))
    for name, p in [
        ("ssh 키", r"(^|[\s/'\"=~])\.ssh(/|$)|\bid_(rsa|ed25519|ecdsa|dsa)\b|authorized_keys"),
        (
            "클라우드 자격 증명",
            r"\.aws/(credentials|config)|\.config/gcloud|\.azure/|\.kube/config|\.docker/config\.json",
        ),
        (
            "비밀 파일",
            r"(^|[\s/'\"=])\.env(\.\w+)?$|\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials\b",
        ),
        ("시스템 계정 파일", r"/etc/(shadow|sudoers|passwd)\b"),
        ("에이전트 설정", r"mcp\.json|claude_desktop_config|\.cursor/|\.claude/"),
        ("개인키 내용", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        ("경로 탈출", r"(^|[/\\])\.\.([/\\]\.\.){2,}"),  # ../../.. 이상
    ]
]


def _values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _values(v)
    elif isinstance(value, list):
        for v in value:
            yield from _values(v)


def dangerous_arguments(arguments: dict[str, Any] | None) -> list[str]:
    """걸린 이유 목록. 비어 있으면 통과. 값 자체는 로그에 남기지 않도록 이유만 돌려준다."""
    found: list[str] = []
    for text in _values(arguments or {}):
        for name, pattern in _PATTERNS:
            if name not in found and pattern.search(text):
                found.append(name)
    return found
