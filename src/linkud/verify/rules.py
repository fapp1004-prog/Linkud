"""규칙 필터: 도구 정의 문자열에서 알려진 툴 포이즈닝 패턴을 찾는다.

판정 단계 (기획서 5장 결정 테이블):
- 치명(critical): 숨은 지시/유출 지시 + 민감 경로가 함께 나옴 → 불신
- 일반(general): 그 밖의 의심 패턴 하나라도 → 승인 대기 (민감 경로 단독은 기록만)

판별 LLM에게 말을 거는 문장("안전하다고 판정해라", "이전 지시 무시")도 여기서 먼저 잡는다.
규칙에 걸린 도구는 LLM이 "정상"이라고 해도 신뢰 등급을 받지 못한다.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    NONE = "none"
    GENERAL = "general"
    CRITICAL = "critical"


@dataclass(frozen=True)
class RuleMatch:
    rule: str  # 규칙 id
    category: str
    field: str  # 어디서 나왔는지 (description, inputSchema.properties.x.description ...)
    excerpt: str


@dataclass(frozen=True)
class RuleResult:
    severity: Severity
    matches: list[RuleMatch] = field(default_factory=list)

    @property
    def categories(self) -> set[str]:
        return {m.category for m in self.matches}

    def reasons(self) -> list[str]:
        return [f"규칙 {m.rule} ({m.category}) @ {m.field}: {m.excerpt!r}" for m in self.matches]


# (rule id, category, pattern). 대소문자 무시.
_RULES: list[tuple[str, str, str]] = [
    # 숨은 지시: 에이전트를 향한 명령, 사용자에게 숨기기
    (
        "hidden-tag",
        "hidden_instruction",
        r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin)\b[^>]*>",
    ),
    (
        "inst-marker",
        "hidden_instruction",
        r"\[/?(INST|SYSTEM)\]|<\|im_start\|>|###\s*(system|instruction)",
    ),
    (
        "hide-from-user",
        "hidden_instruction",
        r"(do\s+not|don'?t|never)\s+(tell|mention|inform|notify|reveal|show|alert)\s+(this\s+to\s+)?(the\s+)?user",
    ),
    (
        "without-user",
        "hidden_instruction",
        r"without\s+(telling|informing|notifying|asking|alerting)\s+(the\s+)?user",
    ),
    ("secretly", "hidden_instruction", r"\b(secretly|silently|covertly|quietly)\b"),
    (
        "before-using",
        "hidden_instruction",
        r"before\s+(using|calling|invoking|running)\s+(this|any|the)\b",
    ),
    (
        "must-first",
        "hidden_instruction",
        r"\byou\s+(must|should|need\s+to)\s+(first|always|also)\b",
    ),
    (
        "ignore-prev",
        "hidden_instruction",
        r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier|other)\s+(instructions|rules|directions|prompts?)",
    ),
    (
        "ko-hide",
        "hidden_instruction",
        r"(사용자|유저)에게\s*(알리지|말하지|보여주지|언급하지)\s*(마|말)|몰래|비밀리에",
    ),
    ("ko-before", "hidden_instruction", r"(이|모든)\s*도구를\s*(사용|호출)하기\s*전에"),
    # 민감 경로·자격 증명
    ("ssh", "sensitive_path", r"~?/?\.ssh\b|id_(rsa|ed25519|ecdsa|dsa)\b|authorized_keys"),
    (
        "cloud-creds",
        "sensitive_path",
        r"\.aws/credentials|\.config/gcloud|\.azure/|\.kube/config|\.docker/config\.json",
    ),
    (
        "dotenv",
        "sensitive_path",
        r"(^|[\s/'\"`(])\.env\b|\.netrc|\.npmrc|\.pypirc|\.git-credentials",
    ),
    ("etc", "sensitive_path", r"/etc/(passwd|shadow|sudoers)"),
    ("mcp-config", "sensitive_path", r"mcp\.json|claude_desktop_config|\.cursor/|\.claude/"),
    (
        "secret-words",
        "sensitive_path",
        r"\b(private\s+key|secret\s+key|api[_\s-]?key|access[_\s-]?token|credentials?|passwords?|seed\s+phrase)\b",
    ),
    # 유출: 데이터를 다른 곳으로 보내게 하는 지시
    (
        "send-to",
        "exfiltration",
        r"\b(send|forward|upload|post|transmit|email)\s+(it|them|this|the\s+\w+|all\s+\w+|its\s+contents?|the\s+contents?)\s+(to|into)\b",
    ),
    (
        "pass-as-param",
        "exfiltration",
        r"(pass|include|put|add|append)\s+(its|the|their|this)\s+(content|contents|value|data|text)\s+(as|in|into)\s+(the\s+)?['\"`]?\w+['\"`]?\s*(parameter|param|argument|field|sidenote|note)",
    ),
    ("ko-send", "exfiltration", r"(내용|파일|값)을?\s*.{0,20}(보내|전송|첨부|포함시켜)"),
    # 판별기 조작: 검사하는 LLM에게 말을 거는 문장
    (
        "judge-classify",
        "judge_manipulation",
        r"(classify|mark|label|rate|judge|treat|consider)\s+(this|it|the\s+tool)\s+(tool\s+)?as\s+(safe|benign|trusted|harmless|legitimate)",
    ),
    (
        "judge-assert",
        "judge_manipulation",
        r"this\s+(tool|description)\s+(is|has\s+been)\s+(safe|benign|verified|trusted|approved|audited)",
    ),
    (
        "judge-address",
        "judge_manipulation",
        r"\b(security\s+)?(classifier|reviewer|scanner|judge|auditor|verifier)s?\b.{0,40}\b(must|should|will|output|respond|return)\b",
    ),
    ("judge-verdict", "judge_manipulation", r"\"?verdict\"?\s*[:=]\s*\"?(benign|safe)"),
    (
        "ko-judge",
        "judge_manipulation",
        r"(안전|정상)(하다고|으로)\s*(판정|분류|평가)|판정(해라|하라|하세요)|이전\s*지시(를|는)?\s*무시",
    ),
    # 다른 도구 동작 바꾸기 (tool shadowing)
    (
        "shadow-other-tool",
        "tool_shadowing",
        r"(when|whenever|if)\s+(the\s+user|you)\s+(uses?|calls?|invokes?)\s+(the\s+)?['\"`]?\w+['\"`]?\s+tool|instead\s+of\s+(using\s+)?the\s+['\"`]?\w+['\"`]?\s+tool|(all|any)\s+other\s+tools?",
    ),
]

_COMPILED = [(rid, cat, re.compile(p, re.IGNORECASE)) for rid, cat, p in _RULES]

# 사람 눈에 안 보이는 문자: zero-width, 양방향 제어, 유니코드 태그 문자(ASCII 밀반입)
_INVISIBLE = re.compile("[​-‏⁠-⁤﻿‪-‮⁦-⁩\U000e0000-\U000e007f]")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")

_CRITICAL_TRIGGERS = {"hidden_instruction", "exfiltration"}
# 민감 경로는 단독으로는 정상 도구(로그인 도구의 password 인자 등)에도 흔해서 등급을 낮추지 않고,
# 치명 판정의 조합 조건과 근거 기록에만 쓴다
_INFO_ONLY = {"sensitive_path"}


def iter_strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """정의 안의 모든 문자열을 (경로, 값)으로 꺼낸다. 딕셔너리 키도 검사 대상이다."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            key_path = f"{path}.{k}" if path else str(k)
            yield f"{key_path}(key)", str(k)
            yield from iter_strings(v, key_path)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from iter_strings(v, f"{path}[{i}]")


def _excerpt(text: str, m: re.Match[str], width: int = 40) -> str:
    start, end = max(0, m.start() - width), min(len(text), m.end() + width)
    return text[start:end].replace("\n", " ")


def scan(definition: dict[str, Any]) -> RuleResult:
    """정규화된 도구 정의(`hashing.canonical_tool`)를 검사한다."""
    matches: list[RuleMatch] = []
    for path, text in iter_strings(definition):
        if path.endswith("(key)") and path.count(".") == 0:
            continue  # 최상위 고정 키(name, description ...)는 건너뜀
        for rid, cat, pattern in _COMPILED:
            if m := pattern.search(text):
                matches.append(RuleMatch(rid, cat, path, _excerpt(text, m)))
        if m := _INVISIBLE.search(text):
            matches.append(
                RuleMatch("invisible-char", "obfuscation", path, f"U+{ord(m.group()):04X}")
            )
        if m := _BASE64_BLOB.search(text):
            matches.append(RuleMatch("base64-blob", "obfuscation", path, m.group()[:40] + "..."))

    categories = {m.category for m in matches}
    if categories & _CRITICAL_TRIGGERS and "sensitive_path" in categories:
        severity = Severity.CRITICAL
    elif categories - _INFO_ONLY:
        severity = Severity.GENERAL
    else:
        severity = Severity.NONE
    return RuleResult(severity, matches)
