"""(A) sanitize.py — 제한 도구를 AI에게 보여줄 사본 만들기. 담당: A. (SPEC 7장, 결정 #30)

제한 도구는 '아직 믿을 수 없는' 도구다. 그 도구의 자연어(설명·제목·예시)가 AI에게 그대로 가면
승인 전이라도 악성 지시가 AI에게 전달된다. 그래서 호출에 필요한 구조만 남기고 나머지는 버린다.

- 원본은 건드리지 않는다. 검사·해시는 원본 기준, 정제는 AI에게 보낼 사본에만 (SPEC 7장 원본 보존).
- 남는 글자(도구 이름, 필드 이름, enum 값 등)도 규칙 검사(B의 checkers.rules.scan)로 한 번 더 본다.
  하나라도 걸리거나 검사를 못 하면 '안전하게 정제할 수 없음' → 목록에서 빼고 호출도 거절한다.
"""

import copy
import importlib
import re
import unicodedata
from typing import Callable

RESTRICTED_DESCRIPTION = "관리자 승인이 필요한 도구입니다."

# 남기는 JSON Schema 키워드 (호출에 필요한 구조·제약). 여기 없는 키는 전부 버린다.
# description·title·examples·$comment·deprecated 같은 설명용 키와 x-로 시작하는 임의 키가 여기서 빠진다.
_SCHEMA_KEYS = {
    "type", "properties", "required", "items", "prefixItems", "additionalProperties", "patternProperties",
    "propertyNames", "enum", "const", "anyOf", "oneOf", "allOf", "not", "if", "then", "else", "$ref", "$defs",
    "definitions", "$schema", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
    "minLength", "maxLength", "pattern", "format", "minItems", "maxItems", "uniqueItems", "contains",
    "minProperties", "maxProperties", "dependentRequired", "default", "nullable",
}
# 값이 '필드 이름 → 스키마' 사전인 키
_NAMED_SCHEMAS = {"properties", "patternProperties", "$defs", "definitions"}
# 값이 스키마 하나인 키 / 스키마 목록인 키
_ONE_SCHEMA = {"items", "additionalProperties", "propertyNames", "not", "if", "then", "else", "contains"}
_SCHEMA_LIST = {"prefixItems", "anyOf", "oneOf", "allOf"}

NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")   # 도구·필드 이름. 문장을 이름에 숨기지 못하게
MAX_VALUE_LEN = 64                                  # enum·const 문자열 길이
MAX_PATTERN_LEN = 128                               # pattern 정규식 길이

Scan = Callable[[str], list]


class Unsafe(Exception):
    """정제해도 안전하게 보여줄 수 없음."""


def _clean_schema(node, strings: list[str], depth: int = 0):
    if depth > 32:
        raise Unsafe("스키마가 너무 깊음")
    if isinstance(node, bool):  # JSON Schema는 true/false도 스키마
        return node
    if not isinstance(node, dict):
        raise Unsafe(f"스키마 자리에 {type(node).__name__}")
    out = {}
    for k, v in node.items():
        if k not in _SCHEMA_KEYS:
            continue
        if k in _NAMED_SCHEMAS:
            if not isinstance(v, dict):
                raise Unsafe(f"{k}가 객체가 아님")
            sub = {}
            for name, s in v.items():
                if k == "properties" and not NAME_RE.match(str(name)):
                    raise Unsafe(f"필드 이름 형식 위반: {name!r}")
                strings.append(str(name))
                sub[name] = _clean_schema(s, strings, depth + 1)
            out[k] = sub
        elif k in _ONE_SCHEMA:
            out[k] = _clean_schema(v, strings, depth + 1)
        elif k in _SCHEMA_LIST:
            if not isinstance(v, list):
                raise Unsafe(f"{k}가 목록이 아님")
            out[k] = [_clean_schema(s, strings, depth + 1) for s in v]
        elif k in ("enum", "const"):
            vals = v if k == "enum" else [v]
            if k == "enum" and not isinstance(v, list):
                raise Unsafe("enum이 목록이 아님")
            for x in vals:
                if isinstance(x, (dict, list)):
                    raise Unsafe(f"{k}에 객체·목록 값")
                if isinstance(x, str):
                    if len(x) > MAX_VALUE_LEN:
                        raise Unsafe(f"{k} 문자열이 너무 김")
                    strings.append(x)
            out[k] = copy.deepcopy(v)
        elif k == "default":
            if isinstance(v, (str, dict, list)):  # 문자열·구조 기본값은 글을 숨길 수 있어서 버린다
                continue
            out[k] = v
        elif k == "required":
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise Unsafe("required가 문자열 목록이 아님")
            strings.extend(v)
            out[k] = list(v)
        elif k == "pattern":
            if not isinstance(v, str) or len(v) > MAX_PATTERN_LEN:
                raise Unsafe("pattern이 문자열이 아니거나 너무 김")
            strings.append(v)
            out[k] = v
        elif k in ("type", "format", "$ref", "$schema"):
            if isinstance(v, list):
                if not all(isinstance(x, str) for x in v):
                    raise Unsafe(f"{k} 값 형식 위반")
                strings.extend(v)
            elif isinstance(v, str):
                if len(v) > MAX_PATTERN_LEN:
                    raise Unsafe(f"{k} 값이 너무 김")
                strings.append(v)
            else:
                raise Unsafe(f"{k} 값 형식 위반")
            out[k] = copy.deepcopy(v)
        elif k == "dependentRequired":
            if not isinstance(v, dict):
                raise Unsafe("dependentRequired가 객체가 아님")
            for name, lst in v.items():
                if not isinstance(lst, list) or not all(isinstance(x, str) for x in lst):
                    raise Unsafe("dependentRequired 값 형식 위반")
                strings.append(str(name))
                strings.extend(lst)
            out[k] = copy.deepcopy(v)
        else:  # 숫자·불리언 제약 (minimum, maxLength, uniqueItems, nullable …)
            if isinstance(v, bool) or isinstance(v, (int, float)):
                out[k] = v
            else:
                raise Unsafe(f"{k} 값이 숫자·불리언이 아님")
    return out


def _has_invisible(s: str) -> bool:
    """눈에 안 보이는 문자(제로폭·방향 제어 등, 유니코드 Cf·Co·Cn)와 제어문자. B 규칙과 별개로 A가 직접 막는다."""
    return any(unicodedata.category(ch) in ("Cf", "Co", "Cn", "Cc") for ch in s)


def sanitize_tool(tool: dict, scan: Scan | None) -> dict:
    """제한 도구의 정제 사본을 돌려준다. 안전하게 못 만들면 Unsafe를 던진다.

    scan: 문자열 하나를 받아 걸린 신호 이름 목록을 돌려주는 규칙 검사 함수. None이면 검사할 수 없음 → Unsafe.
    """
    if scan is None:
        raise Unsafe("규칙 검사(checkers.rules.scan)를 쓸 수 없어 남는 글자를 확인 못 함")
    name = tool.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise Unsafe("도구 이름 형식 위반")
    strings = [name]
    out = {"name": name, "description": RESTRICTED_DESCRIPTION}
    for key in ("inputSchema", "outputSchema"):
        if key in tool:
            out[key] = _clean_schema(tool[key], strings)
    if "inputSchema" not in out:
        out["inputSchema"] = {"type": "object"}
    # title(최상위), annotations는 남기지 않는다

    for s in strings:
        if _has_invisible(s):
            raise Unsafe("보이지 않는 문자")
        try:
            hits = scan(s)
        except Exception as e:  # 규칙 검사가 실패해도 fail-closed
            raise Unsafe(f"규칙 검사 실패: {type(e).__name__}") from e
        if hits:
            raise Unsafe(f"남는 글자에서 규칙 신호: {', '.join(map(str, hits))}")
    return out


def load_scan(mode: str) -> Scan | None:
    """B의 규칙 검사 함수를 불러온다. 실제 모드에서 없으면 None(→ 제한 도구는 전부 비노출).
    개발 모드에서는 B가 아직 없을 때 개발용 가짜 규칙을 쓴다."""
    try:
        fn = getattr(importlib.import_module("checkers.rules"), "scan", None)
        if callable(fn):
            return fn
    except Exception:
        pass
    if mode == "dev":
        from gateway import devcheckers
        return devcheckers.scan
    return None
