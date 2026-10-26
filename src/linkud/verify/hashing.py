"""도구 정의 정규화·해시.

러그풀 감지는 별도 장치 없이 해시 변경으로 한다: 정의가 한 글자라도 바뀌면 해시가
달라지고, 캐시 미스가 나서 검증 경로를 다시 탄다.

해시 대상은 이름·설명·inputSchema·annotations에 더해, 마찬가지로 에이전트 LLM
컨텍스트에 들어가는 title·outputSchema도 포함한다(더 넓게 잡을수록 안전 쪽).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import mcp.types as types


def canonical_tool(tool: types.Tool) -> dict[str, Any]:
    """해시·판별에 쓰는 정규화된 도구 정의."""
    return {
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "outputSchema": tool.output_schema,
        "annotations": tool.annotations.model_dump(mode="json", by_alias=True, exclude_none=True)
        if tool.annotations
        else None,
    }


def tool_hash(tool: types.Tool) -> str:
    data = json.dumps(
        canonical_tool(tool), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
