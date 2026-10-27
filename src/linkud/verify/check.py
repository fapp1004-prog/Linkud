"""도구 정의 JSON을 검사해 판정과 근거를 출력하는 CLI.

    uv run python -m linkud.verify.check tool.json            # 규칙 + 가짜 판별기
    uv run python -m linkud.verify.check tool.json --judge claude   # Claude API 판별 (ANTHROPIC_API_KEY 필요)

입력은 MCP Tool 객체 하나 또는 목록(JSON). `inputSchema`/`input_schema` 둘 다 받는다.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

import mcp.types as types

from linkud.verify.analyze import analyze
from linkud.verify.hashing import canonical_tool
from linkud.verify.judge.base import Judge


def make_judge(name: str, model: str | None = None) -> Judge:
    if name == "claude":
        from linkud.verify.judge.anthropic import DEFAULT_MODEL, ClaudeJudge

        return ClaudeJudge(model or DEFAULT_MODEL)
    from linkud.verify.judge.fake import FakeJudge

    return FakeJudge()


def load_tools(raw: Any) -> list[types.Tool]:
    items = raw if isinstance(raw, list) else [raw]
    return [types.Tool.model_validate(item) for item in items]


async def run(tools: list[types.Tool], judge: Judge) -> list[dict[str, Any]]:
    out = []
    for tool in tools:
        result = await analyze(canonical_tool(tool), judge)
        out.append({"tool": tool.name, **result.to_dict(), "reasons": result.reasons()})
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="도구 정의 규칙·LLM 판별")
    parser.add_argument("path")
    parser.add_argument("--judge", choices=["fake", "claude"], default="fake")
    parser.add_argument("--model", default=None)
    args = parser.parse_args()
    with open(args.path, encoding="utf-8") as f:
        tools = load_tools(json.load(f))
    results = asyncio.run(run(tools, make_judge(args.judge, args.model)))
    json.dump(results, sys.stdout, ensure_ascii=False, indent=2, default=str)
    print()


if __name__ == "__main__":
    main()
