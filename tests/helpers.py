"""테스트 공용 도우미: ASGI 앱을 임의 포트에 띄우기, 가짜 다운스트림."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import mcp.types as types
import uvicorn


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@asynccontextmanager
async def serve(app: Any) -> AsyncIterator[str]:
    """앱을 백그라운드로 띄우고 기본 URL(`http://127.0.0.1:<port>`)을 돌려준다."""
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            if task.done():
                task.result()
            await asyncio.sleep(0.02)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


def tool(name: str, description: str = "", **kwargs: Any) -> types.Tool:
    return types.Tool(
        name=name,
        description=description,
        input_schema=kwargs.pop("input_schema", {"type": "object", "properties": {}}),
        **kwargs,
    )


class FakeDownstream:
    """도구 정의를 데이터로 주입하는 다운스트림. 서버를 띄우지 않는다."""

    def __init__(self, name: str, tools: list[types.Tool], *, fail: bool = False) -> None:
        self.name = name
        self.tools = tools
        self.fail = fail
        self.calls: list[tuple[str, dict[str, Any] | None]] = []
        self.list_count = 0

    async def list_tools(self) -> list[types.Tool]:
        from linkud.proxy.downstream import DownstreamUnavailable

        self.list_count += 1
        if self.fail:
            raise DownstreamUnavailable(self.name)
        return list(self.tools)

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        self.calls.append((name, arguments))
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"{name} ok")])
