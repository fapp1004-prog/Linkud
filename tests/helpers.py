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


class TrustingVerifier:
    """모든 도구를 신뢰로 판정한다 (프록시·캐시 동작만 볼 때)."""

    async def verify(self, req: Any):
        from linkud.models import Tier, ToolVerdict

        return ToolVerdict(req.server, req.tool.name, req.tool_hash, Tier.TRUSTED, False, ["test"])


def pipeline(
    judge: Any = None,
    supply: Any = None,
    no_supply_info: str = "record",
    reapprove_on_change: bool = True,
):
    """FakeJudge 기반 파이프라인 검증기. 기본은 공급망 정보 없음을 기록만 한다."""
    from linkud.verify.decision import NoSupplyInfo, Policy
    from linkud.verify.judge.fake import FakeJudge
    from linkud.verify.pipeline import PipelineVerifier

    policy = Policy(
        no_supply_info=NoSupplyInfo(no_supply_info), reapprove_on_change=reapprove_on_change
    )
    return PipelineVerifier(judge or FakeJudge(), supply, policy)


def make_gateway(downstreams: list[Any], verifier: Any = None, store: Any = None):
    """가짜 다운스트림으로 게이트웨이를 조립한다. (gateway, store)를 돌려준다."""
    from linkud.enforcement.guard import Enforcer
    from linkud.proxy.gateway import Gateway
    from linkud.store.memory import MemoryCache, MemoryStore
    from linkud.verify.service import VerificationService

    cache = MemoryCache()
    store = store if store is not None else MemoryStore()
    service = VerificationService(verifier or TrustingVerifier(), cache, store, timeout=2.0)
    return Gateway(downstreams, Enforcer(service, cache, store)), store
