"""투명 프록시: 여러 다운스트림의 도구를 모아 하나의 MCP 서버로 노출한다.

에이전트 쪽에서는 MCP 서버, 다운스트림 쪽에서는 MCP 클라이언트로 동작한다.
모든 tools/list와 tools/call은 집행 계층(`Enforcer`)을 지난다.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from typing import Any

import anyio
import mcp.types as types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.shared.exceptions import MCPError
from starlette.applications import Starlette

from linkud import __version__
from linkud.config import GatewayConfig
from linkud.enforcement.guard import Enforcer
from linkud.proxy import naming
from linkud.proxy.downstream import Downstream, DownstreamUnavailable, HttpDownstream
from linkud.store.base import Store
from linkud.store.memory import MemoryCache
from linkud.store.sqlite import SqliteStore
from linkud.verify.baseline import BaselineVerifier
from linkud.verify.service import VerificationService, Verifier

logger = logging.getLogger(__name__)


def _error_result(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], is_error=True
    )


class Gateway:
    """다운스트림 묶음. 목록 집계와 호출 라우팅을 맡는다."""

    def __init__(self, downstreams: Sequence[Downstream], enforcer: Enforcer) -> None:
        self.downstreams = {d.name: d for d in downstreams}
        self.enforcer = enforcer

    async def _list_one(self, ds: Downstream) -> list[types.Tool]:
        try:
            tools = await ds.list_tools()
            visible = await self.enforcer.visible_tools(ds.name, tools)
        except (DownstreamUnavailable, MCPError, TimeoutError) as exc:
            # 목록을 못 받은 서버의 도구는 보여주지 않는다(fail-closed)
            logger.warning("도구 목록 실패: %s (%s)", ds.name, type(exc).__name__)
            return []
        return [t.model_copy(update={"name": naming.qualify(ds.name, t.name)}) for t in visible]

    async def list_tools(self) -> list[types.Tool]:
        results: dict[str, list[types.Tool]] = {}

        async def collect(ds: Downstream) -> None:
            results[ds.name] = await self._list_one(ds)

        async with anyio.create_task_group() as tg:
            for ds in self.downstreams.values():
                tg.start_soon(collect, ds)
        # 설정 순서대로 결과를 이어 붙여 응답 순서를 고정한다
        return [t for name in self.downstreams for t in results.get(name, [])]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        parts = naming.split(name)
        ds = self.downstreams.get(parts[0]) if parts else None
        if parts is None or ds is None:
            return _error_result(f"Unknown tool: {name}")
        decision = await self.enforcer.check_call(ds.name, parts[1])
        if not decision.allowed:
            return _error_result(f"Tool not permitted by Linkud gateway: {name}")
        try:
            result = await ds.call_tool(parts[1], arguments)
        except DownstreamUnavailable:
            return _error_result(f"Downstream unavailable for tool: {name}")
        except MCPError as exc:
            return _error_result(f"Downstream error: {exc.message}")
        # 다운스트림 서버 정보 등 메타데이터는 에이전트에게 넘기지 않는다
        return result.model_copy(update={"meta": None})


def build_server(gateway: Gateway, name: str = "linkud-gateway") -> Server[Any]:
    async def on_list_tools(
        ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=await gateway.list_tools())

    async def on_call_tool(
        ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        return await gateway.call_tool(params.name, params.arguments)

    return Server(
        name,
        version=__version__,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def create_app(
    config: GatewayConfig,
    *,
    downstreams: Sequence[Downstream] | None = None,
    verifier: Verifier | None = None,
    store: Store | None = None,
) -> Starlette:
    """게이트웨이 ASGI 앱을 만든다. 인자로 준 구성요소는 설정 대신 쓴다(테스트용)."""
    if downstreams is None:
        downstreams = [
            HttpDownstream(
                d.name,
                d.url,
                connect_timeout=config.connect_timeout,
                call_timeout=config.call_timeout,
            )
            for d in config.downstreams
        ]
    cache = MemoryCache()
    store = store if store is not None else SqliteStore(config.db_path)
    service = VerificationService(
        verifier if verifier is not None else BaselineVerifier(),
        cache,
        store,
        timeout=config.verify_timeout,
    )
    gateway = Gateway(downstreams, Enforcer(service, cache, store))
    server = build_server(gateway, config.name)
    app = server.streamable_http_app(streamable_http_path=config.path, host=config.host)
    session_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        await service.warm()
        async with anyio.create_task_group() as tg:
            for ds in downstreams:
                if isinstance(ds, HttpDownstream):
                    tg.start_soon(ds.run)
            async with session_lifespan(app):
                yield
            for ds in downstreams:
                if isinstance(ds, HttpDownstream):
                    ds.stop()

    app.router.lifespan_context = lifespan
    app.state.gateway = gateway
    return app
