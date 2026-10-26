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
import httpx
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
from linkud.verify.decision import NoSupplyInfo, Policy
from linkud.verify.judge.base import Judge
from linkud.verify.pipeline import PipelineVerifier, SupplyChecker
from linkud.verify.service import VerificationService, Verifier
from linkud.verify.supply.checker import RegistrySupplyChecker, SupplyTarget
from linkud.verify.supply.osv import OsvClient
from linkud.verify.supply.registry import RegistryClient
from linkud.verify.supply.sbom import SyftSbom

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
        # 노출 이름 → 마지막 목록에서 에이전트에게 보여준 inputSchema
        self._schemas: dict[str, dict[str, Any]] = {}

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
        tools = [t for name in self.downstreams for t in results.get(name, [])]
        self._schemas = {t.name: t.input_schema for t in tools}
        return tools

    def input_schema(self, name: str) -> dict[str, Any] | None:
        """SDK의 tools/call 헤더 검증용 스키마 조회.

        이 콜백이 없으면 SDK가 호출마다 tools/list 처리기를 다시 돌려 스키마를 찾는다.
        그러면 호출 경로에서 검증 경로(LLM 판별)가 돌 수 있으므로, 마지막 목록 결과만 돌려준다.
        """
        return self._schemas.get(name)

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
        get_tool_input_schema=gateway.input_schema,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def make_judge(config: GatewayConfig) -> Judge:
    if config.judge == "fake":
        from linkud.verify.judge.fake import FakeJudge

        logger.warning("FakeJudge 사용 중: 개발·테스트 전용 (LLM 판별 없음)")
        return FakeJudge()
    from linkud.verify.judge.anthropic import ClaudeJudge

    return ClaudeJudge(config.judge_model, timeout=config.judge_timeout)


def make_verifier(config: GatewayConfig, supply: SupplyChecker | None = None) -> Verifier:
    policy = Policy(
        high_confidence=config.high_confidence,
        no_supply_info=NoSupplyInfo(config.no_supply_info),
    )
    return PipelineVerifier(make_judge(config), supply, policy)


def make_supply_checker(config: GatewayConfig, http: httpx.AsyncClient) -> RegistrySupplyChecker:
    targets = {d.name: SupplyTarget(d.registry, d.url) for d in config.downstreams}
    return RegistrySupplyChecker(
        targets,
        RegistryClient(http, config.registry_url),
        OsvClient(http, config.osv_url),
        http,
        SyftSbom(config.syft_path),
        timeout=config.supply_timeout,
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
    http = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
    supply = None
    if verifier is None and config.supply_enabled:
        supply = make_supply_checker(config, http)
    service = VerificationService(
        verifier if verifier is not None else make_verifier(config, supply),
        cache,
        store,
        timeout=config.verify_timeout,
    )
    if supply is not None:
        supply.on_update = service.invalidate_server
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
        await http.aclose()

    app.router.lifespan_context = lifespan
    app.state.gateway = gateway
    return app
