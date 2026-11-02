"""투명 프록시: 여러 다운스트림의 도구를 모아 하나의 MCP 서버로 노출한다.

에이전트 쪽에서는 MCP 서버, 다운스트림 쪽에서는 MCP 클라이언트로 동작한다.
모든 tools/list와 tools/call은 집행 계층(`Enforcer`)을 지난다.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from typing import Any

import anyio
import httpx
import mcp.types as types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from linkud import __version__
from linkud.admin.api import admin_routes
from linkud.admin.slack import SlackNotifier, slack_routes
from linkud.config import ConfigError, GatewayConfig
from linkud.enforcement.guard import DENY_TEMPLATE, Enforcer
from linkud.proxy import naming
from linkud.proxy.auth import (
    ADMIN_TOKENS_ENV,
    TOKENS_ENV,
    BearerAuth,
    load_identities,
    load_tokens,
    request_user,
)
from linkud.proxy.downstream import Downstream, DownstreamUnavailable, HttpDownstream
from linkud.store.base import Store
from linkud.store.memory import MemoryCache
from linkud.store.retention import purge_once
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


def deny_result(ref: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=DENY_TEMPLATE.format(ref=ref))], is_error=True
    )


class Gateway:
    """다운스트림 묶음. 목록 집계와 호출 라우팅을 맡는다."""

    def __init__(
        self,
        downstreams: Sequence[Downstream],
        enforcer: Enforcer,
        *,
        max_result_bytes: int = 1_000_000,
    ) -> None:
        self.downstreams = {d.name: d for d in downstreams}
        self.enforcer = enforcer
        self.max_result_bytes = max_result_bytes
        # 노출 이름 → 마지막 목록에서 에이전트에게 보여준 inputSchema
        self._schemas: dict[str, dict[str, Any]] = {}

    async def _list_one(self, ds: Downstream, user: str | None = None) -> list[types.Tool]:
        try:
            tools = await ds.list_tools()
            visible = await self.enforcer.visible_tools(ds.name, tools, user)
        except (DownstreamUnavailable, MCPError, TimeoutError) as exc:
            # 목록을 못 받은 서버의 도구는 보여주지 않는다(fail-closed)
            logger.warning("도구 목록 실패: %s (%s)", ds.name, type(exc).__name__)
            return []
        return [t.model_copy(update={"name": naming.qualify(ds.name, t.name)}) for t in visible]

    async def list_tools(self, user: str | None = None) -> list[types.Tool]:
        results: dict[str, list[types.Tool]] = {}

        async def collect(ds: Downstream) -> None:
            results[ds.name] = await self._list_one(ds, user)

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

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None, user: str | None = None
    ) -> types.CallToolResult:
        """정책 거부와 가용성 오류는 원인과 상관없이 같은 문구 + 참조 번호만 돌려준다.

        문구가 원인마다 다르면 에이전트 쪽에서 어느 필터에 걸렸는지 알아내는 오라클이 된다
        (docs/deny-response.md). 원래 이유는 감사 로그(call_denied·call_failed)에만 남긴다.
        """
        parts = naming.split(name)
        if parts is None:
            ref = await self.enforcer.record_denial(
                "*", name, "bad_name", "노출 이름 형식이 틀림", detail={"user": user}
            )
            return deny_result(ref)
        server, tool = parts
        ds = self.downstreams.get(server)
        if ds is None:
            ref = await self.enforcer.record_denial(
                "*", name, "unknown_server", "설정에 없는 서버", detail={"user": user}
            )
            return deny_result(ref)
        decision = await self.enforcer.check_call(ds.name, tool, arguments, user)
        if not decision.allowed:
            return deny_result(decision.ref or "")
        try:
            result = await ds.call_tool(tool, arguments)
        except DownstreamUnavailable:
            return await self._fail(server, tool, "unavailable", "다운스트림 연결 실패", user)
        except MCPError as exc:
            # 다운스트림이 정한 오류 문자열은 에이전트에게 넘기지 않고 감사 로그에만 (길이 제한)
            return await self._fail(
                server,
                tool,
                "downstream_error",
                f"다운스트림 MCP 오류 {exc.code}: {exc.message[:300]}",
                user,
            )
        # 다운스트림 서버 정보 등 메타데이터는 에이전트에게 넘기지 않는다
        result = result.model_copy(update={"meta": None})
        if len(result.model_dump_json(by_alias=True)) > self.max_result_bytes:
            logger.warning("도구 결과 크기 상한 초과: %s", name)
            return await self._fail(server, tool, "too_large", "도구 결과 크기 상한 초과", user)
        return result

    async def _fail(
        self, server: str, tool: str, code: str, reason: str, user: str | None
    ) -> types.CallToolResult:
        ref = await self.enforcer.record_denial(
            server, tool, code, reason, kind="call_failed", detail={"user": user}
        )
        return deny_result(ref)


def build_server(gateway: Gateway, name: str = "linkud-gateway") -> Server[Any]:
    async def on_list_tools(
        ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=await gateway.list_tools(request_user(ctx.request)))

    async def on_call_tool(
        ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        return await gateway.call_tool(params.name, params.arguments, request_user(ctx.request))

    return Server(
        name,
        version=__version__,
        get_tool_input_schema=gateway.input_schema,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


async def retention_loop(store: Store, retention_days: float) -> None:
    """시작 시 정리는 lifespan에서 했으니 한 주기 뒤부터 반복한다."""
    from linkud.store.retention import run_retention

    await anyio.sleep(3600)
    await run_retention(store, retention_days)


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
        reapprove_on_change=config.reapprove_on_change,
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
        reverify_limit=config.reverify_limit,
        reverify_window=config.reverify_window,
    )
    if supply is not None:
        supply.on_update = service.invalidate_server
    enforcer = Enforcer(service, cache, store, inspect_arguments=config.arg_inspection)
    gateway = Gateway(downstreams, enforcer, max_result_bytes=config.max_result_bytes)
    server = build_server(gateway, config.name)

    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    # 관리 API·Slack 승인 (확장): 비밀값이 설정됐을 때만 연다
    routes = [Route("/healthz", healthz)]
    admin_tokens = load_tokens(ADMIN_TOKENS_ENV)
    if admin_tokens:
        routes += admin_routes(service, enforcer, store)
    if webhook := os.environ.get("SLACK_WEBHOOK_URL"):
        service.on_verdict.append(SlackNotifier(webhook, http).notify)
    if signing_secret := os.environ.get("SLACK_SIGNING_SECRET"):
        approvers = set(load_tokens("SLACK_APPROVERS")) or None
        routes += slack_routes(service, http, signing_secret, approvers)
    security = None
    if config.allowed_hosts:
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(config.allowed_hosts),
            allowed_origins=[f"https://{h}" for h in config.allowed_hosts],
        )

    app = server.streamable_http_app(
        streamable_http_path=config.path,
        host=config.host,
        transport_security=security,
        custom_starlette_routes=routes,
    )
    session_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        await service.warm()
        async with anyio.create_task_group() as tg:
            await purge_once(store, config.audit_retention_days)
            tg.start_soon(retention_loop, store, config.audit_retention_days)
            for ds in downstreams:
                if isinstance(ds, HttpDownstream):
                    tg.start_soon(ds.run)
            async with session_lifespan(app):
                yield
            for ds in downstreams:
                if isinstance(ds, HttpDownstream):
                    ds.stop()
            tg.cancel_scope.cancel()  # 보존 정리 루프 등 남은 백그라운드 작업 종료
        await http.aclose()

    app.router.lifespan_context = lifespan
    app.state.gateway = gateway

    tokens = load_identities()
    if not tokens:
        if config.host not in ("127.0.0.1", "localhost", "::1"):
            # 공개 주소에 인증 없이 뜨지 않는다 (fail-closed)
            raise ConfigError(f"{config.host}에 바인딩하려면 {TOKENS_ENV} 접속 토큰이 필요함")
        logger.warning("접속 토큰 없음: 루프백 주소에서만 인증 없이 실행 (%s 미설정)", TOKENS_ENV)
    app.add_middleware(
        BearerAuth,
        routes={config.path: tokens or None, "/admin": admin_tokens},
        exempt=("/healthz", "/slack/actions"),  # Slack은 자체 서명으로 검증
    )
    return app
