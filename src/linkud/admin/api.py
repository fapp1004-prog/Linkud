"""관리 API (확장): 승인 대기 처리, 판정·서버 등급·감사 로그 조회.

`LINKUD_ADMIN_TOKENS`가 있을 때만 열리고, 에이전트 토큰과 따로 인증한다.

    GET  /admin/pending                 승인 대기 도구
    GET  /admin/verdicts                현재 정의 기준 판정 전체
    GET  /admin/servers                 서버 등급
    GET  /admin/audit?limit=100         감사 로그
    POST /admin/decisions               {"server", "tool", "tool_hash", "tier", "note"?}
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from linkud.enforcement.guard import Enforcer
from linkud.models import Tier, ToolVerdict
from linkud.store.base import Store
from linkud.verify.service import VerificationService

# 사람이 고를 수 있는 등급 (승인 대기는 확정이 아님)
DECIDABLE = {Tier.TRUSTED, Tier.PARTIAL, Tier.UNTRUSTED}


def verdict_json(v: ToolVerdict) -> dict[str, Any]:
    return {
        "server": v.server,
        "tool": v.tool,
        "tool_hash": v.tool_hash,
        "tier": v.tier.value,
        "tier_label": v.tier.label,
        "is_read": v.is_read,
        "reasons": v.reasons,
        "created_at": v.created_at,
    }


def admin_routes(service: VerificationService, enforcer: Enforcer, store: Store) -> list[Route]:
    async def pending(request: Request) -> JSONResponse:
        return JSONResponse([verdict_json(v) for v in service.pending()])

    async def verdicts(request: Request) -> JSONResponse:
        return JSONResponse([verdict_json(v) for v in service.latest()])

    async def servers(request: Request) -> JSONResponse:
        tiers = enforcer.server_tiers()
        return JSONResponse({s: (t.value if t else None) for s, t in tiers.items()})

    async def audit(request: Request) -> JSONResponse:
        try:
            limit = max(1, min(1000, int(request.query_params.get("limit", "100"))))
        except ValueError:
            return JSONResponse({"error": "limit은 정수"}, status_code=400)
        return JSONResponse([asdict(e) for e in await store.audit_log(limit)])

    async def decide(request: Request) -> JSONResponse:
        try:
            body = await request.json()
            tier = Tier(body["tier"])
            server, tool, tool_hash = str(body["server"]), str(body["tool"]), str(body["tool_hash"])
        except (ValueError, KeyError, TypeError):
            return JSONResponse(
                {"error": "server, tool, tool_hash, tier가 필요함"}, status_code=400
            )
        if tier not in DECIDABLE:
            return JSONResponse(
                {"error": "tier는 trusted, partial, untrusted 중 하나"}, status_code=400
            )
        try:
            verdict = await service.apply_decision(
                server,
                tool,
                tool_hash,
                tier,
                actor="admin-api",
                note=str(body.get("note", ""))[:500],
            )
        except LookupError as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        return JSONResponse(verdict_json(verdict))

    return [
        Route("/admin/pending", pending),
        Route("/admin/verdicts", verdicts),
        Route("/admin/servers", servers),
        Route("/admin/audit", audit),
        Route("/admin/decisions", decide, methods=["POST"]),
    ]
