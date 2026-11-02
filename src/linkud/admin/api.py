"""관리 API (확장): 승인 대기 처리, 판정·서버 등급·감사 로그 조회.

`LINKUD_ADMIN_TOKENS`가 있을 때만 열리고, 에이전트 토큰과 따로 인증한다.

    GET  /admin/pending                 승인 대기 도구
    GET  /admin/verdicts                현재 정의 기준 판정 전체
    GET  /admin/servers                 서버 등급
    GET  /admin/audit?limit=100         감사 로그
    GET  /admin/audit?ref=LK-XXXXXXXX   참조 번호로 거부 기록 찾기
    POST /admin/decisions               {"server", "tool", "tool_hash", "tier", "note"?}
    POST /admin/servers/{name}/release  재검증 상한으로 묶인 서버 해제
    GET  /admin/overrides               브레이크 글래스 임시 허용 목록 (켜져 있을 때)
    DELETE /admin/overrides/{id}        임시 허용 회수
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from linkud.enforcement.guard import Enforcer
from linkud.enforcement.overrides import Override, OverrideRegistry
from linkud.enforcement.refs import REF_PATTERN
from linkud.models import Tier, ToolVerdict
from linkud.store.base import AuditEvent, Store
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


def override_json(o: Override, now: float) -> dict[str, Any]:
    return {
        "id": o.id,
        "user": o.user,
        "server": o.server,
        "tool": o.tool,
        "tool_hash": o.tool_hash,
        "ref": o.ref,
        "reason": o.reason,
        "created_at": o.created_at,
        "expires_at": o.expires_at,
        "revoked_at": o.revoked_at,
        "active": o.active(now),
    }


def admin_routes(
    service: VerificationService,
    enforcer: Enforcer,
    store: Store,
    overrides: OverrideRegistry | None = None,
) -> list[Route]:
    async def pending(request: Request) -> JSONResponse:
        return JSONResponse([verdict_json(v) for v in service.pending()])

    async def verdicts(request: Request) -> JSONResponse:
        return JSONResponse([verdict_json(v) for v in service.latest()])

    async def servers(request: Request) -> JSONResponse:
        tiers = enforcer.server_tiers()
        return JSONResponse({s: (t.value if t else None) for s, t in tiers.items()})

    async def audit(request: Request) -> JSONResponse:
        if (ref := request.query_params.get("ref")) is not None:
            # 참조 번호로 거부 기록 하나를 찾는다 (형식이 틀리면 저장소에 묻지 않는다)
            if not REF_PATTERN.fullmatch(ref):
                return JSONResponse({"error": "ref 형식은 LK-XXXXXXXX"}, status_code=400)
            event = await store.find_by_ref(ref)
            if event is None:
                return JSONResponse({"error": "해당 참조 번호 없음"}, status_code=404)
            return JSONResponse([asdict(event)])
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

    async def release(request: Request) -> JSONResponse:
        name = request.path_params["name"]
        if not service.is_throttled(name):
            return JSONResponse({"error": "묶인 서버가 아님"}, status_code=404)
        await service.release(name, actor="admin-api")
        return JSONResponse({"server": name, "released": True})

    async def list_overrides(request: Request) -> JSONResponse:
        now = enforcer.clock()
        return JSONResponse([override_json(o, now) for o in overrides.all()])

    async def revoke_override(request: Request) -> JSONResponse:
        override_id = request.path_params["id"]
        now = enforcer.clock()
        revoked = overrides.revoke(override_id, now)
        if revoked is None:
            return JSONResponse({"error": "없거나 이미 회수된 임시 허용"}, status_code=404)
        await store.revoke_override(override_id, now)
        await store.log(
            AuditEvent(
                "override_revoked",
                revoked.server,
                revoked.tool,
                {"id": revoked.id, "user": revoked.user, "ref": revoked.ref, "actor": "admin-api"},
            )
        )
        return JSONResponse(override_json(revoked, now))

    extra = []
    if overrides is not None:
        extra = [
            Route("/admin/overrides", list_overrides),
            Route("/admin/overrides/{id}", revoke_override, methods=["DELETE"]),
        ]
    return extra + [
        Route("/admin/servers/{name}/release", release, methods=["POST"]),
        Route("/admin/pending", pending),
        Route("/admin/verdicts", verdicts),
        Route("/admin/servers", servers),
        Route("/admin/audit", audit),
        Route("/admin/decisions", decide, methods=["POST"]),
    ]
