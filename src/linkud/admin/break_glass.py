"""브레이크 글래스: 사람이 자기 거부(승인 대기)를 잠시 직접 허용하는 경로 (docs/break-glass.md).

MCP 도구로 노출하지 않는다. /override는 사람 전용 토큰(LINKUD_OVERRIDE_TOKENS, 이름=토큰)으로만
받는다. 에이전트가 쓰는 MCP 토큰은 에이전트 환경에 있어 포이즈닝된 에이전트가 직접 부를 수 있으므로
여기서는 받지 않는다. 허용하지 않을 때는 이유와 상관없이 같은 문구 하나만 돌려준다.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Awaitable, Callable, Mapping

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from linkud.config import GatewayConfig
from linkud.enforcement.guard import Enforcer
from linkud.enforcement.overrides import Override, OverrideRegistry
from linkud.enforcement.refs import REF_PATTERN
from linkud.proxy import naming
from linkud.proxy.auth import match_identity
from linkud.store.base import AuditEvent, Store

DENY_MESSAGE = "이 참조 번호로는 임시 허용할 수 없습니다."
# 인증 미들웨어를 거치지 않는 경로 (처리기가 직접 인증하거나 비밀이 없는 정적 파일)
OVERRIDE_PATHS = ("/override",)
REASON_MIN, REASON_MAX = 10, 500
REF_MAX_AGE = 86400  # 24시간보다 오래된 거부 기록으로는 허용하지 않는다
DAY = 86400


def _deny() -> JSONResponse:
    return JSONResponse({"error": DENY_MESSAGE}, status_code=403)


def break_glass_routes(
    config: GatewayConfig,
    enforcer: Enforcer,
    registry: OverrideRegistry,
    store: Store,
    override_identities: Mapping[str, str | None],
    known_servers: set[str],
    notify: Callable[[Override], Awaitable[None]] | None = None,
) -> list[Route]:
    identities = [(t.encode(), u) for t, u in override_identities.items()]
    lock = anyio.Lock()  # 같은 ref로 동시에 두 번 허용되지 않게

    async def grant(request: Request) -> JSONResponse:
        ok, user = match_identity(request.headers.get("authorization", "").encode(), identities)
        if not ok or user is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            body = await request.json()
        except ValueError:
            body = None
        if not isinstance(body, dict):
            return JSONResponse({"error": "JSON 본문이 필요합니다."}, status_code=400)
        ref, reason = body.get("ref"), body.get("reason")
        if not isinstance(reason, str) or not REASON_MIN <= len(reason.strip()) <= REASON_MAX:
            return JSONResponse(
                {"error": f"사유를 {REASON_MIN}~{REASON_MAX}자로 적어 주세요."}, status_code=400
            )
        reason = reason.strip()
        now = enforcer.clock()
        # 횟수 제한은 도구가 아니라 요청한 사람에 대한 정보라 따로 알린다
        if registry.count_recent(user, now - DAY) >= config.break_glass_daily_limit:
            return JSONResponse({"error": "오늘 임시 허용 횟수를 모두 썼습니다."}, status_code=429)
        if not isinstance(ref, str) or not REF_PATTERN.fullmatch(ref):
            return _deny()

        async with lock:
            event = await store.find_by_ref(ref)
            if event is None or event.kind != "call_denied":
                return _deny()
            d = event.detail
            if (
                d.get("user") != user  # 본인 거부만
                or now - event.ts > REF_MAX_AGE
                or registry.used_ref(ref)  # 한 번만
                or d.get("code") != "tier"  # 원인이 등급 거부이고
                or d.get("tier") != "pending"  # 그때 서버가 승인 대기였을 것
                or not d.get("hash")
                or event.server not in known_servers
            ):
                return _deny()
            # 지금도 같은 정의·같은 상태인지 (캐시만 조회)
            if await enforcer.override_target(event.server, event.tool) != d["hash"]:
                return _deny()
            override = Override(
                id=secrets.token_hex(8),
                user=user,
                server=event.server,
                tool=event.tool,
                tool_hash=d["hash"],
                ref=ref,
                reason=reason,
                created_at=now,
                expires_at=now + config.break_glass_ttl_hours * 3600,
            )
            await store.save_override(override)
            registry.add(override)
        await store.log(
            AuditEvent(
                "override_granted",
                override.server,
                override.tool,
                {
                    "id": override.id,
                    "user": user,
                    "reason": reason,
                    "expires_at": override.expires_at,
                    "ref": ref,
                    "hash": override.tool_hash,
                },
            )
        )
        if notify is not None:
            await notify(override)
        return JSONResponse(
            {
                "granted": True,
                "tool": naming.qualify(override.server, override.tool),
                "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(override.expires_at)),
            }
        )

    return [Route("/override", grant, methods=["POST"])]
