"""게이트웨이 접속 토큰 인증 (Bearer).

경로별로 다른 토큰 묶음을 쓴다: 에이전트(`/mcp`)와 관리자(`/admin`). 에이전트 토큰으로는
관리 API에 접근할 수 없다. 토큰은 환경변수(운영에서는 SSM에서 주입)로 받고 코드·로그에 남기지
않으며, 비교는 상수 시간으로 한다. OAuth는 추후 과제(기획서 7장).
"""

from __future__ import annotations

import hmac
import json
import os
from collections.abc import Iterable, Mapping

from starlette.types import ASGIApp, Receive, Scope, Send

TOKENS_ENV = "LINKUD_AUTH_TOKENS"
ADMIN_TOKENS_ENV = "LINKUD_ADMIN_TOKENS"


def load_tokens(env: str = TOKENS_ENV) -> list[str]:
    """쉼표로 구분한 토큰 목록. 빈 값은 버린다."""
    return [t.strip() for t in os.environ.get(env, "").split(",") if t.strip()]


def _matches(header: bytes | None, tokens: list[bytes]) -> bool:
    if not tokens or not header or not header.lower().startswith(b"bearer "):
        return False
    given = header[7:].strip()
    # 모든 토큰과 비교해 어느 토큰이 맞았는지 시간으로 드러나지 않게 한다
    return any([hmac.compare_digest(given, t) for t in tokens])


class BearerAuth:
    """`routes`: 경로 접두사 → 토큰 목록. 가장 긴 접두사가 이긴다.

    토큰 목록이 None인 접두사는 인증 없이 통과한다(루프백 개발 모드 등).
    `exempt` 경로는 항상 통과한다(헬스체크, 자체 서명을 검증하는 Slack 웹훅).
    """

    def __init__(
        self,
        app: ASGIApp,
        routes: Mapping[str, Iterable[str] | None],
        exempt: Iterable[str] = ("/healthz",),
    ) -> None:
        self.app = app
        self.routes = sorted(
            ((p, None if t is None else [x.encode() for x in t]) for p, t in routes.items()),
            key=lambda r: len(r[0]),
            reverse=True,
        )
        self.exempt = set(exempt)

    def _tokens_for(self, path: str) -> list[bytes] | None | bool:
        for prefix, tokens in self.routes:
            if path.startswith(prefix):
                return tokens
        return False  # 어느 규칙에도 없는 경로는 거부

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in self.exempt:
            await self.app(scope, receive, send)
            return
        tokens = self._tokens_for(scope["path"])
        if tokens is None or (
            tokens is not False and _matches(dict(scope["headers"]).get(b"authorization"), tokens)
        ):
            await self.app(scope, receive, send)
            return
        body = json.dumps({"error": "unauthorized"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", b'Bearer realm="linkud"'),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
