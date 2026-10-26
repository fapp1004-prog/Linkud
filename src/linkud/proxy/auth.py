"""게이트웨이 접속 토큰 인증 (Bearer).

토큰은 환경변수(운영에서는 SSM Parameter Store에서 주입)로 받고 코드·로그에 남기지 않는다.
비교는 상수 시간으로 한다. OAuth는 추후 과제(기획서 7장).
"""

from __future__ import annotations

import hmac
import json
import os
from collections.abc import Iterable

from starlette.types import ASGIApp, Receive, Scope, Send

TOKENS_ENV = "LINKUD_AUTH_TOKENS"


def load_tokens(env: str = TOKENS_ENV) -> list[str]:
    """쉼표로 구분한 토큰 목록. 빈 값은 버린다."""
    return [t.strip() for t in os.environ.get(env, "").split(",") if t.strip()]


class BearerAuth:
    def __init__(self, app: ASGIApp, tokens: Iterable[str], exempt: Iterable[str] = ("/healthz",)):
        self.app = app
        self.tokens = [t.encode() for t in tokens]
        self.exempt = set(exempt)

    def _ok(self, header: bytes | None) -> bool:
        if not header or not header.lower().startswith(b"bearer "):
            return False
        given = header[7:].strip()
        # 모든 토큰과 비교해 어느 토큰이 맞았는지 시간으로 드러나지 않게 한다
        return any([hmac.compare_digest(given, t) for t in self.tokens])

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in self.exempt:
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        if self._ok(headers.get(b"authorization")):
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
