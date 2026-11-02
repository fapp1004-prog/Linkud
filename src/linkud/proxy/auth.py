"""게이트웨이 접속 토큰 인증 (Bearer).

경로별로 다른 토큰 묶음을 쓴다: 에이전트(`/mcp`)와 관리자(`/admin`). 에이전트 토큰으로는
관리 API에 접근할 수 없다. 토큰은 환경변수(운영에서는 SSM에서 주입)로 받고 코드·로그에 남기지
않으며, 비교는 상수 시간으로 한다. OAuth는 추후 과제(기획서 7장).
"""

from __future__ import annotations

import hmac
import json
import os
import re
from collections.abc import Iterable, Mapping

from starlette.types import ASGIApp, Receive, Scope, Send

from linkud.config import ConfigError

TOKENS_ENV = "LINKUD_AUTH_TOKENS"
ADMIN_TOKENS_ENV = "LINKUD_ADMIN_TOKENS"


def load_tokens(env: str = TOKENS_ENV) -> list[str]:
    """쉼표로 구분한 토큰 목록. 빈 값은 버린다."""
    return [t.strip() for t in os.environ.get(env, "").split(",") if t.strip()]


# 사용자 이름: 소문자·숫자로 시작, 소문자·숫자·.·_·- 64자까지
_USER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


def parse_identities(raw: str) -> dict[str, str | None]:
    """'이름=토큰' 또는 '토큰'(익명)을 쉼표로 이은 값 → {토큰: 이름 또는 None}.

    형식이 틀리면 ConfigError로 시작을 거부한다(fail-closed). 같은 이름에 토큰 여러 개는 되지만
    같은 토큰을 두 이름에 줄 수는 없다.
    """
    out: dict[str, str | None] = {}
    for entry in (e.strip() for e in raw.split(",")):
        if not entry:
            continue
        name: str | None = None
        token = entry
        if "=" in entry:
            name, _, token = entry.partition("=")
            name, token = name.strip(), token.strip()
            if not _USER_RE.fullmatch(name):
                raise ConfigError("토큰 이름 형식이 틀림 (소문자·숫자·.·_·-, 64자까지)")
        if not token:
            raise ConfigError("빈 토큰")
        if token in out and out[token] != name:
            raise ConfigError("같은 토큰이 여러 이름에 쓰임")
        out[token] = name
    return out


def load_identities(env: str = TOKENS_ENV) -> dict[str, str | None]:
    return parse_identities(os.environ.get(env, ""))


def _match(
    header: bytes | None, identities: list[tuple[bytes, str | None]]
) -> tuple[bool, str | None]:
    """토큰이 맞으면 (True, 사용자 이름). 모든 토큰과 비교해 어느 토큰이 맞았는지 시간으로 드러나지 않게 한다."""
    if not identities or not header or not header.lower().startswith(b"bearer "):
        return False, None
    given = header[7:].strip()
    found: tuple[bool, str | None] = (False, None)
    for token, user in identities:
        if hmac.compare_digest(given, token):
            found = (True, user)
    return found


# 인증 미들웨어가 알아낸 사용자 이름을 담는 ASGI scope state 키 (익명이면 None)
USER_STATE_KEY = "linkud_user"

Identities = Mapping[str, str | None] | Iterable[str]


class BearerAuth:
    """`routes`: 경로 접두사 → {토큰: 사용자 이름} 또는 토큰 목록. 가장 긴 접두사가 이긴다.

    토큰 목록이 None인 접두사는 인증 없이 통과한다(루프백 개발 모드 등).
    `exempt` 경로는 항상 통과한다(헬스체크, 자체 서명·자체 인증을 하는 경로).
    인증에 성공하면 사용자 이름을 scope state의 USER_STATE_KEY에 넣어 게이트웨이로 넘긴다.
    """

    def __init__(
        self,
        app: ASGIApp,
        routes: Mapping[str, Identities | None],
        exempt: Iterable[str] = ("/healthz",),
    ) -> None:
        self.app = app
        self.routes = sorted(
            ((p, None if t is None else _normalize(t)) for p, t in routes.items()),
            key=lambda r: len(r[0]),
            reverse=True,
        )
        self.exempt = set(exempt)

    def _identities_for(self, path: str) -> list[tuple[bytes, str | None]] | None | bool:
        for prefix, identities in self.routes:
            if path.startswith(prefix):
                return identities
        return False  # 어느 규칙에도 없는 경로는 거부

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in self.exempt:
            await self.app(scope, receive, send)
            return
        identities = self._identities_for(scope["path"])
        if identities is None:
            scope.setdefault("state", {})[USER_STATE_KEY] = None
            await self.app(scope, receive, send)
            return
        if identities is not False:
            ok, user = _match(dict(scope["headers"]).get(b"authorization"), identities)
            if ok:
                scope.setdefault("state", {})[USER_STATE_KEY] = user
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


def _normalize(identities: Identities) -> list[tuple[bytes, str | None]]:
    if isinstance(identities, Mapping):
        return [(t.encode(), u) for t, u in identities.items()]
    return [(t.encode(), None) for t in identities]


def request_user(request: object) -> str | None:
    """MCP 처리기의 HTTP 요청에서 인증 미들웨어가 넣은 사용자 이름을 꺼낸다. 없으면 익명(None)."""
    state = getattr(request, "state", None)
    return getattr(state, USER_STATE_KEY, None) if state is not None else None
