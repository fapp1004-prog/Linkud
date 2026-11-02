"""Slack 승인 (확장): 승인 대기 도구를 알리고, 버튼으로 등급을 확정한다.

- 알림: Slack 앱의 Incoming Webhook(`SLACK_WEBHOOK_URL`)으로 버튼 달린 메시지를 보낸다.
- 버튼: Slack 앱 Interactivity의 Request URL을 `https://<도메인>/slack/actions`로 둔다.
  요청은 서명 비밀값(`SLACK_SIGNING_SECRET`)으로 검증하고, `SLACK_APPROVERS`(사용자 ID,
  쉼표 구분)가 있으면 그 사람만 승인할 수 있다.

알림 본문에는 판정 근거(오염 설명 일부 포함)가 들어가므로 Slack 서식으로 해석되지 않게 이스케이프한다.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from linkud.enforcement.overrides import Override
from linkud.models import Tier, ToolVerdict
from linkud.proxy import naming
from linkud.verify.service import VerificationService

logger = logging.getLogger(__name__)

_BUTTONS = [(Tier.TRUSTED, "primary"), (Tier.PARTIAL, None), (Tier.UNTRUSTED, "danger")]
_MAX_SKEW = 300  # 서명 타임스탬프 허용 오차(초), 재전송 공격 방지


def escape(text: str) -> str:
    """Slack mrkdwn 제어 문자(&, <, >)를 이스케이프해 링크·멘션으로 해석되지 않게 한다."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_message(v: ToolVerdict) -> dict[str, Any]:
    reasons = "\n".join(f"• {escape(r[:200])}" for r in v.reasons[:6])
    buttons = [
        {
            "type": "button",
            "text": {"type": "plain_text", "text": tier.label},
            "action_id": f"linkud_{tier.value}",
            "value": json.dumps(
                {"server": v.server, "tool": v.tool, "hash": v.tool_hash, "tier": tier.value}
            ),
            **({"style": style} if style else {}),
        }
        for tier, style in _BUTTONS
    ]
    title = f"Linkud 승인 대기: {v.server} / {v.tool}"
    return {
        "text": title,
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": title[:150]}},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*해시* `{v.tool_hash[:16]}`\n{reasons}"[:2900],
                },
            },
            {"type": "actions", "elements": buttons},
        ],
    }


def build_override_message(o: Override) -> dict[str, Any]:
    """브레이크 글래스 임시 허용 알림. 사유는 사용자가 쓴 텍스트라 mrkdwn으로 해석되지 않게 이스케이프한다."""
    expires = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(o.expires_at))
    title = f"Linkud 임시 허용: {o.user} → {naming.qualify(o.server, o.tool)}"
    body = (
        f"*사용자* {escape(o.user)}\n*도구* `{escape(naming.qualify(o.server, o.tool))}`\n"
        f"*만료* {expires}\n*참조 번호* {escape(o.ref)}\n*사유* {escape(o.reason[:500])}\n"
        f"*id* `{escape(o.id)}` (회수: DELETE /admin/overrides/{escape(o.id)})"
    )
    return {
        "text": escape(title),
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": title[:150]}},
            {"type": "section", "text": {"type": "mrkdwn", "text": body[:2900]}},
        ],
    }


class SlackNotifier:
    def __init__(self, webhook_url: str, http: httpx.AsyncClient) -> None:
        self.webhook_url = webhook_url
        self.http = http
        self._tasks: set[asyncio.Task[None]] = set()

    async def notify(self, verdict: ToolVerdict) -> None:
        """승인 대기 판정만 알린다. 검증 경로를 막지 않도록 뒤에서 보낸다."""
        if verdict.tier is not Tier.PENDING:
            return
        task = asyncio.create_task(self._send(build_message(verdict)))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def notify_override(self, override: Override) -> None:
        """임시 허용을 관리자에게 즉시 알린다(뒤에서 전송)."""
        task = asyncio.create_task(self._send(build_override_message(override)))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _send(self, message: dict[str, Any]) -> None:
        try:
            resp = await self.http.post(self.webhook_url, json=message)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning("Slack 알림 실패: %s", type(exc).__name__)


def verify_signature(
    secret: str, timestamp: str, body: bytes, signature: str, now: float | None = None
) -> bool:
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs((now or time.time()) - ts) > _MAX_SKEW:
        return False
    base = b"v0:" + timestamp.encode() + b":" + body
    expected = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def slack_routes(
    service: VerificationService,
    http: httpx.AsyncClient,
    signing_secret: str,
    approvers: set[str] | None = None,
) -> list[Route]:
    async def actions(request: Request) -> Response:
        body = await request.body()
        if not verify_signature(
            signing_secret,
            request.headers.get("x-slack-request-timestamp", ""),
            body,
            request.headers.get("x-slack-signature", ""),
        ):
            return JSONResponse({"error": "invalid signature"}, status_code=401)
        try:
            payload = json.loads(parse_qs(body.decode())["payload"][0])
            action = payload["actions"][0]
            value = json.loads(action["value"])
            tier = Tier(value["tier"])
            user = str(payload["user"]["id"])
        except (KeyError, IndexError, ValueError, TypeError):
            return JSONResponse({"error": "bad payload"}, status_code=400)

        if approvers and user not in approvers:
            text = f"<@{escape(user)}>님은 승인 권한이 없습니다."
        elif tier not in (Tier.TRUSTED, Tier.PARTIAL, Tier.UNTRUSTED):
            return JSONResponse({"error": "bad tier"}, status_code=400)
        else:
            try:
                await service.apply_decision(
                    value["server"], value["tool"], value["hash"], tier, actor=f"slack:{user}"
                )
                text = f"{escape(value['server'])} / {escape(value['tool'])}: *{tier.label}* 확정 (<@{escape(user)}>)"
            except LookupError:
                text = "정의가 바뀌어 이 요청은 만료됐습니다. 새 알림을 확인하세요."

        # 원래 메시지를 결과로 바꾼다. response_url은 Slack 주소만 허용(SSRF 방지)
        response_url = str(payload.get("response_url", ""))
        if (
            urlparse(response_url).scheme == "https"
            and urlparse(response_url).hostname == "hooks.slack.com"
        ):
            try:
                await http.post(response_url, json={"replace_original": True, "text": text})
            except httpx.HTTPError as exc:
                logger.warning("Slack 응답 갱신 실패: %s", type(exc).__name__)
        return Response(status_code=200)

    return [Route("/slack/actions", actions, methods=["POST"])]
