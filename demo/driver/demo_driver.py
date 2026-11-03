"""시연 드라이버: 에이전트 역할을 하는 MCP 클라이언트. 정해진 시나리오만 수행한다.

시연 페이지는 nginx를 거쳐 이 경로들만 부른다. 요청 본문·쿼리로 도구 이름·인자를 받지 않는다
(본문이나 쿼리가 있으면 400). 에이전트 토큰은 환경변수 LINKUD_AGENT_TOKEN으로만 받고 응답에 넣지 않는다.

    GET  /driver/status          AI 판사 켜짐 여부, 게이트웨이 연결 여부
    GET  /driver/scene/1         Linkud 없이 번역 서버에 직접 붙었을 때 보이는 도구 목록
    GET  /driver/raw-tool        번역 서버에서 직접 받은 원래 도구 정의 + 규칙 검사가 걸린 곳
    POST /driver/scene/3         Linkud로 목록 받기 + 번역 도구 호출 시도 → 거부 문구·참조 번호
    GET  /driver/eval            eval/results/results.json의 평가 수치
    POST /driver/scene/5/before  러그풀 서버를 처음 상태로 + Linkud 목록
    POST /driver/scene/5/after   러그풀 서버 설명을 바꾼 뒤 + Linkud 목록
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from linkud.verify.rules import scan

logger = logging.getLogger("demo_driver")

# 시나리오에서 쓰는 고정 값 (요청으로 바꿀 수 없음)
TRANSLATE = "translator__translate"
TRANSLATE_ARGS = {"text": "이 문서를 영어로 번역해 주세요."}
RUGPULL_TOOL = "rugpull__summarize_doc"
DISCONNECTED = {"error": "연결 끊김"}


@dataclass(frozen=True)
class Settings:
    gateway_url: str
    translator_url: str
    rugpull_url: str
    agent_token: str = field(repr=False)
    judge: str
    results_path: Path


def settings_from_env(env: Mapping[str, str]) -> Settings:
    token = env.get("LINKUD_AGENT_TOKEN", "")
    if not token:
        raise SystemExit("LINKUD_AGENT_TOKEN 환경변수가 필요하다")
    return Settings(
        gateway_url=env.get("DEMO_GATEWAY_URL", "http://gateway:8000/mcp"),
        translator_url=env.get("DEMO_TRANSLATOR_URL", "http://translator:9000/mcp"),
        rugpull_url=env.get("DEMO_RUGPULL_URL", "http://rugpull:9000"),
        agent_token=token,
        # 'claude'일 때만 켜짐으로 표시한다. 그 밖의 값은 모두 꺼짐(규칙만)으로 본다
        judge="claude" if env.get("DEMO_JUDGE") == "claude" else "fake",
        results_path=Path(env.get("DEMO_RESULTS_PATH", "/app/results.json")),
    )


def highlights(description: str) -> list[dict[str, Any]]:
    """Linkud 규칙 검사(linkud.verify.rules.scan)가 설명에서 걸린 곳을 위치로 돌려준다.

    규칙 결과는 앞뒤 문맥을 포함한 발췌문이라, 그 발췌문이 설명의 어디에 있는지 찾아 표시한다.
    """
    flat = description.replace("\n", " ")
    out = []
    for m in scan({"name": "", "description": description}).matches:
        if m.field != "description":
            continue
        start = flat.find(m.excerpt)
        if start >= 0:
            out.append(
                {
                    "start": start,
                    "end": start + len(m.excerpt),
                    "rule": m.rule,
                    "category": m.category,
                }
            )
    return out


def make_app(settings: Settings) -> Starlette:
    async def agent_client() -> Any:
        http = httpx2.AsyncClient(
            headers={"Authorization": f"Bearer {settings.agent_token}"}, timeout=20.0
        )
        return Client(streamable_http_client(settings.gateway_url, http_client=http), cache=None)

    async def linkud_tools() -> list[str]:
        async with await agent_client() as agent:
            return [t.name for t in (await agent.list_tools()).tools]

    async def direct_tools(url: str) -> list[Any]:
        http = httpx2.AsyncClient(timeout=20.0)
        async with Client(streamable_http_client(url, http_client=http), cache=None) as c:
            return list((await c.list_tools()).tools)

    async def rugpull_switch(path: str) -> None:
        async with httpx.AsyncClient(timeout=10.0) as http:
            (await http.post(f"{settings.rugpull_url}{path}")).raise_for_status()

    def fixed(
        handler: Callable[[], Awaitable[dict[str, Any]]],
    ) -> Callable[[Request], Awaitable[JSONResponse]]:
        async def endpoint(request: Request) -> JSONResponse:
            # 고정 시나리오만: 본문·쿼리로 무언가를 넘기려 하면 거부한다
            if request.url.query or await request.body():
                return JSONResponse({"error": "입력을 받지 않는 경로"}, status_code=400)
            try:
                return JSONResponse(await handler())
            except Exception as exc:  # 연결 실패 등: 내부 정보 없이 '연결 끊김'만
                logger.warning("시나리오 실패: %s", type(exc).__name__)
                return JSONResponse(DISCONNECTED, status_code=502)

        return endpoint

    async def status() -> dict[str, Any]:
        try:
            await linkud_tools()
            ok = True
        except Exception:
            ok = False
        # 'claude'가 아닌 값은 모두 꺼짐으로 표시한다(fail-closed)
        return {"judge": "claude" if settings.judge == "claude" else "fake", "gateway": ok}

    async def scene1() -> dict[str, Any]:
        return {"tools": [t.name for t in await direct_tools(settings.translator_url)]}

    async def raw_tool() -> dict[str, Any]:
        tools = await direct_tools(settings.translator_url)
        t = next(t for t in tools if t.name == "translate")
        description = t.description or ""
        return {
            "server": "translator",
            "name": t.name,
            "description": description,
            "inputSchema": t.input_schema,
            "highlights": highlights(description),
        }

    async def scene3() -> dict[str, Any]:
        async with await agent_client() as agent:
            visible = [t.name for t in (await agent.list_tools()).tools]
            result = await agent.call_tool(TRANSLATE, TRANSLATE_ARGS)
        text = result.content[0].text if result.content else ""
        ref = text.rsplit(" ", 1)[-1] if result.is_error else None
        return {
            "visible": visible,
            "attempted": TRANSLATE,
            "denied": bool(result.is_error),
            "message": text,
            "ref": ref,
        }

    async def scene5(path: str) -> dict[str, Any]:
        await rugpull_switch(path)
        (tool,) = await direct_tools(f"{settings.rugpull_url}/mcp")
        visible = await linkud_tools()
        return {
            "description": tool.description or "",
            "visible": visible,
            "visible_tool": RUGPULL_TOOL in visible,
        }

    async def scene5_before() -> dict[str, Any]:
        return await scene5("/demo/reset")

    async def scene5_after() -> dict[str, Any]:
        return await scene5("/demo/rugpull")

    async def eval_numbers() -> dict[str, Any]:
        data = json.loads(settings.results_path.read_text(encoding="utf-8"))
        rules = data["detection"]["summary"]["rules"]
        rug = data["rugpull"][0]
        latency = data["latency"]
        return {
            "measured_at": data["meta"]["time"],
            "judge": data["meta"]["judge"],
            "detection": {"found": rules["tp"], "total": rules["p"]},
            "false_positive": {"count": rules["fp"], "total": rules["n"]},
            "rugpull": {"hidden": rug["hidden_after_change"], "total": rug["total"]},
            "write_exposed": len(data["permission"]["partial_e2e"]["write_exposed"]),
            "latency_ms": {
                "direct_p50": latency["direct"]["call_tool"]["p50"],
                "linkud_p50": latency["gateway_cache_hit"]["call_tool"]["p50"],
            },
        }

    return Starlette(
        routes=[
            Route("/driver/status", fixed(status), methods=["GET"]),
            Route("/driver/scene/1", fixed(scene1), methods=["GET"]),
            Route("/driver/raw-tool", fixed(raw_tool), methods=["GET"]),
            Route("/driver/scene/3", fixed(scene3), methods=["POST"]),
            Route("/driver/eval", fixed(eval_numbers), methods=["GET"]),
            Route("/driver/scene/5/before", fixed(scene5_before), methods=["POST"]),
            Route("/driver/scene/5/after", fixed(scene5_after), methods=["POST"]),
        ]
    )


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    if os.environ.get("LINKUD_IN_DOCKER") != "1":
        sys.exit("시연 드라이버는 Docker 안에서만 실행한다 (docker compose up)")
    uvicorn.run(make_app(settings_from_env(os.environ)), host="0.0.0.0", port=8100)
