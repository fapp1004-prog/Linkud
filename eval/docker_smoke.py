"""Docker 스모크 테스트: 오염 테스트 서버들 앞의 게이트웨이가 기대대로 걸러내는지 본다.

docker compose -f tests/fixtures/poisoned_servers/docker-compose.yml up -d --build
LINKUD_AUTH_TOKENS=smoke-token uv run python eval/docker_smoke.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import time

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

URL = os.environ.get("LINKUD_URL", "http://127.0.0.1:8000/mcp")
TOKEN = os.environ.get("LINKUD_AUTH_TOKENS", "smoke-token").split(",")[0]


async def list_names() -> set[str]:
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"})
    async with Client(streamable_http_client(URL, http_client=http), cache=None) as agent:
        return {t.name for t in (await agent.list_tools()).tools}


async def main() -> int:
    # 모든 다운스트림이 붙고 러그풀 서버가 아직 정상 설명을 보여줄 때까지 기다린다
    deadline = time.time() + 120
    first: set[str] = set()
    while time.time() < deadline:
        try:
            first = await list_names()
            if any(n.startswith("mixed__") for n in first) and any(
                n.startswith("rugpull__") for n in first
            ):
                break
        except Exception as exc:  # 게이트웨이·다운스트림이 뜨는 중
            print(f"대기 중: {type(exc).__name__}")
        await asyncio.sleep(2)
    # 러그풀 서버는 RUGPULL_AFTER번 뒤부터 오염 설명을 보여준다
    second: set[str] = set()
    for _ in range(6):
        second = await list_names()
        if not any(n.startswith("rugpull__") for n in second):
            break

    checks = {
        "오염 서버 도구 숨김": not any(n.startswith("poisoned__") for n in first | second),
        "판별기 공격 서버 도구 숨김": not any(n.startswith("judge__") for n in first | second),
        "러그풀 전에는 보임": any(n.startswith("rugpull__") for n in first),
        "러그풀 후 숨김": not any(n.startswith("rugpull__") for n in second),
        "정상 혼합 서버 도구 보임": {"mixed__list_items", "mixed__get_item"} <= second,
    }
    for name, ok in checks.items():
        print(f"{'통과' if ok else '실패'}: {name}")
    print("1차 목록:", sorted(first))
    print("마지막 목록:", sorted(second))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
