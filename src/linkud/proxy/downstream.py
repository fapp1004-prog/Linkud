"""다운스트림 MCP 서버 연결.

`Downstream`은 게이트웨이가 다운스트림에 기대하는 최소 인터페이스다. 실제 구현은
`HttpDownstream`(Streamable HTTP)이고, 테스트에서는 도구 정의를 데이터로 주입하는
가짜 구현을 쓴다(오염 서버를 호스트에서 띄우지 않기 위해).
"""

from __future__ import annotations

import logging
from typing import Any, Protocol

import anyio
import mcp.types as types
from mcp import Client
from mcp.shared.exceptions import MCPError

logger = logging.getLogger(__name__)

# 페이지가 끝나지 않는 다운스트림이 목록 요청을 붙잡지 못하게 하는 상한
_MAX_PAGES = 50


class DownstreamUnavailable(Exception):
    """다운스트림에 연결할 수 없거나 응답이 없을 때."""


class Downstream(Protocol):
    name: str

    async def list_tools(self) -> list[types.Tool]: ...

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None
    ) -> types.CallToolResult: ...


class HttpDownstream:
    """원격 HTTP MCP 서버 하나에 대한 연결.

    MCP 클라이언트 세션은 연 태스크에서 닫아야 하므로, 연결 소유 태스크(`run`)가
    세션을 열어 두고 요청 처리 태스크들은 그 세션을 빌려 쓴다. 전송 오류가 나면
    세션을 버리고 다시 연결한다.
    """

    def __init__(
        self,
        name: str,
        url: str,
        *,
        connect_timeout: float = 10.0,
        call_timeout: float = 30.0,
        reconnect_delay: float = 1.0,
    ) -> None:
        self.name = name
        self.url = url
        self.connect_timeout = connect_timeout
        self.call_timeout = call_timeout
        self.reconnect_delay = reconnect_delay
        self._client: Client | None = None
        self._connected = anyio.Event()
        self._reset = anyio.Event()
        self._stopped = False

    async def run(self) -> None:
        """연결을 유지한다. 게이트웨이 수명 동안 태스크 그룹에서 돈다."""
        while not self._stopped:
            try:
                # 응답 캐시를 끈다: 러그풀 감지를 위해 매 목록 요청이 다운스트림까지 가야 함
                async with Client(
                    self.url, cache=None, read_timeout_seconds=self.call_timeout
                ) as client:
                    self._client = client
                    self._connected.set()
                    logger.info("다운스트림 연결됨: %s", self.name)
                    await self._reset.wait()
            except Exception as exc:  # 연결 실패는 재시도한다
                logger.warning("다운스트림 연결 실패: %s (%s)", self.name, type(exc).__name__)
            finally:
                self._client = None
                self._connected = anyio.Event()
                self._reset = anyio.Event()
            if not self._stopped:
                await anyio.sleep(self.reconnect_delay)

    def stop(self) -> None:
        self._stopped = True
        self._reset.set()

    async def _get_client(self) -> Client:
        with anyio.move_on_after(self.connect_timeout):
            await self._connected.wait()
        if self._client is None:
            raise DownstreamUnavailable(self.name)
        return self._client

    def _drop(self) -> None:
        self._reset.set()

    async def list_tools(self) -> list[types.Tool]:
        client = await self._get_client()
        tools: list[types.Tool] = []
        cursor: str | None = None
        try:
            with anyio.fail_after(self.call_timeout):
                for _ in range(_MAX_PAGES):
                    page = await client.list_tools(cursor=cursor, cache_mode="refresh")
                    tools.extend(page.tools)
                    cursor = page.next_cursor
                    if cursor is None:
                        return tools
        except MCPError:
            raise
        except Exception as exc:
            self._drop()
            raise DownstreamUnavailable(self.name) from exc
        # 페이지가 끝나지 않으면 불완전한 목록을 쓰지 않는다(fail-closed)
        raise DownstreamUnavailable(f"{self.name}: 페이지 상한 초과")

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        client = await self._get_client()
        try:
            with anyio.fail_after(self.call_timeout):
                return await client.call_tool(name, arguments)
        except MCPError:
            raise
        except Exception as exc:
            self._drop()
            raise DownstreamUnavailable(self.name) from exc
