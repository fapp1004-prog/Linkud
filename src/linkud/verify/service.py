"""검증 경로 진입점.

캐시에 없는 도구(새 도구이거나 해시가 바뀐 도구)만 검증기를 돌린다. 같은 도구에
동시 요청이 와도 락으로 검증은 한 번만 돈다. 검증이 실패하거나 시간을 넘기면
판정 없음(None)을 돌려주고, 집행 계층은 그 도구를 숨긴다(fail-closed).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

import anyio
import mcp.types as types

from linkud.models import ToolVerdict
from linkud.store.base import AuditEvent, Cache, Store, verdict_key
from linkud.verify.hashing import tool_hash

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VerifyRequest:
    server: str
    tool: types.Tool
    tool_hash: str
    # 같은 서버·같은 이름 도구의 직전 판정(해시가 다름). 있으면 정의가 바뀐 것(러그풀 후보)
    previous: ToolVerdict | None


class Verifier(Protocol):
    async def verify(self, req: VerifyRequest) -> ToolVerdict: ...


class VerificationService:
    def __init__(self, verifier: Verifier, cache: Cache, store: Store, *, timeout: float = 30.0):
        self.verifier = verifier
        self.cache = cache
        self.store = store
        self.timeout = timeout
        self._locks: dict[str, anyio.Lock] = {}
        # (서버, 도구 이름) → 가장 최근 판정. 정의 변경(러그풀) 감지 기록용
        self._latest_by_name: dict[tuple[str, str], ToolVerdict] = {}

    async def warm(self) -> None:
        """저장소의 판정 이력으로 캐시를 채운다(재시작 후 재검증 방지)."""
        for v in sorted(await self.store.latest_verdicts(), key=lambda v: v.created_at):
            await self.cache.set(verdict_key(v.server, v.tool_hash), v)
            self._latest_by_name[(v.server, v.tool)] = v

    async def verdicts(
        self, server: str, tools: Sequence[types.Tool]
    ) -> dict[str, ToolVerdict | None]:
        """도구 이름 → 판정. 판정이 없으면(None) 숨겨야 한다."""
        results: dict[str, ToolVerdict | None] = {}

        async def one(tool: types.Tool) -> None:
            results[tool.name] = await self.verdict_for(server, tool)

        async with anyio.create_task_group() as tg:
            for tool in tools:
                tg.start_soon(one, tool)
        return results

    async def verdict_for(self, server: str, tool: types.Tool) -> ToolVerdict | None:
        h = tool_hash(tool)
        key = verdict_key(server, h)
        if (cached := await self.cache.get(key)) is not None:
            return cached
        lock = self._locks.setdefault(key, anyio.Lock())
        async with lock:
            # 락을 기다리는 동안 다른 요청이 검증을 끝냈을 수 있다
            if (cached := await self.cache.get(key)) is not None:
                return cached
            return await self._verify(server, tool, h, key)

    async def _verify(self, server: str, tool: types.Tool, h: str, key: str) -> ToolVerdict | None:
        previous = self._latest_by_name.get((server, tool.name))
        if previous is not None and previous.tool_hash != h:
            await self.store.log(
                AuditEvent(
                    "definition_changed",
                    server,
                    tool.name,
                    {"old_hash": previous.tool_hash, "new_hash": h, "old_tier": previous.tier},
                )
            )
        req = VerifyRequest(
            server, tool, h, previous if previous and previous.tool_hash != h else None
        )
        try:
            with anyio.fail_after(self.timeout):
                verdict = await self.verifier.verify(req)
        except Exception as exc:
            # 실패는 캐시하지 않는다: 다음 목록 요청에서 다시 검증한다
            logger.warning("검증 실패: %s/%s (%s)", server, tool.name, type(exc).__name__)
            await self.store.log(
                AuditEvent(
                    "verify_failed", server, tool.name, {"hash": h, "error": type(exc).__name__}
                )
            )
            return None
        await self.cache.set(key, verdict)
        await self.store.save_verdict(verdict)
        self._latest_by_name[(server, tool.name)] = verdict
        await self.store.log(
            AuditEvent(
                "verdict",
                server,
                tool.name,
                {
                    "hash": h,
                    "tier": verdict.tier,
                    "is_read": verdict.is_read,
                    "reasons": verdict.reasons,
                },
            )
        )
        return verdict
