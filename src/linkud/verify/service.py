"""검증 경로 진입점.

캐시에 없는 도구(새 도구이거나 해시가 바뀐 도구)만 검증기를 돌린다. 같은 도구에
동시 요청이 와도 락으로 검증은 한 번만 돈다. 검증이 실패하거나 시간을 넘기면
판정 없음(None)을 돌려주고, 집행 계층은 그 도구를 숨긴다(fail-closed).
"""

from __future__ import annotations

import dataclasses
import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

import anyio
import mcp.types as types

from linkud.models import Tier, ToolVerdict
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
        # 새 판정이 나올 때 부르는 콜백 (Slack 알림 등). 실패해도 판정에는 영향 없음
        self.on_verdict: list[Callable[[ToolVerdict], Awaitable[None]]] = []

    async def warm(self) -> None:
        """저장소의 판정 이력으로 캐시를 채운다(재시작 후 재검증 방지)."""
        for v in sorted(await self.store.latest_verdicts(), key=lambda v: v.created_at):
            await self.cache.set(verdict_key(v.server, v.tool_hash), v)
            self._latest_by_name[(v.server, v.tool)] = v

    def pending(self) -> list[ToolVerdict]:
        """현재 정의 기준으로 승인 대기인 도구들."""
        return [v for v in self._latest_by_name.values() if v.tier is Tier.PENDING]

    def latest(self) -> list[ToolVerdict]:
        return list(self._latest_by_name.values())

    async def apply_decision(
        self, server: str, tool: str, tool_hash: str, tier: Tier, *, actor: str, note: str = ""
    ) -> ToolVerdict:
        """사람이 등급을 확정한다. 지금 보이는 정의(해시)에 대해서만 받는다.

        확정은 해시 단위라서, 승인 뒤 정의가 바뀌면(러그풀) 자동으로 다시 검증 경로를 탄다.
        """
        current = self._latest_by_name.get((server, tool))
        if current is None or current.tool_hash != tool_hash:
            raise LookupError("현재 정의와 해시가 다름 (정의가 바뀌었거나 없는 도구)")
        verdict = dataclasses.replace(
            current,
            tier=tier,
            reasons=[f"관리자 확정: {tier.label} (by {actor}){': ' + note if note else ''}"]
            + current.reasons,
            details={**current.details, "decided_by": actor, "previous_tier": current.tier.value},
            created_at=time.time(),
        )
        await self.cache.set(verdict_key(server, tool_hash), verdict)
        await self.store.save_verdict(verdict)
        self._latest_by_name[(server, tool)] = verdict
        await self.store.log(
            AuditEvent(
                "decision",
                server,
                tool,
                {
                    "hash": tool_hash,
                    "tier": tier,
                    "from": current.tier,
                    "actor": actor,
                    "note": note,
                },
            )
        )
        return verdict

    async def invalidate_server(self, server: str) -> None:
        """서버의 현재 판정을 캐시에서 지워 다음 목록 요청 때 다시 검증하게 한다.

        공급망 조회가 뒤늦게 끝났을 때 등 판정 입력이 바뀐 경우에 쓴다.
        """
        for (srv, _), verdict in list(self._latest_by_name.items()):
            if srv == server:
                await self.cache.delete(verdict_key(server, verdict.tool_hash))
        await self.store.log(AuditEvent("reverify_requested", server, "*", {}))

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
        for callback in self.on_verdict:
            try:
                await callback(verdict)
            except Exception as exc:
                logger.warning("판정 알림 실패: %s", type(exc).__name__)
        return verdict
