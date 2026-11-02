"""브레이크 글래스 임시 허용 기록과 메모리 레지스트리 (docs/break-glass.md).

임시 허용 하나는 (사용자, 서버, 도구, 도구 해시) 하나에만 적용된다. 정의가 바뀌면 해시가 달라져 자동으로
맞지 않고, 만료는 조회할 때 판단한다. 런타임 경로(tools/list·tools/call)는 이 레지스트리(메모리)만 본다.
"""

from __future__ import annotations

from dataclasses import dataclass

from linkud.store.base import Store


@dataclass(frozen=True)
class Override:
    id: str
    user: str
    server: str
    tool: str
    tool_hash: str
    ref: str  # 이 임시 허용의 근거가 된 거부 참조 번호
    reason: str
    created_at: float
    expires_at: float
    revoked_at: float | None = None

    def active(self, now: float) -> bool:
        return self.revoked_at is None and now < self.expires_at


class OverrideRegistry:
    def __init__(self) -> None:
        self._by_id: dict[str, Override] = {}
        self._expired_logged: set[str] = set()

    async def restore(self, store: Store, now: float) -> None:
        """시작할 때 최근 24시간 기록(만료 상한·하루 횟수 계산에 필요한 범위)을 메모리로 올린다."""
        for o in await store.load_overrides(since=now - 86400):
            self._by_id[o.id] = o
            if not o.active(now):
                self._expired_logged.add(o.id)  # 재시작 전 일은 다시 기록하지 않는다

    def add(self, override: Override) -> None:
        self._by_id[override.id] = override

    def get(self, override_id: str) -> Override | None:
        return self._by_id.get(override_id)

    def all(self) -> list[Override]:
        return sorted(self._by_id.values(), key=lambda o: o.created_at, reverse=True)

    def revoke(self, override_id: str, at: float) -> Override | None:
        o = self._by_id.get(override_id)
        if o is None or o.revoked_at is not None:
            return None
        revoked = Override(**{**o.__dict__, "revoked_at": at})
        self._by_id[override_id] = revoked
        return revoked

    def active_for(
        self, user: str | None, server: str, tool: str, tool_hash: str | None, now: float
    ) -> Override | None:
        if user is None or tool_hash is None:
            return None
        for o in self._by_id.values():
            if (o.user, o.server, o.tool, o.tool_hash) == (
                user,
                server,
                tool,
                tool_hash,
            ) and o.active(now):
                return o
        return None

    def newly_expired(self, now: float) -> list[Override]:
        """만료됐지만 아직 감사 로그에 남기지 않은 것 (회수된 것은 제외)."""
        out = [
            o
            for o in self._by_id.values()
            if o.revoked_at is None and now >= o.expires_at and o.id not in self._expired_logged
        ]
        self._expired_logged.update(o.id for o in out)
        return out

    def count_recent(self, user: str, since: float) -> int:
        """하루 횟수 제한용: 회수·만료와 상관없이 since 이후 받은 임시 허용 수."""
        return sum(1 for o in self._by_id.values() if o.user == user and o.created_at >= since)

    def used_ref(self, ref: str) -> bool:
        return any(o.ref == ref for o in self._by_id.values())
