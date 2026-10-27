"""감사 로그 보존 기간 정리.

게이트웨이가 켜질 때 한 번, 이후 `interval`초마다 보존 기간이 지난 감사 로그를 지운다.
판정 이력(verdicts)은 캐시 복원·러그풀 비교에 쓰이므로 지우지 않는다.
"""

from __future__ import annotations

import logging
import time

import anyio

from linkud.store.base import AuditEvent, Store

logger = logging.getLogger(__name__)

DAY = 86400


async def purge_once(store: Store, retention_days: float) -> int:
    """보존 기간이 지난 행을 지우고 그 사실을 감사 로그에 남긴다. 0 이하면 정리하지 않는다."""
    if retention_days <= 0:
        return 0
    cutoff = time.time() - retention_days * DAY
    removed = await store.purge_audit(before=cutoff)
    if removed:
        logger.info("감사 로그 %d행 정리 (보존 %s일)", removed, retention_days)
        await store.log(
            AuditEvent(
                "audit_purged", "*", "*", {"removed": removed, "retention_days": retention_days}
            )
        )
    return removed


async def run_retention(store: Store, retention_days: float, interval: float = 3600.0) -> None:
    while True:
        try:
            await purge_once(store, retention_days)
        except Exception as exc:  # 정리 실패가 게이트웨이를 멈추게 하지 않는다
            logger.warning("감사 로그 정리 실패: %s", type(exc).__name__)
        await anyio.sleep(interval)
