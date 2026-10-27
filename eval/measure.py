"""지연·처리량 측정 도우미 (run_eval.py, bench_multiproc.py 공용)."""

from __future__ import annotations

import asyncio
import statistics
import time
from typing import Any

from mcp import Client


def pct(values: list[float], q: float) -> float:
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def stats(ms: list[float]) -> dict[str, float]:
    return {"n": len(ms), "mean": statistics.mean(ms), "p50": pct(ms, 0.5), "p95": pct(ms, 0.95)}


async def timed(fn: Any, n: int) -> list[float]:
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        await fn()
        out.append((time.perf_counter() - t0) * 1000)
    return out


async def throughput(url: str, tool: str, concurrency: int, total: int) -> float:
    """동시 클라이언트 `concurrency`개가 합쳐서 `total`번 호출할 때 초당 호출 수."""
    per = max(1, total // concurrency)

    async def worker() -> None:
        async with Client(url, cache=None) as c:
            await c.list_tools()
            for _ in range(per):
                await c.call_tool(tool, {"a": 1, "b": 2})

    t0 = time.perf_counter()
    await asyncio.gather(*(worker() for _ in range(concurrency)))
    return (per * concurrency) / (time.perf_counter() - t0)


async def measure_path(url: str, tool: str, n: int, concurrency: int, total: int) -> dict[str, Any]:
    """한 경로의 list_tools·call_tool 지연과 처리량."""
    async with Client(url, cache=None) as c:
        await c.list_tools()  # 게이트웨이면 첫 검증으로 캐시를 채운다
        out: dict[str, Any] = {
            "list_tools": stats(await timed(c.list_tools, n)),
            "call_tool": stats(await timed(lambda: c.call_tool(tool, {"a": 1, "b": 2}), n)),
        }
    out["throughput_rps"] = await throughput(url, tool, concurrency, total)
    return out
