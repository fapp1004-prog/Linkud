"""처리량 측정 (별도 프로세스): 테스트 서버·게이트웨이·부하 클라이언트를 각각 다른 프로세스로 돌린다.

run_eval.py의 기본 지연 측정은 세 가지가 한 프로세스·한 이벤트 루프를 나눠 써서 서로의 CPU 시간을
빼앗는다(처리량이 낮게, 게이트웨이 오버헤드가 크게 나오는 편향). 이 스크립트는 그 편향을 뺀 값을 잰다.

    uv run python eval/bench_multiproc.py              # 결과를 출력
    uv run python eval/run_eval.py --multiproc         # RESULTS.md에 두 방식 결과를 함께 기록
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from eval.measure import measure_path  # noqa: E402


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port: int, proc: subprocess.Popen, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"프로세스가 종료됨 (exit {proc.returncode})")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"포트 {port}가 열리지 않음")


@contextmanager
def spawn(args: list[str], port: int) -> Iterator[None]:
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    env.pop("LINKUD_AUTH_TOKENS", None)
    proc = subprocess.Popen(
        [sys.executable, *args],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_port(port, proc)
        yield
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


async def run(n: int = 200, concurrency: int = 10, total: int = 1000) -> dict[str, Any]:
    out: dict[str, Any] = {
        "mode": "multiprocess",
        "n": n,
        "concurrency": concurrency,
        "total_calls": total,
    }
    math_port = free_port()
    # 정상 테스트 서버(호스트 실행 안전)만 띄운다
    with spawn(["-m", "tests.fixtures.benign_servers", "math", str(math_port)], math_port):
        downstream = f"http://127.0.0.1:{math_port}/mcp"
        out["direct"] = await measure_path(downstream, "add", n, concurrency, total)
        for store in ("memory", "sqlite"):
            gw_port = free_port()
            cmd = [
                "eval/bench_gateway.py",
                "--port",
                str(gw_port),
                "--downstream",
                downstream,
                "--store",
                store,
            ]
            with spawn(cmd, gw_port):
                url = f"http://127.0.0.1:{gw_port}/mcp"
                out[f"gateway_{store}"] = await measure_path(
                    url, "math__add", n, concurrency, total
                )
    return out


if __name__ == "__main__":
    print(json.dumps(asyncio.run(run()), ensure_ascii=False, indent=2))
