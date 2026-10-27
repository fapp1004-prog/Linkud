"""2-2: 테스트 서버·게이트웨이를 별도 프로세스로 띄워 재는 측정 (작은 수로만 실행)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


async def test_multiprocess_bench_reports_all_paths():
    from eval.bench_multiproc import run

    result = await run(n=5, concurrency=2, total=10)
    assert result["mode"] == "multiprocess"
    for key in ("direct", "gateway_memory", "gateway_sqlite"):
        assert result[key]["throughput_rps"] > 0
        assert result[key]["call_tool"]["n"] == 5
