"""측정용 게이트웨이 프로세스 (eval/bench_multiproc.py가 띄운다).

    python eval/bench_gateway.py --port 9100 --downstream http://127.0.0.1:9101/mcp --store sqlite

FakeJudge·공급망 꺼짐·공급망 정보 없음 기록만: 캐시 히트 경로의 게이트웨이 오버헤드만 본다.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

import uvicorn

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from linkud.config import parse_config  # noqa: E402
from linkud.proxy.gateway import create_app  # noqa: E402
from linkud.store.memory import MemoryStore  # noqa: E402
from linkud.store.sqlite import SqliteStore  # noqa: E402
from linkud.verify.decision import NoSupplyInfo, Policy  # noqa: E402
from linkud.verify.judge.fake import FakeJudge  # noqa: E402
from linkud.verify.pipeline import PipelineVerifier  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--downstream", required=True)
    parser.add_argument("--store", choices=["memory", "sqlite"], default="memory")
    args = parser.parse_args()

    cfg = parse_config(
        {
            "gateway": {"supply_enabled": False},
            "downstreams": [{"name": "math", "url": args.downstream}],
        }
    )
    with tempfile.TemporaryDirectory() as tmp:
        store = MemoryStore() if args.store == "memory" else SqliteStore(Path(tmp) / "bench.db")
        verifier = PipelineVerifier(FakeJudge(), None, Policy(no_supply_info=NoSupplyInfo.RECORD))
        app = create_app(cfg, store=store, verifier=verifier)
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
