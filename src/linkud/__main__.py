"""`linkud --config config.yaml` 로 게이트웨이를 실행한다."""

from __future__ import annotations

import argparse
import logging

import uvicorn

from linkud.config import load_config
from linkud.proxy.gateway import create_app


def main() -> None:
    parser = argparse.ArgumentParser(prog="linkud", description="Linkud MCP 게이트웨이")
    parser.add_argument("--config", default="config.yaml", help="설정 파일 경로")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    config = load_config(args.config)
    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port, log_level="info")


if __name__ == "__main__":
    main()
