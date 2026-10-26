"""게이트웨이 설정 읽기.

다운스트림은 원격 HTTP(S) MCP 서버만 받는다. stdio 서버 실행은 범위 밖이며 금지한다
(남의 코드를 게이트웨이 권한으로 실행하지 않기 위해, CLAUDE.md 원칙).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

# 다운스트림 이름은 도구 이름 접두사로 쓰이므로 구분자("__")가 들어가면 안 된다.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class ConfigError(ValueError):
    """설정 파일이 형식에 맞지 않을 때."""


@dataclass(frozen=True)
class DownstreamConfig:
    name: str
    url: str
    # MCP Registry의 server.json 이름 (예: io.github.org/server). 없으면 공급망 정보 없음
    registry: str | None = None


@dataclass(frozen=True)
class GatewayConfig:
    name: str = "linkud-gateway"
    host: str = "127.0.0.1"
    port: int = 8000
    path: str = "/mcp"
    # 다운스트림 연결·응답 타임아웃(초)
    connect_timeout: float = 10.0
    call_timeout: float = 30.0
    # 검증 경로 타임아웃(초). 넘기면 그 도구는 숨긴다(fail-closed)
    verify_timeout: float = 30.0
    db_path: str = "linkud.db"
    # LLM 판별기: claude(운영) | fake(개발·테스트 전용, 모든 도구를 정상으로 판별)
    judge: str = "claude"
    judge_model: str = "claude-haiku-5-5"
    judge_timeout: float = 20.0
    # 결정 테이블 정책
    high_confidence: float = 0.8
    no_supply_info: str = "partial"  # partial(부분신뢰) | record(기록만)
    # 공급망 검증
    supply_enabled: bool = True
    registry_url: str = "https://registry.modelcontextprotocol.io"
    osv_url: str = "https://api.osv.dev"
    syft_path: str = "syft"
    supply_timeout: float = 15.0  # 넘기면 이번 판정은 정보 없음, 뒤에서 계속 조회
    # 공개 배포: 허용할 Host 헤더(예: ["gw.example.com"]). 비우면 루프백 주소만 허용
    allowed_hosts: list[str] = field(default_factory=list)
    # 다운스트림 도구 결과 크기 상한(바이트). 넘으면 에이전트에게 넘기지 않는다
    max_result_bytes: int = 1_000_000
    # 인자 검사(확장): 허용된 도구라도 민감 경로 등 위험한 값으로 부르면 거부
    arg_inspection: bool = True
    downstreams: list[DownstreamConfig] = field(default_factory=list)


def _parse_downstream(raw: Any) -> DownstreamConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"downstream 항목은 매핑이어야 함: {raw!r}")
    if "command" in raw or "args" in raw:
        raise ConfigError("stdio 다운스트림은 지원하지 않음 (원격 HTTP 서버만 등록)")
    name = raw.get("name")
    url = raw.get("url")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise ConfigError(f"다운스트림 이름은 소문자·숫자·하이픈만 허용: {name!r}")
    if not isinstance(url, str) or urlparse(url).scheme not in ("http", "https"):
        raise ConfigError(f"다운스트림 URL은 http(s)만 허용: {url!r}")
    registry = raw.get("registry")
    if registry is not None and not isinstance(registry, str):
        raise ConfigError(f"registry는 문자열이어야 함: {registry!r}")
    return DownstreamConfig(name=name, url=url, registry=registry)


def parse_config(data: dict[str, Any]) -> GatewayConfig:
    gw = data.get("gateway") or {}
    if not isinstance(gw, dict):
        raise ConfigError("gateway 항목은 매핑이어야 함")
    downstreams = [_parse_downstream(d) for d in data.get("downstreams") or []]
    names = [d.name for d in downstreams]
    if len(names) != len(set(names)):
        raise ConfigError("다운스트림 이름이 중복됨")
    known = {k: gw[k] for k in GatewayConfig.__dataclass_fields__ if k in gw and k != "downstreams"}
    cfg = GatewayConfig(**known, downstreams=downstreams)
    if cfg.judge not in ("claude", "fake"):
        raise ConfigError(f"judge는 claude 또는 fake: {cfg.judge!r}")
    if cfg.no_supply_info not in ("partial", "record"):
        raise ConfigError(f"no_supply_info는 partial 또는 record: {cfg.no_supply_info!r}")
    return cfg


def load_config(path: str | Path) -> GatewayConfig:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ConfigError("설정 파일 최상위는 매핑이어야 함")
    return parse_config(data)
