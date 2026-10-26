"""MCP 공식 Registry 조회와 서버 매칭 (기획서 6장 1·2단계).

다운스트림 설정에 Registry 이름(`registry`)을 명시하고, 그 `server.json`의 `remotes`에
등록된 URL이 실제로 연결하는 URL과 같을 때만 그 패키지와 연결한다(이름 사칭 방지).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlparse

import httpx

DEFAULT_REGISTRY_URL = "https://registry.modelcontextprotocol.io"


@dataclass(frozen=True)
class Package:
    registry_type: str  # npm, pypi, oci, nuget, mcpb ...
    identifier: str
    version: str

    @property
    def key(self) -> str:
        return f"{self.registry_type}:{self.identifier}@{self.version}"


@dataclass(frozen=True)
class ServerRecord:
    name: str
    version: str
    repository: str | None
    remotes: list[str]
    packages: list[Package] = field(default_factory=list)


def parse_server_json(data: dict[str, Any]) -> ServerRecord:
    server = data.get("server", data)
    packages = [
        Package(
            str(p.get("registryType", "")), str(p.get("identifier", "")), str(p.get("version", ""))
        )
        for p in server.get("packages") or []
        if p.get("identifier") and p.get("version")
    ]
    return ServerRecord(
        name=str(server.get("name", "")),
        version=str(server.get("version", "")),
        repository=(server.get("repository") or {}).get("url"),
        remotes=[str(r["url"]) for r in server.get("remotes") or [] if r.get("url")],
        packages=packages,
    )


def normalize_url(url: str) -> str:
    """스킴·호스트는 소문자, 끝의 '/'와 기본 포트는 무시한다. 쿼리·프래그먼트는 버린다."""
    p = urlparse(url)
    host = (p.hostname or "").lower()
    default = {"https": 443, "http": 80}.get(p.scheme.lower())
    port = f":{p.port}" if p.port and p.port != default else ""
    return f"{p.scheme.lower()}://{host}{port}{p.path.rstrip('/')}"


def remote_matches(record: ServerRecord, url: str) -> bool:
    target = normalize_url(url)
    return any(normalize_url(r) == target for r in record.remotes)


class RegistryClient:
    def __init__(self, http: httpx.AsyncClient, base_url: str = DEFAULT_REGISTRY_URL) -> None:
        self.http = http
        self.base_url = base_url.rstrip("/")

    async def latest(self, name: str) -> ServerRecord | None:
        url = f"{self.base_url}/v0/servers/{quote(name, safe='')}/versions/latest"
        resp = await self.http.get(url)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return parse_server_json(resp.json())
