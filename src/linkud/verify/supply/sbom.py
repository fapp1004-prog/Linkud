"""SBOM 생성 (기획서 6장 3단계): syft로 풀어 둔 패키지의 의존성 목록을 만든다."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import anyio

from linkud.verify.supply.registry import Package


class SbomUnavailable(Exception):
    """syft가 없거나 실패했을 때."""


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    purl: str


def root_purl(pkg: Package) -> str | None:
    if pkg.registry_type == "npm":
        return f"pkg:npm/{quote(pkg.identifier, safe='/')}@{pkg.version}"
    if pkg.registry_type == "pypi":
        name = pkg.identifier.lower().replace("_", "-").replace(".", "-")
        return f"pkg:pypi/{name}@{pkg.version}"
    return None


def parse_cyclonedx(doc: dict) -> list[Component]:
    out = []
    for c in doc.get("components") or []:
        purl = c.get("purl")
        if purl and c.get("version"):
            out.append(Component(str(c.get("name", "")), str(c["version"]), str(purl)))
    return out


class SyftSbom:
    def __init__(self, syft_path: str = "syft", timeout: float = 120.0) -> None:
        self.syft_path = syft_path
        self.timeout = timeout

    def available(self) -> bool:
        return shutil.which(self.syft_path) is not None

    async def generate(self, directory: Path) -> list[Component]:
        if not self.available():
            raise SbomUnavailable("syft 없음")
        with anyio.fail_after(self.timeout):
            result = await anyio.run_process(
                [self.syft_path, f"dir:{directory}", "-o", "cyclonedx-json", "-q"],
                check=False,
            )
        if result.returncode != 0:
            raise SbomUnavailable(f"syft 실패 (exit {result.returncode})")
        return parse_cyclonedx(json.loads(result.stdout))
