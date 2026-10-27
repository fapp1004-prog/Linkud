"""공급망 검증: Registry `server.json` → 패키지 → SBOM → OSV → 결정 테이블 신호.

결과는 `패키지@버전` 단위로 캐시한다. 조회가 `timeout`을 넘기면 이번 판정에는 "정보 없음"을
돌려주고, 조회는 뒤에서 계속해 끝나면 `on_update(server)`를 불러 재검증하게 한다.
"""

from __future__ import annotations

import asyncio
import logging
import tempfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from linkud.verify.decision import SupplySignals
from linkud.verify.supply.osv import OsvClient, Vuln
from linkud.verify.supply.packages import (
    IntegrityMismatch,
    IntegrityUnavailable,
    UnsupportedPackage,
    fetch_package,
)
from linkud.verify.supply.registry import Package, RegistryClient, remote_matches
from linkud.verify.supply.sbom import SbomUnavailable, SyftSbom, root_purl

logger = logging.getLogger(__name__)

PACKAGE_TTL = 24 * 3600  # 새 CVE가 공개될 수 있으니 하루 지나면 다시 조회
SERVER_TTL = 3600  # Registry 최신 버전이 바뀔 수 있으니 한 시간 지나면 다시 조회


@dataclass(frozen=True)
class SupplyTarget:
    registry_name: str | None
    url: str


@dataclass(frozen=True)
class PackageResult:
    package: Package
    available: bool
    vulns: list[Vuln] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    tampering: bool = False


class RegistrySupplyChecker:
    def __init__(
        self,
        targets: dict[str, SupplyTarget],
        registry: RegistryClient,
        osv: OsvClient,
        http: httpx.AsyncClient,
        sbom: SyftSbom | None = None,
        *,
        timeout: float = 15.0,
        on_update: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self.targets = targets
        self.registry = registry
        self.osv = osv
        self.http = http
        self.sbom = sbom or SyftSbom()
        self.timeout = timeout
        self.on_update = on_update
        self._packages: dict[str, tuple[float, PackageResult]] = {}
        self._servers: dict[str, tuple[float, SupplySignals]] = {}
        self._inflight: dict[str, asyncio.Task[SupplySignals]] = {}

    async def check(self, server: str) -> SupplySignals:
        cached = self._servers.get(server)
        if cached and time.time() - cached[0] < SERVER_TTL:
            return cached[1]
        # 같은 서버의 여러 도구가 동시에 물어도 조회는 한 번만 돈다
        task = self._inflight.get(server)
        if task is None:
            task = asyncio.create_task(self._check_and_store(server))
            self._inflight[server] = task
        try:
            return await asyncio.wait_for(asyncio.shield(task), self.timeout)
        except TimeoutError:
            task.add_done_callback(lambda t: self._notify_later(server, t))
            return SupplySignals(reasons=["공급망 조회 시간 초과: 정보 없음 (뒤에서 계속 조회)"])

    def _notify_later(self, server: str, task: asyncio.Task[SupplySignals]) -> None:
        if self.on_update is not None and not task.cancelled() and task.exception() is None:
            asyncio.get_running_loop().create_task(self.on_update(server))

    async def _check_and_store(self, server: str) -> SupplySignals:
        try:
            signals = await self._check(server)
        finally:
            self._inflight.pop(server, None)
        self._servers[server] = (time.time(), signals)
        return signals

    async def _check(self, server: str) -> SupplySignals:
        target = self.targets.get(server)
        if target is None or not target.registry_name:
            return SupplySignals(reasons=["Registry 이름 미지정: 공급망 정보 없음"])
        record = await self.registry.latest(target.registry_name)
        if record is None:
            return SupplySignals(reasons=[f"Registry에 없음: {target.registry_name}"])
        if not remote_matches(record, target.url):
            return SupplySignals(
                reasons=[f"원격 주소가 Registry remotes와 불일치: {target.registry_name}"]
            )
        if not record.packages:
            return SupplySignals(
                reasons=[f"Registry에 패키지 정보 없음: {record.name}@{record.version}"]
            )

        results = [await self._package(p) for p in record.packages]
        vulns = [v for r in results for v in r.vulns]
        reasons = [f"Registry 매칭: {record.name}@{record.version}"]
        for r in results:
            reasons += r.reasons
        reasons += [f"OSV {v.id} ({v.severity}) @ {v.purl}" for v in vulns]
        return SupplySignals(
            available=all(r.available for r in results),
            malicious_package=any(v.malicious for v in vulns),
            severe_vulnerability=any(v.severe for v in vulns),
            tampering=any(r.tampering for r in results),
            reasons=reasons,
        )

    async def _package(self, pkg: Package) -> PackageResult:
        cached = self._packages.get(pkg.key)
        if cached and time.time() - cached[0] < PACKAGE_TTL:
            return cached[1]
        result = await self._scan_package(pkg)
        self._packages[pkg.key] = (time.time(), result)
        return result

    async def _scan_package(self, pkg: Package) -> PackageResult:
        purl = root_purl(pkg)
        if purl is None:
            return PackageResult(pkg, False, reasons=[f"{pkg.key}: 지원하지 않는 패키지 형식"])
        purls = {purl}
        reasons = []
        sbom_ok = False
        try:
            with tempfile.TemporaryDirectory(prefix="linkud-pkg-") as tmp:
                directory = await fetch_package(self.http, pkg, Path(tmp))
                components = await self.sbom.generate(directory)
            purls |= {c.purl for c in components}
            sbom_ok = True
            reasons.append(f"{pkg.key}: SBOM 구성요소 {len(components)}개")
        except IntegrityMismatch as exc:
            # 조작 의심 패키지는 풀지 않는다. 루트 패키지 OSV 결과는 그대로 조회
            reasons.append(f"{pkg.key}: 공급망 조작 의심 ({exc})")
            return PackageResult(pkg, False, await self.osv.query([purl]), reasons, tampering=True)
        except IntegrityUnavailable as exc:
            reasons.append(f"{pkg.key}: {exc}, 루트 패키지만 조회")
        except (SbomUnavailable, UnsupportedPackage, httpx.HTTPError, ValueError, OSError) as exc:
            reasons.append(
                f"{pkg.key}: SBOM 생성 실패({type(exc).__name__}: {exc}), 루트 패키지만 조회"
            )
        vulns = await self.osv.query(sorted(purls))
        # 의존성을 확인하지 못했으면 '정보 없음'으로 본다. 루트 패키지 결과(MAL- 등)는 그대로 반영
        return PackageResult(pkg, sbom_ok, vulns, reasons)
