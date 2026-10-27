"""패키지 내려받기 (기획서 6장 3단계 앞부분).

내려받아 풀기만 하고 설치·실행하지 않는다(npm install 스크립트 등 자동 실행 방지).
압축 해제는 경로 탈출·링크·장치 파일을 막는 안전 필터로 한다.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import httpx

from linkud.verify.supply.registry import Package

MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024


class UnsupportedPackage(Exception):
    """내려받을 수 없는 패키지 형식 (OCI 이미지 등)."""


async def _get_json(http: httpx.AsyncClient, url: str) -> dict:
    resp = await http.get(url)
    resp.raise_for_status()
    return resp.json()


async def artifact_url(http: httpx.AsyncClient, pkg: Package) -> str:
    if pkg.registry_type == "npm":
        meta = await _get_json(
            http,
            f"https://registry.npmjs.org/{quote(pkg.identifier, safe='@/')}/{quote(pkg.version)}",
        )
        return meta["dist"]["tarball"]
    if pkg.registry_type == "pypi":
        meta = await _get_json(
            http, f"https://pypi.org/pypi/{quote(pkg.identifier)}/{quote(pkg.version)}/json"
        )
        files = meta.get("urls") or []
        # 휠(빌드 스크립트 없음)을 우선하고, 없으면 sdist
        for kind in ("bdist_wheel", "sdist"):
            for f in files:
                if f.get("packagetype") == kind:
                    return f["url"]
        raise UnsupportedPackage(f"{pkg.key}: 내려받을 파일 없음")
    raise UnsupportedPackage(f"{pkg.registry_type} 패키지는 지원하지 않음")


async def download(http: httpx.AsyncClient, url: str, limit: int = MAX_DOWNLOAD_BYTES) -> bytes:
    buf = bytearray()
    async with http.stream("GET", url) as resp:
        resp.raise_for_status()
        async for chunk in resp.aiter_bytes():
            buf.extend(chunk)
            if len(buf) > limit:
                raise ValueError("패키지 크기 상한 초과")
    return bytes(buf)


def _safe_member(name: str) -> bool:
    p = PurePosixPath(name)
    return not p.is_absolute() and ".." not in p.parts


def extract(data: bytes, dest: Path) -> None:
    """tar(.tgz)·zip(.whl) 아카이브를 안전하게 푼다."""
    dest.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if not _safe_member(info.filename):
                    raise ValueError(f"안전하지 않은 경로: {info.filename}")
            zf.extractall(dest)
        return
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        # 'data' 필터: 절대경로·경로 탈출·링크 탈출·장치 파일 거부, 실행 권한 제거
        tf.extractall(dest, filter="data")


async def fetch_package(http: httpx.AsyncClient, pkg: Package, dest: Path) -> Path:
    data = await download(http, await artifact_url(http, pkg))
    extract(data, dest)
    return dest
