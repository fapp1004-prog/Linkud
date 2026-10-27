"""패키지 내려받기 (기획서 6장 3단계 앞부분).

내려받아 풀기만 하고 설치·실행하지 않는다(npm install 스크립트 등 자동 실행 방지).
푸는 것도 레지스트리 메타데이터의 해시(npm dist.integrity sha512, PyPI digests.sha256)와
맞을 때만 한다.
압축 해제는 경로 탈출·링크·장치 파일을 막는 안전 필터로 한다.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import io
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import httpx

from linkud.verify.supply.registry import Package

MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024


class UnsupportedPackage(Exception):
    """내려받을 수 없는 패키지 형식 (OCI 이미지 등)."""


class IntegrityUnavailable(Exception):
    """레지스트리 메타데이터에 무결성 해시가 없어 확인할 수 없음."""


class IntegrityMismatch(Exception):
    """내려받은 파일 해시가 레지스트리 메타데이터와 다름 (공급망 조작 의심)."""


@dataclass(frozen=True)
class Artifact:
    url: str
    algorithm: str  # sha512 (npm SRI) | sha256 (PyPI)
    expected: bytes | None  # 기대 해시 원본 바이트. None이면 메타데이터에 없음


def _npm_integrity(dist: dict) -> tuple[str, bytes | None]:
    """npm dist.integrity(SRI, 'sha512-<base64>')에서 sha512 값을 꺼낸다."""
    for token in str(dist.get("integrity") or "").split():
        algo, _, value = token.partition("-")
        if algo == "sha512" and value:
            try:
                return "sha512", base64.b64decode(value, validate=True)
            except binascii.Error:
                return "sha512", None
    return "sha512", None


def verify_integrity(data: bytes, artifact: Artifact) -> None:
    if artifact.expected is None:
        raise IntegrityUnavailable(f"무결성 정보 없음: {artifact.url}")
    actual = hashlib.new(artifact.algorithm, data).digest()
    if not hmac.compare_digest(actual, artifact.expected):
        raise IntegrityMismatch(f"{artifact.algorithm} 불일치: {artifact.url}")


async def _get_json(http: httpx.AsyncClient, url: str) -> dict:
    resp = await http.get(url)
    resp.raise_for_status()
    return resp.json()


async def artifact(http: httpx.AsyncClient, pkg: Package) -> Artifact:
    if pkg.registry_type == "npm":
        meta = await _get_json(
            http,
            f"https://registry.npmjs.org/{quote(pkg.identifier, safe='@/')}/{quote(pkg.version)}",
        )
        algo, expected = _npm_integrity(meta["dist"])
        return Artifact(meta["dist"]["tarball"], algo, expected)
    if pkg.registry_type == "pypi":
        meta = await _get_json(
            http, f"https://pypi.org/pypi/{quote(pkg.identifier)}/{quote(pkg.version)}/json"
        )
        files = meta.get("urls") or []
        # 휠(빌드 스크립트 없음)을 우선하고, 없으면 sdist
        for kind in ("bdist_wheel", "sdist"):
            for f in files:
                if f.get("packagetype") == kind:
                    digest = (f.get("digests") or {}).get("sha256")
                    try:
                        expected = bytes.fromhex(digest) if digest else None
                    except ValueError:
                        expected = None
                    return Artifact(f["url"], "sha256", expected)
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
    """내려받아 레지스트리 해시와 맞을 때만 푼다. 다르면 풀지 않고 IntegrityMismatch."""
    meta = await artifact(http, pkg)
    data = await download(http, meta.url)
    verify_integrity(data, meta)
    extract(data, dest)
    return dest
