"""5단계: 공급망 검증 (외부 API는 httpx MockTransport로 대체)."""

import asyncio
import io
import json
import tarfile
import zipfile
from pathlib import Path

import httpx
import pytest

from linkud.models import Tier
from linkud.verify.decision import SupplySignals
from linkud.verify.supply.annotations import annotation_mismatch
from linkud.verify.supply.checker import RegistrySupplyChecker, SupplyTarget
from linkud.verify.supply.osv import OsvClient, cvss3_base_score, severity_of
from linkud.verify.supply.packages import extract
from linkud.verify.supply.registry import (
    Package,
    RegistryClient,
    normalize_url,
    parse_server_json,
    remote_matches,
)
from linkud.verify.supply.sbom import (
    Component,
    SbomUnavailable,
    SyftSbom,
    parse_cyclonedx,
    root_purl,
)
from tests.helpers import FakeDownstream, make_gateway, pipeline, tool

FIXTURES = Path(__file__).parent / "fixtures" / "supply"
REGISTRY_DOC = json.loads((FIXTURES / "registry_achromat.json").read_text())
NAME = "ai.achromat/mcp-server"
REMOTE = "https://mom.achromat.ai/mcp"
ROOT_PURL = "pkg:npm/%40achromat-ai/mcp-server@0.1.2"
DEP_PURL = "pkg:npm/lodash@4.17.20"


def _tgz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


TARBALL = _tgz({"package/package.json": b'{"name": "x", "scripts": {"postinstall": "evil"}}'})


class FakeSbom:
    def __init__(self, components=None, fail=False):
        self.components = (
            components if components is not None else [Component("lodash", "4.17.20", DEP_PURL)]
        )
        self.fail = fail
        self.dirs = []

    async def generate(self, directory):
        self.dirs.append(sorted(p.name for p in directory.rglob("*")))
        if self.fail:
            raise SbomUnavailable("syft 없음")
        return self.components


def make_transport(vulns_by_purl=None, details=None, registry_status=200, calls=None):
    vulns_by_purl = vulns_by_purl or {}
    details = details or {}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if calls is not None:
            calls.append(url)
        if url.startswith("https://registry.modelcontextprotocol.io/v0/servers/"):
            if registry_status != 200:
                return httpx.Response(registry_status)
            return httpx.Response(200, json=REGISTRY_DOC)
        if url == "https://registry.npmjs.org/@achromat-ai/mcp-server/0.1.2":
            return httpx.Response(
                200, json={"dist": {"tarball": "https://registry.npmjs.org/t.tgz"}}
            )
        if url == "https://registry.npmjs.org/t.tgz":
            return httpx.Response(200, content=TARBALL)
        if url == "https://api.osv.dev/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": i} for i in vulns_by_purl.get(q["package"]["purl"], [])]}
                        for q in queries
                    ]
                },
            )
        if url.startswith("https://api.osv.dev/v1/vulns/"):
            return httpx.Response(200, json=details[url.rsplit("/", 1)[1]])
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def make_checker(transport, sbom=None, name=NAME, url=REMOTE, **kw):
    http = httpx.AsyncClient(transport=transport)
    return RegistrySupplyChecker(
        {"s": SupplyTarget(name, url)},
        RegistryClient(http),
        OsvClient(http),
        http,
        sbom or FakeSbom(),
        **kw,
    )


# --- Registry ------------------------------------------------------------------


def test_parse_registry_fixture():
    rec = parse_server_json(REGISTRY_DOC)
    assert rec.name == NAME
    assert rec.packages == [Package("npm", "@achromat-ai/mcp-server", "0.1.2")]
    assert rec.remotes == [REMOTE]


@pytest.mark.parametrize(
    ("url", "match"),
    [
        (REMOTE, True),
        ("https://MOM.achromat.ai/mcp/", True),
        ("https://mom.achromat.ai:443/mcp", True),
        ("https://mom.achromat.ai/mcp?x=1", True),
        ("http://mom.achromat.ai/mcp", False),
        ("https://evil.example/mcp", False),
        ("https://mom.achromat.ai/other", False),
    ],
)
def test_remote_matching(url, match):
    assert remote_matches(parse_server_json(REGISTRY_DOC), url) is match


def test_normalize_url_keeps_custom_port():
    assert normalize_url("https://h:8443/a/") == "https://h:8443/a"


# --- SBOM·OSV ------------------------------------------------------------------


def test_root_purl():
    assert root_purl(Package("npm", "@achromat-ai/mcp-server", "0.1.2")) == ROOT_PURL
    assert root_purl(Package("pypi", "Foo_Bar", "1.0")) == "pkg:pypi/foo-bar@1.0"
    assert root_purl(Package("oci", "x", "1")) is None


def test_parse_cyclonedx():
    doc = {
        "components": [
            {"name": "a", "version": "1", "purl": "pkg:npm/a@1"},
            {"name": "nopurl", "version": "1"},
        ]
    }
    assert parse_cyclonedx(doc) == [Component("a", "1", "pkg:npm/a@1")]


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("garbage", None),
    ],
)
def test_cvss3_base_score(vector, score):
    assert cvss3_base_score(vector) == score


def test_severity_prefers_database_rating():
    assert severity_of({"database_specific": {"severity": "HIGH"}}) == "HIGH"
    cvss = {
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    }
    assert severity_of(cvss) == "CRITICAL"
    assert severity_of({}) == "UNKNOWN"


# --- 압축 해제 안전성 ------------------------------------------------------------


def test_tar_path_traversal_rejected(tmp_path):
    with pytest.raises(tarfile.TarError):
        extract(_tgz({"../escape.txt": b"x"}), tmp_path / "out")
    assert not (tmp_path / "escape.txt").exists()


def test_zip_path_traversal_rejected(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../escape.txt", "x")
    with pytest.raises(ValueError):
        extract(buf.getvalue(), tmp_path / "out")


def test_extract_does_not_run_scripts(tmp_path):
    extract(TARBALL, tmp_path)
    assert (tmp_path / "package" / "package.json").exists()  # 풀기만 하고 실행하지 않는다


# --- 체커 ------------------------------------------------------------------------


async def test_full_check_with_severe_vulnerability():
    sbom = FakeSbom()
    details = {"GHSA-1": {"id": "GHSA-1", "database_specific": {"severity": "HIGH"}}}
    checker = make_checker(make_transport({DEP_PURL: ["GHSA-1"]}, details), sbom)
    signals = await checker.check("s")
    assert signals.available and signals.severe_vulnerability and not signals.malicious_package
    assert any("GHSA-1" in r for r in signals.reasons)
    assert sbom.dirs and "package.json" in sbom.dirs[0]


async def test_malicious_root_package():
    checker = make_checker(make_transport({ROOT_PURL: ["MAL-2026-1"]}))
    signals = await checker.check("s")
    assert signals.malicious_package


async def test_clean_package_is_available():
    signals = await make_checker(make_transport()).check("s")
    assert signals.available and not signals.severe_vulnerability and not signals.malicious_package


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"name": None}, "Registry 이름 미지정"),
        ({"url": "https://evil.example/mcp"}, "불일치"),
    ],
)
async def test_unavailable_cases(kwargs, reason):
    signals = await make_checker(make_transport(), **kwargs).check("s")
    assert not signals.available
    assert reason in signals.reasons[0]


async def test_not_in_registry():
    signals = await make_checker(make_transport(registry_status=404)).check("s")
    assert not signals.available and "Registry에 없음" in signals.reasons[0]


async def test_sbom_failure_is_unavailable_but_root_still_checked():
    checker = make_checker(make_transport({ROOT_PURL: ["MAL-1"]}), FakeSbom(fail=True))
    signals = await checker.check("s")
    assert not signals.available and signals.malicious_package
    assert any("루트 패키지만" in r for r in signals.reasons)


async def test_package_result_is_cached():
    calls = []
    checker = make_checker(make_transport(calls=calls))
    await checker.check("s")
    checker._servers.clear()  # 서버 캐시만 비우고 패키지 캐시는 유지
    await checker.check("s")
    assert sum("t.tgz" in c for c in calls) == 1


async def test_timeout_returns_no_info_and_notifies_later():
    class SlowSbom(FakeSbom):
        async def generate(self, directory):
            await asyncio.sleep(0.3)
            return []

    updated = asyncio.Event()

    async def on_update(server):
        updated.set()

    checker = make_checker(make_transport(), SlowSbom(), timeout=0.05, on_update=on_update)
    signals = await checker.check("s")
    assert not signals.available and "시간 초과" in signals.reasons[0]
    await asyncio.wait_for(updated.wait(), 2)
    assert (await checker.check("s")).available  # 뒤에서 채운 결과


async def test_real_syft_if_installed(tmp_path):
    sbom = SyftSbom()
    if not sbom.available():
        pytest.skip("syft 없음")
    (tmp_path / "package.json").write_text('{"name": "a", "version": "1.0.0"}')
    assert isinstance(await sbom.generate(tmp_path), list)


# --- annotations 불일치와 등급 반영 -----------------------------------------------


@pytest.mark.parametrize(
    ("definition", "mismatch"),
    [
        ({"name": "delete_file", "annotations": {"readOnlyHint": True}}, True),
        (
            {
                "name": "get_file",
                "description": "Deletes the file after reading.",
                "annotations": {"readOnlyHint": True},
            },
            True,
        ),
        (
            {"name": "get_file", "annotations": {"readOnlyHint": True, "destructiveHint": True}},
            True,
        ),
        (
            {
                "name": "get_file",
                "description": "Read a file.",
                "annotations": {"readOnlyHint": True},
            },
            False,
        ),
        ({"name": "delete_file", "annotations": {"readOnlyHint": False}}, False),
    ],
)
def test_annotation_mismatch(definition, mismatch):
    assert bool(annotation_mismatch(definition)) is mismatch


class StaticSupply:
    def __init__(self, signals):
        self.signals = signals

    async def check(self, server):
        return self.signals


@pytest.mark.parametrize(
    ("signals", "tier"),
    [
        (SupplySignals(available=True), Tier.TRUSTED),
        (SupplySignals(available=True, severe_vulnerability=True), Tier.PARTIAL),
        (SupplySignals(available=True, malicious_package=True), Tier.UNTRUSTED),
        (SupplySignals(), Tier.PARTIAL),
    ],
)
async def test_supply_result_reflected_in_tier(signals, tier):
    """Registry에 있는 서버의 OSV 결과가 등급에 반영된다."""
    gw, _ = make_gateway(
        [FakeDownstream("s", [tool("get_x", "Get x.")])],
        verifier=pipeline(supply=StaticSupply(signals), no_supply_info="partial"),
    )
    await gw.list_tools()
    assert gw.enforcer.server_tiers()["s"] is tier


async def test_annotation_mismatch_makes_server_pending():
    ds = FakeDownstream(
        "s", [tool("delete_all", "Delete everything.", annotations={"readOnlyHint": True})]
    )
    gw, _ = make_gateway(
        [ds], verifier=pipeline(supply=StaticSupply(SupplySignals(available=True)))
    )
    assert await gw.list_tools() == []
    assert gw.enforcer.server_tiers()["s"] is Tier.PENDING


async def test_checker_end_to_end_through_pipeline():
    checker = make_checker(make_transport({ROOT_PURL: ["MAL-9"]}))
    gw, store = make_gateway(
        [FakeDownstream("s", [tool("get_x", "Get x.")])], verifier=pipeline(supply=checker)
    )
    assert await gw.list_tools() == []
    verdict = store.verdicts[-1]
    assert verdict.tier is Tier.UNTRUSTED
    assert any("MAL-9" in r for r in verdict.reasons)
