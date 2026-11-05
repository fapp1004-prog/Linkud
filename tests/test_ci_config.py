"""3-2 · 3-5: CI·이미지 공급망 고정 규칙을 검사한다 (파일 정적 검사)."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)(.*)$")


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_actions_pinned_to_full_sha(path):
    found = 0
    for line in path.read_text().splitlines():
        m = USES.match(line)
        if not m:
            continue
        found += 1
        ref, rest = m.groups()
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), (
            f"{path.name}: SHA 고정 아님: {ref}"
        )
        assert re.search(r"#\s*v\d", rest), f"{path.name}: 버전 태그 주석 없음: {line.strip()}"
    assert found


def test_dependabot_covers_actions_and_python():
    import yaml

    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    assert cfg["version"] == 2
    ecosystems = {u["package-ecosystem"] for u in cfg["updates"]}
    assert {"github-actions", "uv"} <= ecosystems
    assert all(u.get("schedule", {}).get("interval") for u in cfg["updates"])


def test_ci_has_vulnerability_scans_and_sbom():
    import yaml

    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    steps = [s for job in ci["jobs"].values() for s in job["steps"]]
    runs = " ".join(s.get("run", "") for s in steps)
    uses = " ".join(s.get("uses", "") for s in steps)
    assert "pip-audit" in runs  # 의존성 취약점 검사
    assert "aquasecurity/trivy-action@" in uses  # 이미지 취약점 스캔
    assert "anchore/sbom-action@" in uses  # syft 기반 이미지 SBOM
    assert "actions/upload-artifact@" in uses  # SBOM 첨부


DOCKERFILES = [
    ROOT / "deploy" / "Dockerfile",
    ROOT / "tests" / "fixtures" / "poisoned_servers" / "Dockerfile",
    ROOT / "demo" / "servers" / "Dockerfile",
    ROOT / "demo" / "driver" / "Dockerfile",
]
COMPOSES = [ROOT / "deploy" / "docker-compose.yml", ROOT / "demo" / "docker-compose.yml"]


def test_ci_runs_demo_smoke():
    import yaml

    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    job = ci["jobs"]["demo-smoke"]
    assert job["needs"] == "test"
    runs = " ".join(s.get("run", "") for s in job["steps"])
    assert "docker compose -f demo/docker-compose.yml up -d --build" in runs
    assert "demo/smoke.py" in runs
    assert "down -v" in runs


def test_dependabot_tracks_demo_images():
    import yaml

    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    docker = next(u for u in cfg["updates"] if u["package-ecosystem"] == "docker")
    assert {"/demo/servers", "/demo/driver"} <= set(docker["directories"])


DIGEST = re.compile(r"[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}")


def _external_images(path):
    for line in path.read_text().splitlines():
        s = line.strip()
        if m := re.match(r"FROM\s+(\S+)", s):
            yield line, m.group(1)
        elif m := re.search(r"COPY\s+--from=(\S+)", s):
            yield line, m.group(1)
        elif m := re.match(r"image:\s*(\S+)", s):
            if not m.group(1).startswith("${"):  # 직접 빌드한 이미지(배포 변수)는 제외
                yield line, m.group(1)


@pytest.mark.parametrize("path", DOCKERFILES + COMPOSES, ids=lambda p: str(p.relative_to(ROOT)))
def test_base_images_pinned_by_digest(path):
    stages = {m.group(1) for m in re.finditer(r"FROM\s+\S+\s+AS\s+(\w+)", path.read_text(), re.I)}
    images = [(line, img) for line, img in _external_images(path) if img not in stages]
    assert images
    for line, img in images:
        assert DIGEST.fullmatch(img), f"다이제스트 고정 아님: {line.strip()}"


def test_oidc_deploy_workflow_uses_short_lived_credentials():
    import yaml

    text = (ROOT / ".github" / "workflows" / "deploy-oidc.yml").read_text()
    wf = yaml.safe_load(text)
    assert wf["permissions"]["id-token"] == "write"
    assert "aws-actions/configure-aws-credentials@" in text
    assert "AWS_ACCESS_KEY_ID" not in text and "AWS_SECRET_ACCESS_KEY" not in text  # 장기 키 없음
    assert "ssm send-command" in text  # 22번 SSH 없이 SSM Run Command로 배포


def test_image_scan_targets_vulnerabilities():
    import yaml

    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    trivy = next(
        s for s in ci["jobs"]["image-scan"]["steps"] if "trivy-action" in s.get("uses", "")
    )
    # 서드파티 패키지 문서 문자열의 예시 값이 비밀값으로 잡히는 오탐을 피하려고 취약점만 본다
    assert trivy["with"]["scanners"] == "vuln"


def test_syft_built_from_source_with_pinned_go():
    text = (ROOT / "deploy" / "Dockerfile").read_text()
    assert re.search(r"FROM golang:[\d.]+-\w+@sha256:[0-9a-f]{64} AS syft", text)
    assert "github.com/anchore/syft/cmd/syft@v" in text
    # syft가 끌어오는 취약한 의존성(go-jose < 4.1.6, CVE-2026-116587)은 수정판으로 올려서 빌드한다
    m = re.search(r"ARG GO_JOSE_VERSION=4\.1\.(\d+)", text)
    assert m and int(m.group(1)) >= 6
    assert "github.com/go-jose/go-jose/v4@v${GO_JOSE_VERSION}" in text
    assert "go build" in text
    assert "COPY --from=syft" in text
    assert "SYFT_CHECK_FOR_APP_UPDATE=false" in text  # 실행 중 외부 업데이트 확인 끔


PY_SLIM_DOCKERFILES = [
    ROOT / "deploy" / "Dockerfile",
    ROOT / "tests" / "fixtures" / "poisoned_servers" / "Dockerfile",
    ROOT / "demo" / "servers" / "Dockerfile",
    ROOT / "demo" / "driver" / "Dockerfile",
]


@pytest.mark.parametrize("path", PY_SLIM_DOCKERFILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_final_stage_upgrades_apt_for_cve_2026_109518(path):
    # 최종(실행) 단계에서 apt·libapt-pkg7.0을 수정판(3.0.4 이상)으로 올리고, 못 올리면 빌드를 멈춘다
    text = path.read_text()
    final = text[text.rindex("\nFROM ") :]
    assert final.lstrip().startswith("FROM python:3.12-slim@sha256:")
    runs = [r for r in re.split(r"\n(?=[A-Z]+ )", final) if r.startswith("RUN ")]
    upgrade = next((r for r in runs if "--only-upgrade" in r), None)
    assert upgrade, "apt 업그레이드 RUN 없음"
    for part in (
        "apt-get update",
        "apt libapt-pkg7.0",
        "dpkg --compare-versions \"$(dpkg-query -W -f='${Version}' apt)\" ge 3.0.4",
        "rm -rf /var/lib/apt/lists/*",  # 같은 RUN에서 목록 캐시 삭제
    ):
        assert part in upgrade, part
    # 업그레이드는 root 단계에서, 그 뒤 비 root 사용자로 전환
    assert final.index(upgrade) < final.index("\nUSER app")
