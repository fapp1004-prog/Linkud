"""(C) supply_chain.py — 공급망 검사. 담당: C. 다른 사람은 고치지 않는다.

서버 폴더의 의존성 파일을 읽어 (이름, 버전) 목록을 만들고, OSV에 알려진 취약점이 있는지 조회한다.
서버 단위 검사라서 A가 서버당 한 번만 부르고, 결과를 그 서버의 모든 도구에 똑같이 붙인다. (SPEC 3·4·5장)

판정 (결정안 ⑦ ⑨)
  ID가 MAL- 로 시작        → malicious_package, risk 100, hard_block
  심각도 HIGH/CRITICAL     → critical_vuln, risk 80  (policy.yaml이 '최소 제한')
  그 밖의 취약점           → known_vuln, risk 50
  의존성 파일 없음          → no_supply_info, risk 40
  버전 고정(==)된 게 없음   → no_supply_info, risk 40
  파일은 있는데 의존성 0개  → risk 0 (표준 라이브러리만 쓴다고 명시한 것)

에러(OSV 접속 실패 등)는 잡지 않고 raise → A가 '제한' 처리 (fail-closed).
외부 라이브러리 없이 표준 라이브러리(urllib)만 쓴다.
"""

import json
import math
import re
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"

RISK = {"malicious_package": 100, "critical_vuln": 80, "known_vuln": 50, "no_supply_info": 40}
MAX_DETAIL = 10          # 심각도를 확인할 취약점 최대 개수
DETAIL_TIMEOUT = 3.0     # 상세 조회 1건당 제한 시간(초)
TOTAL_BUDGET = 8.0       # 검사 전체 제한 (게이트웨이 제한 10초보다 짧게)

_REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([^\s;#,]+)\s*(;.*)?$")


# ── 의존성 파일 읽기 ──────────────────────────────────

def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str):
    """requirements.txt → (고정된 패키지 [(이름, 버전)], 고정 안 된 줄 [str], 의존성 줄 수)."""
    pinned, unpinned, count = [], [], 0
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):          # -r, -e, --index-url 같은 옵션은 조회 대상 아님
            unpinned.append(line)
            continue
        count += 1
        m = _REQ_LINE.match(line)
        if m and not any(c in m.group(3) for c in "*<>!~"):
            pinned.append((_norm(m.group(1)), m.group(3)))
        else:
            unpinned.append(line)
    return pinned, unpinned, count


def parse_package_lock(text: str):
    """package-lock.json (v1·v2·v3) → [(이름, 버전)]."""
    data = json.loads(text)
    found = set()
    for path, info in (data.get("packages") or {}).items():
        if path and isinstance(info, dict) and info.get("version") and "node_modules/" in path:
            found.add((path.rsplit("node_modules/", 1)[1], info["version"]))

    def walk(deps):
        for name, info in (deps or {}).items():
            if isinstance(info, dict):
                if info.get("version"):
                    found.add((name, info["version"]))
                walk(info.get("dependencies"))
    if not found:
        walk(data.get("dependencies"))
    return sorted(found)


def parse_toml_lock(text: str):
    """uv.lock / poetry.lock → [(이름, 버전)]. tomllib는 파이썬 3.11+ 기본 내장."""
    import tomllib
    data = tomllib.loads(text)
    return sorted({(_norm(p["name"]), str(p["version"])) for p in data.get("package", [])
                   if p.get("name") and p.get("version")})


def collect_packages(server_dir):
    """서버 폴더 → (패키지 [(생태계, 이름, 버전)], 고정 안 된 줄, 읽은 파일, 의존성 줄 수)."""
    root = Path(server_dir)
    packages, unpinned, files, count = set(), [], [], 0
    for f in sorted(root.glob("requirements*.txt")):
        pinned, loose, n = parse_requirements(f.read_text(encoding="utf-8", errors="replace"))
        packages.update(("PyPI", n_, v) for n_, v in pinned)
        unpinned += loose
        count += n
        files.append(f.name)
    for name in ("uv.lock", "poetry.lock"):
        f = root / name
        if f.is_file():
            found = parse_toml_lock(f.read_text(encoding="utf-8"))
            packages.update(("PyPI", n_, v) for n_, v in found)
            count += len(found)
            files.append(name)
    f = root / "package-lock.json"
    if f.is_file():
        found = parse_package_lock(f.read_text(encoding="utf-8"))
        packages.update(("npm", n_, v) for n_, v in found)
        count += len(found)
        files.append(f.name)
    return sorted(packages), unpinned, files, count


# ── OSV 조회 ─────────────────────────────────────────

def _http_json(url: str, body=None, timeout: float = 5.0):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def query_osv(packages, timeout: float):
    """querybatch 한 번 → {취약점 ID: [패키지 표시, ...]}. querybatch는 ID만 주고 심각도는 안 준다."""
    queries = [{"package": {"name": n, "ecosystem": eco}, "version": v} for eco, n, v in packages]
    res = _http_json(OSV_BATCH, {"queries": queries}, timeout=timeout)
    hits: dict[str, list[str]] = {}
    for (eco, n, v), r in zip(packages, res.get("results", [])):
        for vuln in (r or {}).get("vulns", []):
            hits.setdefault(vuln["id"], []).append(f"{n}=={v}")
    return hits


# CVSS v3 기본 점수 계산 (vector 문자열 → 0~10). 심각도 표시가 없는 기록용.
_W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
      "UI": {"N": .85, "R": .62}, "CIA": {"H": .56, "L": .22, "N": 0.0}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str):
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        return _roundup(min((1.08 if changed else 1) * (impact + expl), 10))
    except (KeyError, ValueError, IndexError):
        return None


def is_severe(vuln: dict) -> bool:
    """HIGH/CRITICAL 표시가 있거나 CVSS v3 점수 7.0 이상이면 심각."""
    labels = [str((vuln.get("database_specific") or {}).get("severity", ""))]
    for a in vuln.get("affected", []):
        labels.append(str((a.get("ecosystem_specific") or {}).get("severity", "")))
        labels.append(str((a.get("database_specific") or {}).get("severity", "")))
    if any(l.upper() in ("HIGH", "CRITICAL") for l in labels):
        return True
    for s in vuln.get("severity", []):
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = cvss3_score(str(s.get("score", "")))
            if score is not None and score >= 7.0:
                return True
    return False


# ── 검사기 ───────────────────────────────────────────

def _result(risk, signals, evidence, started, hard_block=False):
    return {"checker": "supply_chain", "risk": risk, "hard_block": hard_block, "signals": signals,
            "evidence": evidence, "latency_ms": int((time.monotonic() - started) * 1000)}


def check(tool: dict, server: dict) -> dict:
    started = time.monotonic()
    server_dir = server.get("dir")
    if not server_dir or not Path(server_dir).is_dir():
        raise FileNotFoundError(f"서버 폴더를 알 수 없음: {server_dir!r}")

    packages, unpinned, files, count = collect_packages(server_dir)
    loose = f" · 버전 미고정 {len(unpinned)}줄 조회 안 함" if unpinned else ""
    if not files:
        return _result(RISK["no_supply_info"], ["no_supply_info"], "의존성 파일 없음", started)
    if count == 0 and not unpinned:
        return _result(0, [], f"외부 의존성 없음 ({', '.join(files)})", started)
    if not packages:
        return _result(RISK["no_supply_info"], ["no_supply_info"],
                       f"버전이 고정된 의존성이 없음 ({', '.join(files)}){loose}", started)

    hits = query_osv(packages, timeout=max(1.0, TOTAL_BUDGET - (time.monotonic() - started)))
    if not hits:
        return _result(0, [], f"패키지 {len(packages)}개, 알려진 취약점 없음{loose}", started)

    malicious = sorted(i for i in hits if i.startswith("MAL-"))
    if malicious:
        ev = ", ".join(f"{i} ({'/'.join(hits[i])})" for i in malicious[:5])
        return _result(RISK["malicious_package"], ["malicious_package"], f"악성 패키지: {ev}{loose}",
                       started, hard_block=True)

    # 심각도 확인: GHSA 기록이 심각도 표시를 갖고 있는 경우가 많아서 먼저 본다
    ids = sorted(hits, key=lambda i: (not i.startswith("GHSA-"), i))
    targets, skipped = ids[:MAX_DETAIL], len(ids) - min(len(ids), MAX_DETAIL)
    severe, unchecked = [], skipped
    remaining = max(0.5, TOTAL_BUDGET - (time.monotonic() - started))
    with ThreadPoolExecutor(max_workers=min(len(targets), MAX_DETAIL)) as pool:
        futures = {pool.submit(_http_json, OSV_VULN.format(i), None, DETAIL_TIMEOUT): i for i in targets}
        done, not_done = wait(futures, timeout=remaining)
        unchecked += len(not_done)
        for fut in done:
            try:
                if is_severe(fut.result()):
                    severe.append(futures[fut])
            except Exception:
                unchecked += 1
    note = f" · 심각도 미조회 {unchecked}개" if unchecked else ""

    if severe:
        ev = ", ".join(f"{i} ({'/'.join(hits[i])})" for i in sorted(severe)[:5])
        return _result(RISK["critical_vuln"], ["critical_vuln"],
                       f"심각 취약점 {len(severe)}개: {ev} · 전체 {len(ids)}개{note}{loose}", started)
    ev = ", ".join(f"{i} ({'/'.join(hits[i])})" for i in ids[:5])
    return _result(RISK["known_vuln"], ["known_vuln"], f"취약점 {len(ids)}개: {ev}{note}{loose}", started)
