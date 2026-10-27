"""OSV 조회 (기획서 6장 4단계): 알려진 취약점(CVE)과 악성 패키지 기록(MAL-)."""

from __future__ import annotations

import math
from dataclasses import dataclass

import httpx

DEFAULT_OSV_URL = "https://api.osv.dev"
_BATCH = 500  # OSV querybatch 한 번에 보낼 질의 수 상한(1000)보다 작게


@dataclass(frozen=True)
class Vuln:
    id: str
    purl: str
    malicious: bool
    severity: str  # CRITICAL, HIGH, MODERATE/MEDIUM, LOW, UNKNOWN

    @property
    def severe(self) -> bool:
        return self.severity in ("CRITICAL", "HIGH")


# --- CVSS v3.x 기본 점수 (FIRST CVSS v3.1 명세) ------------------------------------

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = parts["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[
            parts["PR"]
        ]
        iss = 1 - (
            (1 - _W["CIA"][parts["C"]]) * (1 - _W["CIA"][parts["I"]]) * (1 - _W["CIA"][parts["A"]])
        )
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploitability = (
            8.22 * _W["AV"][parts["AV"]] * _W["AC"][parts["AC"]] * pr * _W["UI"][parts["UI"]]
        )
        if impact <= 0:
            return 0.0
        total = impact + exploitability
        return _roundup(min(1.08 * total, 10) if scope_changed else min(total, 10))
    except (KeyError, ValueError):
        return None


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "NONE"


def severity_of(vuln: dict) -> str:
    """GHSA 등 데이터베이스가 준 등급을 먼저 쓰고, 없으면 CVSS v3 벡터로 계산한다."""
    db = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db, str) and db:
        return db.upper()
    for sev in vuln.get("severity") or []:
        if sev.get("type") in ("CVSS_V3", "CVSS_V3_1", "CVSS_V3_0"):
            score = cvss3_base_score(str(sev.get("score", "")))
            if score is not None:
                return _score_to_severity(score)
    return "UNKNOWN"


class OsvClient:
    def __init__(self, http: httpx.AsyncClient, base_url: str = DEFAULT_OSV_URL) -> None:
        self.http = http
        self.base_url = base_url.rstrip("/")
        self._details: dict[str, dict] = {}

    async def _detail(self, vuln_id: str) -> dict:
        if vuln_id not in self._details:
            resp = await self.http.get(f"{self.base_url}/v1/vulns/{vuln_id}")
            resp.raise_for_status()
            self._details[vuln_id] = resp.json()
        return self._details[vuln_id]

    async def query(self, purls: list[str]) -> list[Vuln]:
        found: list[tuple[str, str]] = []
        for i in range(0, len(purls), _BATCH):
            chunk = purls[i : i + _BATCH]
            resp = await self.http.post(
                f"{self.base_url}/v1/querybatch",
                json={"queries": [{"package": {"purl": p}} for p in chunk]},
            )
            resp.raise_for_status()
            for purl, result in zip(chunk, resp.json().get("results") or [], strict=False):
                found += [(purl, v["id"]) for v in result.get("vulns") or [] if v.get("id")]
        vulns = []
        for purl, vuln_id in found:
            malicious = vuln_id.startswith("MAL-")
            severity = "CRITICAL" if malicious else severity_of(await self._detail(vuln_id))
            vulns.append(Vuln(vuln_id, purl, malicious, severity))
        return vulns
