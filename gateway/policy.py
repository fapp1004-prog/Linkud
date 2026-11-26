"""(A) policy.py — 담당: A. 다른 사람은 고치지 않는다.

검사기 결과를 policy.yaml 규칙대로 합쳐 0~100 신뢰점수와 허용/제한/차단 등급을 정한다. (SPEC 5장)

판정 순서 (위에서부터 처음 걸리는 것으로 결정):
  1) hard_block 또는 B의 confidence ≥ 기준 → 차단 (에러가 있어도 차단이 우선)
  2) 검사기 에러·시간 초과·잘못된 결과  → 제한
  3) restrict_if_signals 신호            → 최소 제한
  4) 신뢰점수 = 100 - Σ(risk × weight)  → 허용 / 제한 / 차단
"""

import hashlib
import importlib
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Callable

import yaml

from checkers.base import SIGNALS
from gateway import paths

GRADE_ORDER = {"allow": 0, "restrict": 1, "block": 2}

# 서버 단위 검사기: 서버당 한 번만 돌리고 결과를 그 서버의 모든 도구에 똑같이 쓴다 (SPEC 5장)
SERVER_LEVEL = {"supply_chain", "identity"}


# ── 정책 파일 ─────────────────────────────────────────

def load_policy(path=None) -> dict:
    with open(path or paths.policy_path(), encoding="utf-8") as f:
        p = yaml.safe_load(f)
    weights = p["weights"]
    if abs(sum(weights.values()) - 1.0) > 1e-6:
        raise ValueError(f"policy.yaml weights 합이 1이 아님: {weights}")
    t = p["thresholds"]
    if not (0 <= t["restrict"] <= t["allow"] <= 100):
        raise ValueError(f"policy.yaml thresholds 이상: {t}")
    return p


def policy_fp(policy: dict) -> str:
    """적용한 정책 설정의 지문. 캐시 키에 들어가서, 정책이 바뀌면 이전 판정·승인을 쓰지 않는다 (SPEC 6장).
    주석·공백·키 순서는 지문에 영향을 주지 않는다(파싱한 값 기준)."""
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── 검사기 불러오기 ───────────────────────────────────

Checker = Callable[[dict, dict], dict]


def _missing(name: str, why: str) -> Checker:
    def check(tool, server):
        raise NotImplementedError(f"검사기 '{name}'를 쓸 수 없음: {why}")
    return check


def load_checkers(policy: dict) -> dict[str, Checker]:
    """policy.yaml weights에 있는 검사기를 checkers/<이름>.py의 check 함수로 불러온다.

    아직 구현 안 됐으면 호출할 때 에러를 내는 함수로 대신한다 → 판정은 '제한' (fail-closed).
    LINKUD_DEV_CHECKERS=1 이면 개발용 가짜 검사기를 쓴다 (gateway/devcheckers.py).
    """
    if paths.mode() == "dev":
        from gateway import devcheckers
        print("[policy] ⚠ 개발용 가짜 검사기 사용 중 (LINKUD_DEV_CHECKERS=1)", file=sys.stderr)
        return {n: getattr(devcheckers, n) for n in policy["weights"]}

    loaded: dict[str, Checker] = {}
    for name in policy["weights"]:
        try:
            mod = importlib.import_module(f"checkers.{name}")
            fn = getattr(mod, "check", None)
            loaded[name] = fn if callable(fn) else _missing(name, "check 함수가 없음")
        except Exception as e:  # 검사기 파일 자체가 깨져도 게이트웨이는 살아서 '제한'으로 처리
            loaded[name] = _missing(name, f"불러오기 실패 {type(e).__name__}: {e}")
    return loaded


# ── 검사기 실행 ───────────────────────────────────────

_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="checker")


def run_checker(name: str, fn: Checker, tool: dict, server: dict, timeout: float):
    """검사기 하나를 시간 제한을 걸고 실행한다. 실패하면 결과 대신 예외 객체를 돌려준다."""
    started = time.monotonic()
    future = _pool.submit(fn, tool, server)
    try:
        result = future.result(timeout=timeout)
    except FutureTimeout:
        return TimeoutError(f"{name}: {timeout}초 안에 끝나지 않음")
    except Exception as e:
        return e
    try:
        validate_result(name, result)
    except ValueError as e:
        return e
    result.setdefault("latency_ms", int((time.monotonic() - started) * 1000))
    return result


def validate_result(name: str, r) -> None:
    """약속 1 모양인지 확인한다. 어긋나면 에러 → '제한'."""
    if not isinstance(r, dict):
        raise ValueError(f"{name}: 결과가 dict가 아님")
    for key, typ in (("checker", str), ("risk", int), ("hard_block", bool), ("signals", list), ("evidence", str)):
        if not isinstance(r.get(key), typ) or (typ is int and isinstance(r.get(key), bool)):
            raise ValueError(f"{name}: '{key}' 필드가 없거나 타입이 {typ.__name__}가 아님")
    if not 0 <= r["risk"] <= 100:
        raise ValueError(f"{name}: risk가 0~100 밖 ({r['risk']})")
    unknown = [s for s in r["signals"] if s not in SIGNALS]
    if unknown:
        raise ValueError(f"{name}: 목록에 없는 신호 {unknown} (checkers/base.py SIGNALS에 먼저 추가)")
    if "confidence" in r and not (isinstance(r["confidence"], (int, float)) and 0 <= r["confidence"] <= 1):
        raise ValueError(f"{name}: confidence가 0~1 숫자가 아님")
    for key in ("model", "prompt_version"):  # B가 판정에 쓴 모델·프롬프트 버전 (SPEC 3·14장)
        if key in r and not (isinstance(r[key], str) and r[key]):
            raise ValueError(f"{name}: '{key}'가 비어 있지 않은 문자열이 아님")


# ── 서버 지문 (C의 checkers/fingerprint.py) ─────────────

Fingerprint = Callable[[dict], str]


def load_fingerprints() -> tuple[Fingerprint | None, Fingerprint | None]:
    """C의 file_fp(server)·dep_fp(server)를 불러온다. (SPEC 6장, 결정 #29)
    실제 모드에서 없으면 None → 지문 없음 → 판정을 재사용·승인하지 않는다.
    개발 모드에서는 C가 아직 없을 때 개발용 가짜 지문을 쓴다."""
    try:
        mod = importlib.import_module("checkers.fingerprint")
        f, d = getattr(mod, "file_fp", None), getattr(mod, "dep_fp", None)
        if callable(f) and callable(d):
            return f, d
    except Exception:
        pass
    if paths.mode() == "dev":
        from gateway import devcheckers
        return devcheckers.file_fp, devcheckers.dep_fp
    return None, None


# ── 판정 ─────────────────────────────────────────────

@dataclass
class Decision:
    grade: str
    score: int
    signals: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def _grade_by_score(score: int, thresholds: dict) -> str:
    if score >= thresholds["allow"]:
        return "allow"
    if score >= thresholds["restrict"]:
        return "restrict"
    return "block"


def decide(results: dict[str, object], policy: dict) -> Decision:
    """results: {검사기 이름: CheckResult 또는 예외}. 정책에 있는 검사기가 빠져 있으면 에러로 본다."""
    rules = policy["hard_rules"]
    weights = policy["weights"]
    signals: list[str] = []
    reasons: list[str] = []

    # 1) 에러 — 하나라도 있으면 '제한' (fail-closed). 단, 다른 검사기가 '차단'을 냈으면 차단이 우선
    errors = []
    for name in weights:
        r = results.get(name)
        if r is None:
            errors.append(f"{name}: 결과 없음")
        elif isinstance(r, BaseException):
            errors.append(f"{type(r).__name__}: {r}")
    ok = {n: r for n, r in results.items() if isinstance(r, dict)}
    for r in ok.values():
        signals.extend(s for s in r["signals"] if s not in signals)

    # 2) 하드 룰: 차단
    for n, r in ok.items():
        if rules.get("block_if_hard_block") and r["hard_block"]:
            reasons.append(f"hard_block: {n} — {r['evidence']}")
        conf = r.get("confidence")
        limit = rules.get("block_if_confidence_at_least")
        if conf is not None and limit is not None and conf >= limit:
            reasons.append(f"confidence {conf:.2f} ≥ {limit}: {n} — {r['evidence']}")
    if reasons:
        return Decision("block", 0, signals, reasons + [f"checker_error: {e}" for e in errors])

    if errors:
        return Decision(rules.get("on_checker_error", "restrict"), 0, signals,
                        [f"checker_error: {e}" for e in errors])

    # 4) 점수
    score = round(100 - sum(ok[n]["risk"] * w for n, w in weights.items()))
    score = max(0, min(100, score))
    grade = _grade_by_score(score, policy["thresholds"])
    reasons.append(f"score {score} → {grade}")

    # 3) 최소 제한 신호
    hits = [s for s in rules.get("restrict_if_signals", []) if s in signals]
    if hits and grade == "allow":
        grade = "restrict"
        reasons.append(f"최소 제한 신호: {', '.join(hits)}")

    for n, r in ok.items():
        if r["risk"] > 0:
            reasons.append(f"{n} risk {r['risk']}: {r['evidence']}")
    return Decision(grade, score, signals, reasons)
