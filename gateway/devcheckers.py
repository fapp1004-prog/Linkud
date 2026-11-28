"""(A) devcheckers.py — 개발용 가짜 검사기·가짜 지문. 담당: A.

B·C 검사기가 완성되기 전(D2~D4)에 게이트웨이를 끝까지 돌려보려고 쓴다.
LINKUD_DEV_CHECKERS=1 일 때만 쓰이고, 실제 시연·평가에는 절대 쓰지 않는다.
판정 근거(evidence)에 [DEV]를 붙이고, 판정·DB·대시보드에 모드 'dev'가 기록된다 (SPEC 12장).

테스트용 스위치:
  LINKUD_DEV_NOISY=1          검사기가 print()로 stdout에 글을 쓴다 (통신 선 오염 방지 확인용, SPEC 2장)
  LINKUD_DEV_FAIL=<검사기>    그 검사기가 에러를 낸다 (checker_error 감사 기록 확인용)
"""

import hashlib
import os
import re

_PATTERNS = {
    "hidden_tag": re.compile(r"<\s*important\s*>", re.I),
    "ssh_key_access": re.compile(r"~/\.ssh|id_rsa", re.I),
    "env_file_access": re.compile(r"\.env\b"),
    "secrecy_request": re.compile(r"말하지\s*마|do not (tell|mention)", re.I),
}


def scan(text: str) -> list[str]:
    """B의 checkers.rules.scan 대신 쓰는 가짜 규칙 검사 (제한 도구 정제 확인용)."""
    return [name for name, p in _PATTERNS.items() if p.search(text)]


def _hooks(name: str) -> None:
    if os.environ.get("LINKUD_DEV_NOISY") == "1":
        print(f"[DEV] {name} 검사기가 stdout에 쓴 잡음")  # 게이트웨이가 stderr로 돌려야 한다
    if os.environ.get("LINKUD_DEV_FAIL") == name:
        raise RuntimeError(f"[DEV] {name} 검사기 강제 실패")


def injection(tool: dict, server: dict) -> dict:
    _hooks("injection")
    hits = scan(f"{tool.get('description', '')} {tool.get('inputSchema', '')}")
    return {
        "checker": "injection",
        "risk": min(100, 45 * len(hits)),
        "hard_block": False,
        "signals": hits,
        "evidence": "[DEV] " + (", ".join(hits) if hits else "이상 없음"),
        "latency_ms": 0,
        "confidence": 0.9 if len(hits) >= 2 else 0.0,
        "model": "dev",
        "prompt_version": "dev",
    }


def supply_chain(tool: dict, server: dict) -> dict:
    _hooks("supply_chain")
    return {"checker": "supply_chain", "risk": 0, "hard_block": False, "signals": [],
            "evidence": "[DEV] 검사 안 함", "latency_ms": 0}


def identity(tool: dict, server: dict) -> dict:
    _hooks("identity")
    return {"checker": "identity", "risk": 0, "hard_block": False, "signals": [],
            "evidence": "[DEV] 검사 안 함", "latency_ms": 0}


# ── 가짜 지문 (C의 checkers/fingerprint.py 대신) ──

def _digest(paths: list[str]) -> str:
    h = hashlib.sha256(b"dev:")
    for p in sorted(paths):
        try:
            with open(p, "rb") as f:
                h.update(p.encode() + b"\0" + f.read() + b"\0")
        except OSError:
            h.update(p.encode() + b"\0missing\0")
    return h.hexdigest()


def file_fp(server: dict) -> str:
    """서버 폴더의 코드 파일 내용으로 지문을 만든다. 폴더를 모르면 실행 명령으로."""
    d = server.get("dir")
    if not d:
        return hashlib.sha256(("dev-cmd:" + "\0".join(server.get("command", []))).encode()).hexdigest()
    files = [os.path.join(d, n) for n in os.listdir(d) if n.endswith((".py", ".js", ".mjs", ".ts"))]
    return _digest(files)


def dep_fp(server: dict) -> str:
    d = server.get("dir")
    names = ("requirements.txt", "package-lock.json", "poetry.lock", "uv.lock")
    files = [os.path.join(d, n) for n in names if d and os.path.exists(os.path.join(d, n))]
    return _digest(files)
