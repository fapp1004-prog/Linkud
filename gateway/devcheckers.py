"""(A) devcheckers.py — 개발용 가짜 검사기. 담당: A.

B·C 검사기가 완성되기 전(D2~D4)에 게이트웨이를 끝까지 돌려보려고 쓴다.
LINKUD_DEV_CHECKERS=1 일 때만 쓰이고, 실제 시연·평가에는 절대 쓰지 않는다.
판정 근거(evidence)에 [DEV]를 붙여서 대시보드에서 구분되게 한다.
"""

import re

_PATTERNS = {
    "hidden_tag": re.compile(r"<\s*important\s*>", re.I),
    "ssh_key_access": re.compile(r"~/\.ssh|id_rsa", re.I),
    "env_file_access": re.compile(r"\.env\b"),
    "secrecy_request": re.compile(r"말하지\s*마|do not (tell|mention)", re.I),
}


def injection(tool: dict, server: dict) -> dict:
    text = f"{tool.get('description', '')} {tool.get('inputSchema', '')}"
    hits = [name for name, p in _PATTERNS.items() if p.search(text)]
    return {
        "checker": "injection",
        "risk": min(100, 45 * len(hits)),
        "hard_block": False,
        "signals": hits,
        "evidence": "[DEV] " + (", ".join(hits) if hits else "이상 없음"),
        "latency_ms": 0,
        "confidence": 0.9 if len(hits) >= 2 else 0.0,
    }


def supply_chain(tool: dict, server: dict) -> dict:
    return {"checker": "supply_chain", "risk": 0, "hard_block": False, "signals": [],
            "evidence": "[DEV] 검사 안 함", "latency_ms": 0}


def identity(tool: dict, server: dict) -> dict:
    return {"checker": "identity", "risk": 0, "hard_block": False, "signals": [],
            "evidence": "[DEV] 검사 안 함", "latency_ms": 0}
