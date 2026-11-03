"""시연 환경 종단 간 스모크 테스트 (시연 compose를 띄운 상태에서 실행한다).

    docker compose -f demo/docker-compose.yml up -d --build
    DEMO_ADMIN_TOKEN="$(docker compose -f demo/docker-compose.yml exec -T nginx cat /demo-secrets/admin.nginx)" \
        uv run python demo/smoke.py

DEMO_ADMIN_TOKEN은 '페이지에 관리 토큰이 없는지' 확인하는 데만 쓰고 출력하지 않는다(없으면 그 검사는 건너뜀).
"""

from __future__ import annotations

import os
import re
import socket
import sys
import time

import httpx

BASE = os.environ.get("DEMO_URL", "http://127.0.0.1:8080")
REF = re.compile(r"LK-[0-9A-HJKMNP-TV-Z]{8}")
results: list[bool] = []


def check(name: str, ok: bool, extra: str = "") -> None:
    results.append(ok)
    print(f"{'통과' if ok else '실패'}: {name}" + (f" ({extra})" if extra else ""))


def port_closed(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) != 0


def main() -> int:
    http = httpx.Client(base_url=BASE, timeout=60, trust_env=False)

    # 모든 서비스가 뜨고 게이트웨이가 다운스트림에 붙을 때까지 기다린다
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            if http.get("/driver/status").json().get("gateway"):
                break
        except Exception as exc:
            print(f"대기 중: {type(exc).__name__}")
        time.sleep(3)

    # 1. 장면 3: 실제 참조 번호 → 감사 로그에서 조회
    s3 = http.post("/driver/scene/3").json()
    ref = s3.get("ref") or ""
    check("장면 3 번역 도구 숨김", "translator__translate" not in s3.get("visible", []))
    check("장면 3 정상 도구 보임", "notes__list_notes" in s3.get("visible", []))
    check("장면 3 거부 + 참조 번호", s3.get("denied") is True and bool(REF.fullmatch(ref)), ref)
    found = http.get("/api/admin/audit", params={"ref": ref})
    event = found.json()[0] if found.status_code == 200 and found.json() else {}
    check(
        "참조 번호가 감사 로그에서 조회됨",
        event.get("ref") == ref and event.get("server") == "translator",
        f"HTTP {found.status_code}",
    )

    # 2. 장면 1·2·4·5
    check(
        "장면 1 직접 목록에 translate",
        http.get("/driver/scene/1").json().get("tools") == ["translate"],
    )
    raw = http.get("/driver/raw-tool").json()
    check(
        "장면 2 원래 정의 + 형광펜",
        "id_rsa" in raw.get("description", "") and bool(raw.get("highlights")),
    )
    ev = http.get("/driver/eval").json()
    check("장면 4 평가 수치", ev.get("detection", {}).get("total", 0) > 0)
    before = http.post("/driver/scene/5/before").json()
    after = http.post("/driver/scene/5/after").json()
    check(
        "장면 5 러그풀 전 보임 → 후 숨김",
        before.get("visible_tool") is True and after.get("visible_tool") is False,
    )

    # 3. nginx: 관리 API는 조회 세 경로의 GET만
    for method in ("POST", "DELETE", "PUT", "PATCH"):
        r = http.request(method, "/api/admin/audit")
        check(f"/api/admin/audit {method} 막힘", r.status_code in (403, 405), str(r.status_code))
    for path in (
        "/api/admin/decisions",
        "/api/admin/pending",
        "/api/admin/overrides",
        "/api/admin/servers/x/release",
    ):
        r = http.post(path)
        check(f"POST {path} 막힘", r.status_code in (403, 404, 405), str(r.status_code))
    # 클라이언트가 보낸 다른 토큰으로 바꿔치기할 수 없다(nginx가 덮어씀) → 조회는 그대로 됨
    r = http.get("/api/admin/servers", headers={"Authorization": "Bearer wrong"})
    check("클라이언트 Authorization 무시", r.status_code == 200, str(r.status_code))

    # 4. 드라이버: 고정 시나리오만
    r = http.post("/driver/scene/3", json={"tool": "notes__save_note", "arguments": {"title": "x"}})
    check("드라이버가 임의 입력 거부", r.status_code == 400, str(r.status_code))

    # 5. 페이지: 보안 헤더, 토큰 없음
    page = http.get("/")
    csp = page.headers.get("content-security-policy", "")
    check("CSP: 인라인 스크립트 금지", "script-src 'self'" in csp and "unsafe-inline" not in csp)
    bodies = [page.text, http.get("/app.js").text, http.get("/app.css").text]
    token = os.environ.get("DEMO_ADMIN_TOKEN", "")
    check(
        "페이지에 Authorization·Bearer 없음",
        not any(("Bearer" in b or "Authorization" in b) for b in bodies),
    )
    if token:
        check(
            "페이지·응답에 관리 토큰 값 없음",
            not any(token in b for b in [*bodies, found.text, str(found.headers)]),
        )
    else:
        print("건너뜀: DEMO_ADMIN_TOKEN이 없어 토큰 값 검사는 하지 않음")

    # 6. 호스트에는 nginx 포트만 열려 있다
    for port in (8000, 8100, 9000):
        check(f"호스트 127.0.0.1:{port} 닫힘", port_closed(port))

    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
