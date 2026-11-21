"""(A) dashboard.py — 담당: A. 다른 사람은 고치지 않는다.

점수·등급·승인 버튼을 보여주는 웹 대시보드. (SPEC 8장)
게이트웨이와 별개 프로그램으로 실행하고, 같은 SQLite·감사 로그 파일을 읽는다.

실행:
    python -m gateway.dashboard          → http://127.0.0.1:8000

보안:
- 127.0.0.1에만 연다.
- 도구 이름·설명·근거는 공격자가 쓴 글일 수 있으므로 화면에 넣기 전에 전부 이스케이프한다(XSS 방지).
- 승인은 POST로만, 같은 출처(127.0.0.1/localhost)에서 온 요청만 받는다(다른 웹사이트가 몰래 승인시키는 CSRF 방지).
"""

import html
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from gateway import audit
from gateway.cache import TrustStore, Verdict

HOST = "127.0.0.1"
PORT = int(os.environ.get("LINKUD_DASHBOARD_PORT", "8000"))

LABEL = {"allow": ("허용", "ok"), "approved": ("승인됨", "ok"), "restrict": ("제한", "warn"),
         "block": ("차단", "bad"), "unknown": ("판정 없음", "bad")}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1f2328;--muted:#656d76;--line:#d0d7de;
--ok:#1a7f37;--okbg:#dafbe1;--warn:#9a6700;--warnbg:#fff8c5;--bad:#cf222e;--badbg:#ffebe9}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--text:#e6edf3;--muted:#8d96a0;
--line:#30363d;--ok:#3fb950;--okbg:#12261e;--warn:#d29922;--warnbg:#272115;--bad:#f85149;--badbg:#2d1214}}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,'Malgun Gothic',sans-serif;
background:var(--bg);color:var(--text);font-size:14px}
main{max-width:1200px;margin:0 auto;padding:24px 16px}h1{font-size:20px;margin:0 0 4px}
h2{font-size:16px;margin:28px 0 10px}.sub{color:var(--muted);margin:0 0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow-x:auto}
table{width:100%;border-collapse:collapse}th,td{padding:8px 10px;border-bottom:1px solid var(--line);
text-align:left;vertical-align:top}th{color:var(--muted);font-weight:500;white-space:nowrap}
tr:last-child td{border-bottom:none}.pill{display:inline-block;padding:2px 8px;border-radius:99px;
font-size:12px;font-weight:600;white-space:nowrap}.ok{color:var(--ok);background:var(--okbg)}
.warn{color:var(--warn);background:var(--warnbg)}.bad{color:var(--bad);background:var(--badbg)}
code{font-family:ui-monospace,Consolas,monospace;font-size:12px}.muted{color:var(--muted)}
ul{margin:0;padding-left:18px}button{font:inherit;padding:4px 12px;border-radius:6px;cursor:pointer;
border:1px solid var(--ok);background:var(--ok);color:#fff}
form.search{display:flex;gap:8px;margin-bottom:12px}input{font:inherit;padding:5px 8px;border-radius:6px;
border:1px solid var(--line);background:var(--card);color:var(--text);width:220px}
.empty{padding:16px;color:var(--muted)}.score{font-variant-numeric:tabular-nums}
"""


def esc(x) -> str:
    return html.escape(str(x), quote=True)


def pill(state: str) -> str:
    label, cls = LABEL.get(state, (state, "bad"))
    return f'<span class="pill {cls}">{esc(label)}</span>'


def verdict_rows(vs: list[Verdict], with_button: bool) -> str:
    if not vs:
        return '<div class="empty">없음</div>'
    rows = []
    for v in vs:
        btn = ""
        if with_button:
            btn = (f'<form method="post" action="/approve"><input type="hidden" name="server" value="{esc(v.server)}">'
                   f'<input type="hidden" name="hash" value="{esc(v.hash)}"><button>승인</button></form>')
        reasons = "".join(f"<li>{esc(r)}</li>" for r in v.reasons)
        signals = ", ".join(f"<code>{esc(s)}</code>" for s in v.signals) or '<span class="muted">-</span>'
        rows.append(
            f"<tr><td>{pill(v.effective)}</td><td class='score'>{v.score}</td>"
            f"<td>{esc(v.server)}</td><td><b>{esc(v.tool)}</b><br><code class='muted'>{esc(v.hash[:12])}</code></td>"
            f"<td>{signals}</td><td><ul>{reasons}</ul></td><td class='muted'>{esc(v.created_at)}</td>"
            + (f"<td>{btn}</td>" if with_button else "") + "</tr>")
    head = ("<tr><th>상태</th><th>점수</th><th>서버</th><th>도구</th><th>신호</th><th>근거</th><th>판정 시각</th>"
            + ("<th></th>" if with_button else "") + "</tr>")
    return f"<div class='card'><table>{head}{''.join(rows)}</table></div>"


def audit_rows(recs: list[dict]) -> str:
    if not recs:
        return '<div class="empty">없음</div>'
    rows = []
    for r in recs:
        detail = r.get("ref") or r.get("error") or (f"{r.get('score')}점" if "score" in r else "")
        state = r.get("grade", "")
        rows.append(f"<tr><td class='muted'>{esc(r.get('ts', ''))}</td><td><code>{esc(r.get('event', ''))}</code></td>"
                    f"<td>{esc(r.get('server', ''))}</td><td>{esc(r.get('tool', ''))}</td>"
                    f"<td>{pill(state) if state else ''}</td><td><code>{esc(detail)}</code></td></tr>")
    return ("<div class='card'><table><tr><th>시각</th><th>이벤트</th><th>서버</th><th>도구</th><th>등급</th>"
            f"<th>참조번호·비고</th></tr>{''.join(rows)}</table></div>")


def render(store: TrustStore, ref: str = "", notice: str = "") -> str:
    all_v = store.all()
    pending = [v for v in all_v if v.grade == "restrict" and not v.approved]
    ref_html = ""
    if ref:
        found = audit.find_ref(ref)
        extra = ""
        for rec in found:
            v = store.get(rec.get("server", ""), rec.get("hash") or "")
            if v:
                extra = "<h2>그 도구의 판정</h2>" + verdict_rows([v], False)
        ref_html = f"<h2>참조번호 {esc(ref)} 조회</h2>" + audit_rows(found) + extra
    note = f"<p class='pill ok'>{esc(notice)}</p>" if notice else ""
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="5">
<title>링커드 게이트웨이 대시보드</title><style>{CSS}</style></head><body><main>
<h1>링커드 게이트웨이 대시보드</h1><p class="sub">5초마다 새로고침 · 도구 {len(all_v)}개 판정 · 승인 대기 {len(pending)}개</p>{note}
<form class="search" method="get" action="/"><input name="ref" placeholder="참조번호 (LK-...)" value="{esc(ref)}"><button>조회</button></form>
{ref_html}
<h2>승인 대기</h2>{verdict_rows(pending, True)}
<h2>전체 판정</h2>{verdict_rows(all_v, False)}
<h2>최근 기록</h2>{audit_rows(audit.read_recent(50))}
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    store: TrustStore = None  # serve()에서 채움

    def log_message(self, fmt, *args):
        sys.stderr.write("[dashboard] " + fmt % args + "\n")

    def _send(self, code: int, body: str, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path != "/":
            return self._send(404, "not found", "text/plain; charset=utf-8")
        q = parse_qs(url.query)
        self._send(200, render(self.store, q.get("ref", [""])[0].strip(), q.get("msg", [""])[0]))

    def _same_origin(self) -> bool:
        allowed = {f"http://{HOST}:{PORT}", f"http://localhost:{PORT}"}
        origin = self.headers.get("Origin")
        if origin:
            return origin in allowed
        referer = self.headers.get("Referer", "")
        return any(referer.startswith(a + "/") or referer == a for a in allowed)

    def do_POST(self):
        if urlparse(self.path).path != "/approve":
            return self._send(404, "not found", "text/plain; charset=utf-8")
        if not self._same_origin():
            return self._send(403, "다른 출처에서 온 승인 요청은 받지 않습니다.", "text/plain; charset=utf-8")
        length = min(int(self.headers.get("Content-Length", "0") or 0), 10_000)
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        server, h = form.get("server", [""])[0], form.get("hash", [""])[0]
        ok = self.store.approve(server, h)
        v = self.store.get(server, h)
        if ok:
            audit.write("approved", server=server, tool=v.tool if v else "", hash=h, grade="approved")
        msg = "승인했습니다" if ok else "승인할 수 없습니다 (제한 등급만 승인 가능)"
        from urllib.parse import quote
        self._send(303, "", headers={"Location": "/?msg=" + quote(msg)})


def serve() -> None:
    Handler.store = TrustStore()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"대시보드: http://{HOST}:{PORT}  (종료: Ctrl+C)", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    serve()
