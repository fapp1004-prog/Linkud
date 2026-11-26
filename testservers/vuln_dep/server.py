"""(C) vuln_dep — 취약한 옛 라이브러리를 쓰는(척하는) 서버. (SPEC 10장)

같은 폴더의 requirements.txt에 심각(Critical/High) CVE가 있는 옛 버전을 '적어만' 둔다.
기대: 공급망 검사에서 critical_vuln → 제한 → 대시보드 승인 후 실행.

안전: 그 라이브러리를 설치·import하지 않는다. fetch는 네트워크를 쓰지 않고 가짜 응답만 준다.
"""
import json
import sys

NAME, VERSION = "vuln-dep", "1.0.0"
TOOLS = [{
    "name": "fetch",
    "description": "주어진 URL의 내용을 가져온다.",
    "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
}]


def call(name, args):
    if name == "fetch":
        return f"[가짜 응답] {str(args['url'])[:100]} 의 내용 (실제 네트워크 요청 없음)"
    raise KeyError(name)


def send(msg):
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main():
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        mid, method = msg.get("id"), msg.get("method")
        if mid is None:                       # 알림(id 없음)에는 답하지 않는다
            continue
        params = msg.get("params") or {}
        try:
            if method == "initialize":
                result = {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                          "capabilities": {"tools": {}},
                          "serverInfo": {"name": NAME, "version": VERSION}}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                text = call(params["name"], params.get("arguments") or {})
                result = {"content": [{"type": "text", "text": text}]}
            else:
                send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"unknown method: {method}"}})
                continue
        except (KeyError, TypeError) as e:
            send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"invalid params: {e}"}})
            continue
        send({"jsonrpc": "2.0", "id": mid, "result": result})


if __name__ == "__main__":
    main()
