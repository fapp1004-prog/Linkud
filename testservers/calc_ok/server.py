"""(C) calc_ok — 정상 덧셈 서버. 기대 결과: 허용. (SPEC 10장)

표준 라이브러리만 쓰는 stdio JSON-RPC 서버. stdout에는 JSON 응답 말고 아무것도 출력하지 않는다
(디버깅은 print(..., file=sys.stderr)).
"""
import json
import sys

NAME, VERSION = "calc-ok", "1.0.0"
TOOLS = [{
    "name": "add",
    "description": "두 수를 더한다.",
    "inputSchema": {"type": "object",
                    "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
                    "required": ["a", "b"]},
}]


def call(name, args):
    if name == "add":
        return str(args["a"] + args["b"])
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
