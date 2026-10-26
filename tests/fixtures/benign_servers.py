"""정상(benign) 테스트 MCP 서버.

호스트에서 실행해도 안전한 서버만 둔다. 오염 서버는 `poisoned_servers/`에 있고
Docker 안에서만 실행한다.

수동 실행: `uv run python -m tests.fixtures.benign_servers math 8001`
"""

from __future__ import annotations

import sys

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations


def make_math_server() -> MCPServer:
    server = MCPServer("math")

    @server.tool(description="Add two integers and return the sum.")
    def add(a: int, b: int) -> int:
        return a + b

    @server.tool(description="Multiply two integers and return the product.")
    def multiply(a: int, b: int) -> int:
        return a * b

    return server


def make_notes_server() -> MCPServer:
    """읽기·쓰기 도구가 섞인 서버 (권한 매핑 테스트용)."""
    server = MCPServer("notes")
    notes: dict[str, str] = {"welcome": "hello"}

    @server.tool(
        description="List the titles of all notes.",
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    def list_notes() -> list[str]:
        return sorted(notes)

    @server.tool(
        description="Read the content of a note by title.",
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    def read_note(title: str) -> str:
        return notes.get(title, "")

    @server.tool(
        description="Create or overwrite a note.",
        annotations=ToolAnnotations(readOnlyHint=False),
    )
    def create_note(title: str, content: str) -> str:
        notes[title] = content
        return "ok"

    @server.tool(
        description="Delete a note by title.",
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True),
    )
    def delete_note(title: str) -> str:
        notes.pop(title, None)
        return "ok"

    return server


def make_mutable_server(state: dict[str, str]):
    """설명이 바뀌는 서버 (러그풀 테스트용). `state["description"]`을 바꾸면 다음 목록에 반영된다.

    바뀐 설명도 정상 문장만 쓴다. 악성 설명을 담은 서버는 `poisoned_servers/`에 둔다.
    """
    import mcp.types as types
    from mcp.server.lowlevel import Server

    async def on_list_tools(ctx, params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="echo",
                    description=state["description"],
                    input_schema={"type": "object", "properties": {"text": {"type": "string"}}},
                )
            ]
        )

    async def on_call_tool(ctx, params):
        text = (params.arguments or {}).get("text", "")
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

    return Server("mutable", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


SERVERS = {"math": make_math_server, "notes": make_notes_server}


if __name__ == "__main__":
    import uvicorn

    name, port = sys.argv[1], int(sys.argv[2])
    uvicorn.run(SERVERS[name]().streamable_http_app(), host="127.0.0.1", port=port)
