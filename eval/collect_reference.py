"""정상 데이터 수집: MCP 공식 레퍼런스 서버의 도구 정의를 정적으로 추출한다.

패키지는 PyPI에서 휠을 내려받아 풀기만 하고 import·실행하지 않는다. 소스를 AST로 읽어
`@server.tool(name=..., description=..., annotations=...)` 데코레이터와 함수 인자의
`Annotated[T, Field(description=...)]`에서 이름·설명·annotations·인자 설명을 꺼낸다.
설명 문자열은 원문 그대로이고(f-string 자리표시자는 `{이름}`으로 남김), inputSchema의
타입 정보는 소스에서 재구성한 것이다.

npm 레퍼런스 서버는 tarball을 풀지 않고 메모리에서 dist/*.js를 읽어
`registerTool("이름", { description: ..., annotations: {...} })` 형태만 정규식으로 꺼낸다
(인자 설명은 zod 체인이라 생략).

    uv run python eval/collect_reference.py    # → eval/data/benign_reference.json
"""

from __future__ import annotations

import ast
import asyncio
import io
import json
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import httpx

PACKAGES = ["mcp-server-git", "mcp-server-time", "mcp-server-fetch"]
NPM_PACKAGES = [
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-memory",
]
OUT = Path(__file__).parent / "data" / "benign_reference.json"

_TYPES = {"str": "string", "int": "integer", "float": "number", "bool": "boolean"}


class _Module:
    def __init__(self, tree: ast.Module) -> None:
        self.tree = tree
        self.consts: dict[str, ast.expr] = {}
        self.enums: dict[str, dict[str, str]] = {}
        self.funcs: dict[str, ast.FunctionDef] = {}
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                self.consts[node.targets[0].id] = node.value
            elif isinstance(node, ast.ClassDef):
                members = {
                    s.targets[0].id: s.value.value
                    for s in node.body
                    if isinstance(s, ast.Assign)
                    and isinstance(s.targets[0], ast.Name)
                    and isinstance(s.value, ast.Constant)
                    and isinstance(s.value.value, str)
                }
                if members:
                    self.enums[node.name] = members
            elif isinstance(node, ast.FunctionDef):
                self.funcs[node.name] = node

    def text(self, node: ast.expr | None) -> str | None:
        """문자열 식을 원문으로 푼다. f-string 자리표시자는 {식}으로 남긴다."""
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    parts.append(str(v.value))
                elif isinstance(v, ast.FormattedValue):
                    inner = (
                        self.text(v.value)
                        if isinstance(v.value, ast.Name) and v.value.id in self.consts
                        else None
                    )
                    parts.append(inner if inner is not None else "{" + ast.unparse(v.value) + "}")
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.text(node.left), self.text(node.right)
            return None if left is None or right is None else left + right
        if isinstance(node, ast.Name) and node.id in self.consts:
            return self.text(self.consts[node.id])
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "value"
            and isinstance(node.value, ast.Attribute)
        ):
            enum = node.value.value
            if isinstance(enum, ast.Name) and enum.id in self.enums:
                return self.enums[enum.id].get(node.value.attr)
        return None

    def annotations(self, node: ast.expr | None) -> dict[str, Any] | None:
        if node is None:
            return None
        if isinstance(node, ast.Name) and node.id in self.consts:
            return self.annotations(self.consts[node.id])
        if isinstance(node, ast.Call):
            fn = ast.unparse(node.func)
            kwargs = {k.arg: k.value for k in node.keywords if k.arg}
            if fn.endswith("ToolAnnotations"):
                out = {}
                for py, js in (
                    ("read_only_hint", "readOnlyHint"),
                    ("destructive_hint", "destructiveHint"),
                    ("idempotent_hint", "idempotentHint"),
                    ("open_world_hint", "openWorldHint"),
                ):
                    if py in kwargs and isinstance(kwargs[py], ast.Constant):
                        out[js] = kwargs[py].value
                return out
            if fn in self.funcs:
                # 도우미 함수가 ToolAnnotations를 만들어 돌려주는 경우: 리터럴 인자를 대입한다
                for ret in ast.walk(self.funcs[fn]):
                    if isinstance(ret, ast.Return) and isinstance(ret.value, ast.Call):
                        base = self.annotations(ret.value) or {}
                        args = [a.arg for a in self.funcs[fn].args.args]
                        bound = dict(zip(args, node.args, strict=False)) | kwargs
                        for k in ret.value.keywords:
                            if isinstance(k.value, ast.Name) and isinstance(
                                bound.get(k.value.id), ast.Constant
                            ):
                                js = {
                                    "destructive_hint": "destructiveHint",
                                    "idempotent_hint": "idempotentHint",
                                }.get(k.arg or "")
                                if js:
                                    base[js] = bound[k.value.id].value
                        return base
        return None

    def param_schema(self, ann: ast.expr | None) -> tuple[dict[str, Any], str | None]:
        desc = None
        if isinstance(ann, ast.Subscript) and ast.unparse(ann.value) == "Annotated":
            elts = ann.slice.elts if isinstance(ann.slice, ast.Tuple) else [ann.slice]
            ann = elts[0]
            for meta in elts[1:]:
                if isinstance(meta, ast.Call) and ast.unparse(meta.func) == "Field":
                    desc = self.text(
                        next((k.value for k in meta.keywords if k.arg == "description"), None)
                    )
        schema: dict[str, Any] = {}
        src = ast.unparse(ann) if ann is not None else ""
        if src in _TYPES:
            schema["type"] = _TYPES[src]
        elif src.startswith(("list[", "List[")):
            schema["type"] = "array"
        elif src.startswith("Literal["):
            schema["enum"] = [e.value for e in ast.walk(ann) if isinstance(e, ast.Constant)]
        if desc:
            schema["description"] = desc
        return schema, desc

    def tools(self) -> list[dict[str, Any]]:
        out = []
        for fn in ast.walk(self.tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for dec in fn.decorator_list:
                if not (isinstance(dec, ast.Call) and ast.unparse(dec.func).endswith(".tool")):
                    continue
                kw = {k.arg: k.value for k in dec.keywords if k.arg}
                name = self.text(kw.get("name")) or fn.name
                props, required = {}, []
                args = fn.args.args
                defaults = [None] * (len(args) - len(fn.args.defaults)) + list(fn.args.defaults)
                for arg, default in zip(args, defaults, strict=True):
                    if arg.arg in ("self", "ctx", "context"):
                        continue
                    props[arg.arg], _ = self.param_schema(arg.annotation)
                    if default is None:
                        required.append(arg.arg)
                tool: dict[str, Any] = {
                    "name": name,
                    "description": self.text(kw.get("description")) or ast.get_docstring(fn),
                    "inputSchema": {"type": "object", "properties": props, "required": required},
                }
                if (ann := self.annotations(kw.get("annotations"))) is not None:
                    tool["annotations"] = ann
                out.append(tool)
        return out


async def collect(http: httpx.AsyncClient, package: str) -> list[dict[str, Any]]:
    meta = (await http.get(f"https://pypi.org/pypi/{package}/json")).json()
    version = meta["info"]["version"]
    wheel = next(u["url"] for u in meta["urls"] if u["packagetype"] == "bdist_wheel")
    data = (await http.get(wheel)).content
    tools = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            if name.endswith(".py"):
                module = _Module(ast.parse(zf.read(name).decode("utf-8")))
                for t in module.tools():
                    tools.append({"source": f"pypi:{package}@{version}", "tool": t})
    return tools


_JS_TOOL = re.compile(r"registerTool\(\s*[\"'`]([\w-]+)[\"'`]\s*,\s*\{")
_JS_STR = r"(?:`((?:[^`\\]|\\.)*)`|\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)')"
_JS_DESC = re.compile(r"\bdescription:\s*" + _JS_STR)
_JS_HINT = re.compile(
    r"\b(readOnlyHint|destructiveHint|idempotentHint|openWorldHint):\s*(true|false)"
)


def js_tools(source: str) -> list[dict[str, Any]]:
    out = []
    matches = list(_JS_TOOL.finditer(source))
    for i, m in enumerate(matches):
        body = source[m.end() : matches[i + 1].start() if i + 1 < len(matches) else len(source)]
        desc = _JS_DESC.search(body)
        if desc is None or "${" in (desc.group(1) or ""):
            continue  # 템플릿 치환이 있는 설명은 원문을 확정할 수 없어 건너뜀
        text = next(g for g in desc.groups() if g is not None)
        text = (
            json.loads('"' + text.replace('"', '\\"').replace("\n", "\\n") + '"')
            if "\\" in text
            else text
        )
        tool: dict[str, Any] = {
            "name": m.group(1),
            "description": text,
            "inputSchema": {"type": "object", "properties": {}},
        }
        hints = {
            k: v == "true"
            for k, v in _JS_HINT.findall(body[: body.find("async") if "async" in body else None])
        }
        if hints:
            tool["annotations"] = hints
        out.append(tool)
    return out


async def collect_npm(http: httpx.AsyncClient, package: str) -> list[dict[str, Any]]:
    resp = await http.get(f"https://registry.npmjs.org/{package}/latest")
    if resp.status_code != 200:
        print(f"건너뜀: {package} (HTTP {resp.status_code})")
        return []
    meta = resp.json()
    data = (await http.get(meta["dist"]["tarball"])).content
    tools = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for member in tf.getmembers():
            if member.isfile() and member.name.endswith(".js") and "/dist/" in member.name:
                f = tf.extractfile(member)
                if f is not None:
                    for t in js_tools(f.read().decode("utf-8", "replace")):
                        tools.append({"source": f"npm:{package}@{meta['version']}", "tool": t})
    return tools


async def main() -> None:
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as http:
        results = [t for p in PACKAGES for t in await collect(http, p)]
        results += [t for p in NPM_PACKAGES for t in await collect_npm(http, p)]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{len(results)}개 도구 → {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
