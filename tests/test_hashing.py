import mcp.types as types

from linkud.verify.hashing import tool_hash
from tests.helpers import tool


def test_same_definition_same_hash():
    assert tool_hash(tool("a", "desc")) == tool_hash(tool("a", "desc"))


def test_schema_key_order_does_not_matter():
    s1 = {"type": "object", "properties": {"x": {"type": "string"}, "y": {"type": "integer"}}}
    s2 = {"properties": {"y": {"type": "integer"}, "x": {"type": "string"}}, "type": "object"}
    assert tool_hash(tool("a", input_schema=s1)) == tool_hash(tool("a", input_schema=s2))


def test_any_part_change_changes_hash():
    base = tool_hash(tool("a", "desc"))
    assert tool_hash(tool("a", "desc.")) != base  # 한 글자
    assert tool_hash(tool("b", "desc")) != base
    assert tool_hash(tool("a", "desc", title="T")) != base
    assert (
        tool_hash(tool("a", "desc", annotations=types.ToolAnnotations(readOnlyHint=True))) != base
    )
    schema = {"type": "object", "properties": {"p": {"type": "string", "description": "x"}}}
    assert tool_hash(tool("a", "desc", input_schema=schema)) != base
