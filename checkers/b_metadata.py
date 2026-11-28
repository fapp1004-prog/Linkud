"""도구 정의 전체를 제한된 크기로 검증한다. label·정답은 호출자가 넣지 않는다."""
import json
import math

MAX_BYTES = 96_000
MAX_NODES = 12_000
MAX_DEPTH = 32


def canonical_tool(tool: dict) -> str:
    if not isinstance(tool, dict) or not isinstance(tool.get('name'), str) or not tool['name']:
        raise ValueError('도구에는 비어 있지 않은 name 문자열이 필요합니다.')
    if 'description' in tool and not isinstance(tool['description'], str):
        raise ValueError('description은 문자열이어야 합니다.')
    count = 0
    ancestors = set()

    def walk(node, depth):
        nonlocal count
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError('도구 정의의 크기 또는 중첩 제한을 넘었습니다.')
        if isinstance(node, (dict, list)):
            if id(node) in ancestors:
                raise ValueError('순환하는 도구 정의입니다.')
            ancestors.add(id(node))
            if isinstance(node, dict):
                for k, v in node.items():
                    if not isinstance(k, str):
                        raise ValueError('JSON 객체의 키는 문자열이어야 합니다.')
                    walk(k, depth + 1)
                    walk(v, depth + 1)
            else:
                for value in node:
                    walk(value, depth + 1)
            ancestors.remove(id(node))
        elif not (node is None or isinstance(node, (str, bool, int, float))):
            raise ValueError('JSON으로 표현할 수 없는 도구 정의입니다.')
        elif isinstance(node, float) and not math.isfinite(node):
            raise ValueError('NaN·Infinity는 허용하지 않습니다.')
        elif isinstance(node, str) and len(node) > MAX_BYTES:
            raise ValueError('도구 문자열이 너무 깁니다.')

    walk(tool, 0)
    text = json.dumps(tool, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    if len(text.encode('utf-8')) > MAX_BYTES:
        raise ValueError('도구 정의가 96KB를 넘었습니다. 내용을 자르지 않고 검사를 실패시킵니다.')
    return text


def text_fields(tool):
    """키 이름과 모든 문자열 값. inputSchema·annotations·outputSchema·확장 키 포함."""
    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                yield path + '/<key>', key
                yield from walk(value, path + '/' + key.replace('~', '~0').replace('/', '~1'))
        elif isinstance(node, list):
            for i, value in enumerate(node):
                yield from walk(value, path + '/' + str(i))
        elif isinstance(node, str):
            yield path, node
    yield from walk(tool, '')
