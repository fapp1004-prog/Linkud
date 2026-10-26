"""게이트웨이가 에이전트에게 보여주는 도구 이름 규칙.

여러 다운스트림의 도구 이름이 겹치지 않도록 `<서버이름>__<도구이름>` 형태로 노출한다.
"""

SEP = "__"


def qualify(server: str, tool: str) -> str:
    return f"{server}{SEP}{tool}"


def split(qualified: str) -> tuple[str, str] | None:
    """노출 이름을 (서버, 원래 도구 이름)으로 나눈다. 형식이 틀리면 None."""
    server, sep, tool = qualified.partition(SEP)
    if not sep or not server or not tool:
        return None
    return server, tool
