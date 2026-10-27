import pytest

from linkud.config import ConfigError, parse_config


def test_parse_minimal():
    cfg = parse_config(
        {"gateway": {"port": 9000}, "downstreams": [{"name": "math", "url": "http://x/mcp"}]}
    )
    assert cfg.port == 9000
    assert cfg.downstreams[0].name == "math"


@pytest.mark.parametrize(
    "ds",
    [
        {"name": "x", "command": "npx", "args": ["evil"]},  # stdio 금지
        {"name": "x", "url": "file:///etc/passwd"},
        {"name": "a__b", "url": "http://x/mcp"},  # 구분자 포함 이름
        {"name": "UPPER", "url": "http://x/mcp"},
    ],
)
def test_rejects_invalid_downstream(ds):
    with pytest.raises(ConfigError):
        parse_config({"downstreams": [ds]})


def test_rejects_duplicate_names():
    ds = {"name": "a", "url": "http://x/mcp"}
    with pytest.raises(ConfigError):
        parse_config({"downstreams": [ds, ds]})
