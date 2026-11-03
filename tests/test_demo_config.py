"""시연 구성(demo/docker-compose.yml, nginx, 게이트웨이 설정·시작 스크립트)을 정적으로 검사한다."""

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import yaml

from linkud.config import load_config

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "demo"
COMPOSE = yaml.safe_load((DEMO / "docker-compose.yml").read_text(encoding="utf-8"))
SERVICES = COMPOSE["services"]
NGINX = (DEMO / "nginx/demo.conf.template").read_text(encoding="utf-8")

sys.path.insert(0, str(DEMO))
import init_secrets  # noqa: E402

# --- compose -------------------------------------------------------------------


def test_only_nginx_publishes_a_loopback_port():
    published = {name: s["ports"] for name, s in SERVICES.items() if "ports" in s}
    assert list(published) == ["nginx"]
    (port,) = published["nginx"]
    assert port.startswith("127.0.0.1:")


def test_mcp_servers_are_isolated():
    nets = COMPOSE["networks"]
    for name in ("translator", "notes", "rugpull"):
        s = SERVICES[name]
        assert s["build"]["dockerfile"] == "demo/servers/Dockerfile"
        assert s["read_only"] is True and s["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in s["security_opt"]
        # 내부 네트워크에만 붙어 인터넷으로 나갈 수 없다
        assert s["networks"] == ["back"] and nets["back"]["internal"] is True
        assert "volumes" not in s  # 토큰 볼륨을 받지 않는다
    assert nets["front"]["internal"] is True


def test_secrets_volume_only_where_needed():
    holders = {
        name
        for name, s in SERVICES.items()
        if any(str(v).startswith("demo-secrets:") for v in s.get("volumes", []))
    }
    assert holders == {"secrets", "gateway", "driver", "nginx"}
    for name in ("gateway", "driver", "nginx"):
        vols = [str(v) for v in SERVICES[name]["volumes"] if str(v).startswith("demo-secrets:")]
        assert all(v.endswith(":ro") for v in vols)
        assert SERVICES[name]["depends_on"]["secrets"]["condition"] == (
            "service_completed_successfully"
        )


def test_hardened_services():
    for name in ("gateway", "driver", "nginx", "secrets"):
        s = SERVICES[name]
        assert s["read_only"] is True and s["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in s["security_opt"]
    # nginx는 작업 프로세스 사용자 전환에 필요한 권한만 다시 받는다
    assert set(SERVICES["nginx"].get("cap_add", [])) <= {"CHOWN", "SETUID", "SETGID"}
    for name in ("gateway", "driver"):
        assert SERVICES[name]["mem_limit"] and SERVICES[name]["pids_limit"]


def test_nginx_refuses_to_start_without_admin_token():
    cmd = SERVICES["nginx"]["entrypoint"][-1]
    assert (
        'DEMO_ADMIN_TOKEN="$$(cat /demo-secrets/admin.nginx)" && export DEMO_ADMIN_TOKEN && exec'
        in cmd
    )


def test_judge_mode_follows_api_key_presence():
    gw = SERVICES["gateway"]["environment"]
    assert gw["ANTHROPIC_API_KEY"] == "${ANTHROPIC_API_KEY:-}"
    # 드라이버는 키를 받지 않고, 키가 있는지만 같은 조건으로 안다
    drv = SERVICES["driver"]["environment"]
    assert drv["DEMO_JUDGE"] == "${ANTHROPIC_API_KEY:+claude}"
    assert "ANTHROPIC_API_KEY" not in drv
    assert "egress" in SERVICES["gateway"]["networks"]
    assert "egress" not in SERVICES["driver"]["networks"]


def test_no_literal_tokens_in_compose():
    text = (DEMO / "docker-compose.yml").read_text(encoding="utf-8")
    assert "LINKUD_AUTH_TOKENS:" not in text and "LINKUD_ADMIN_TOKENS:" not in text
    assert "LINKUD_AGENT_TOKEN:" not in text


# --- 게이트웨이 설정·시작 스크립트 --------------------------------------------------


def test_gateway_configs_differ_only_in_judge():
    fake = load_config(DEMO / "gateway/config.fake.yaml")
    claude = load_config(DEMO / "gateway/config.claude.yaml")
    assert fake.judge == "fake" and claude.judge == "claude"
    assert {d.name for d in fake.downstreams} == {"translator", "notes", "rugpull"}
    assert fake.supply_enabled is False and fake.break_glass_enabled is False
    assert fake.db_path.startswith("/tmp/")
    a, b = vars(fake).copy(), vars(claude).copy()
    a.pop("judge"), b.pop("judge")
    assert a == b


def _run_start(tmp_path, env_extra):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "agent").write_text("AGENT-T")
    (secrets / "admin").write_text("ADMIN-T")
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    linkud = fakebin / "linkud"
    linkud.write_text(
        '#!/bin/sh\necho "args=$*"\necho "auth=$LINKUD_AUTH_TOKENS admin=$LINKUD_ADMIN_TOKENS"\n'
        'echo "key=${ANTHROPIC_API_KEY:-none}"\n'
    )
    linkud.chmod(linkud.stat().st_mode | stat.S_IEXEC)
    env = {
        "PATH": f"{fakebin}:{os.environ['PATH']}",
        "DEMO_SECRETS_DIR": str(secrets),
        "DEMO_CONFIG_DIR": "/cfg",
        **env_extra,
    }
    out = subprocess.run(
        ["sh", str(DEMO / "gateway/start.sh")], env=env, capture_output=True, text=True, check=True
    )
    return out.stdout


def test_start_script_picks_fake_without_key(tmp_path):
    out = _run_start(tmp_path, {})
    assert "args=--config /cfg/config.fake.yaml" in out
    assert "auth=AGENT-T admin=ADMIN-T" in out


def test_start_script_picks_claude_with_key(tmp_path):
    out = _run_start(tmp_path, {"ANTHROPIC_API_KEY": "sk-test"})
    assert "args=--config /cfg/config.claude.yaml" in out


def test_start_script_fails_without_secrets(tmp_path):
    env = {"PATH": os.environ["PATH"], "DEMO_SECRETS_DIR": str(tmp_path / "missing")}
    r = subprocess.run(["sh", str(DEMO / "gateway/start.sh")], env=env, capture_output=True)
    assert r.returncode != 0


# --- 토큰 생성 ----------------------------------------------------------------------


def test_init_secrets_writes_fresh_private_tokens(tmp_path):
    me = os.getuid()
    init_secrets.write_tokens(tmp_path, uid=me, gid=os.getgid(), nginx_uid=me)
    first = {n: (tmp_path / n).read_text() for n in ("agent", "admin")}
    assert len(set(first.values())) == 2 and all(len(v) >= 32 for v in first.values())
    assert (tmp_path / "admin.nginx").read_text() == first["admin"]
    for n in ("agent", "admin", "admin.nginx"):
        assert stat.S_IMODE((tmp_path / n).stat().st_mode) == 0o400
    init_secrets.write_tokens(tmp_path, uid=me, gid=os.getgid(), nginx_uid=me)
    assert {n: (tmp_path / n).read_text() for n in first} != first  # 띄울 때마다 새로


# --- nginx -------------------------------------------------------------------------


def _location(pattern: str) -> str:
    m = re.search(r"location\s+" + pattern + r"\s*\{(.*?)\n    \}", NGINX, re.S)
    assert m, pattern
    return m.group(1)


def test_admin_proxy_is_get_only_with_server_side_token():
    block = _location(re.escape("~ ^/api/admin/(audit|verdicts|servers)$"))
    assert re.search(r"limit_except GET \{\s*deny all;\s*\}", block)
    assert 'proxy_set_header Authorization "Bearer ${DEMO_ADMIN_TOKEN}";' in block
    assert "proxy_pass http://linkud_gateway/admin/$1$is_args$args;" in block


def test_other_api_paths_are_closed():
    assert "return 404;" in _location(re.escape("/api/"))


def test_driver_proxy_drops_client_auth():
    block = _location(re.escape("/driver/"))
    assert 'proxy_set_header Authorization "";' in block
    assert re.search(r"limit_except GET POST \{\s*deny all;\s*\}", block)


def test_static_page_headers():
    assert "server_tokens off;" in NGINX
    csp = re.search(r'Content-Security-Policy "([^"]+)"', NGINX).group(1)
    assert "script-src 'self'" in csp and "default-src 'none'" in csp
    assert "unsafe-inline" not in csp and "http" not in csp
    for h in ("X-Content-Type-Options nosniff", "frame-ancestors 'none'", "Referrer-Policy"):
        assert h in NGINX
    # 위치별 add_header가 있으면 서버 단위 보안 헤더가 사라지므로 두지 않는다
    directives = re.findall(r"^(\s*)add_header", NGINX, re.M)
    assert directives and all(indent == "    " for indent in directives)
