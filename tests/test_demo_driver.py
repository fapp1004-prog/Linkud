"""시연 드라이버(demo/driver): 고정 시나리오만 수행하고 토큰을 내보내지 않는지 본다.

실제 게이트웨이와 시연용 MCP 서버를 프로세스 안에서 띄워 종단 간으로 확인한다(외부 네트워크 없음).
"""

import json
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path

import httpx
import pytest

from linkud.config import parse_config
from linkud.enforcement.guard import DENY_TEMPLATE
from linkud.enforcement.refs import REF_PATTERN
from linkud.proxy.gateway import create_app
from linkud.store.memory import MemoryStore
from tests.helpers import free_port, serve

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "demo" / "servers"))
sys.path.insert(0, str(ROOT / "demo" / "driver"))

import demo_driver  # noqa: E402
import demo_server  # noqa: E402

AGENT = "demo-agent-token-0123456789"
ADMIN = "demo-admin-token-0123456789"
RESULTS = json.loads((ROOT / "eval/results/results.json").read_text(encoding="utf-8"))


def settings(gateway, translator, rugpull, judge="fake"):
    return demo_driver.Settings(
        gateway_url=f"{gateway}/mcp",
        translator_url=f"{translator}/mcp",
        rugpull_url=rugpull,
        agent_token=AGENT,
        judge=judge,
        results_path=ROOT / "eval/results/results.json",
    )


@asynccontextmanager
async def stack(monkeypatch, judge="fake"):
    monkeypatch.setenv("LINKUD_AUTH_TOKENS", AGENT)
    monkeypatch.setenv("LINKUD_ADMIN_TOKENS", ADMIN)
    async with AsyncExitStack() as es:
        urls = {}
        for role in demo_server.ROLES:
            urls[role] = await es.enter_async_context(serve(demo_server.make_app(role)))
        cfg = parse_config(
            {
                "gateway": {"judge": "fake", "supply_enabled": False, "no_supply_info": "record"},
                "downstreams": [{"name": r, "url": f"{u}/mcp"} for r, u in urls.items()],
            }
        )
        gw = await es.enter_async_context(serve(create_app(cfg, store=MemoryStore())))
        app = demo_driver.make_app(settings(gw, urls["translator"], urls["rugpull"], judge))
        drv = await es.enter_async_context(serve(app))
        http = await es.enter_async_context(httpx.AsyncClient(base_url=drv, timeout=30))
        yield http, gw


async def test_scene3_denies_translate_with_real_ref(monkeypatch):
    async with stack(monkeypatch) as (http, gw):
        r = await http.post("/driver/scene/3")
        assert r.status_code == 200
        body = r.json()
        assert "translator__translate" not in body["visible"]
        assert "notes__list_notes" in body["visible"]
        assert body["attempted"] == "translator__translate"
        assert body["denied"] is True
        assert REF_PATTERN.fullmatch(body["ref"])
        assert body["message"] == DENY_TEMPLATE.format(ref=body["ref"])
        # 그 번호가 감사 로그에서 실제로 조회된다
        async with httpx.AsyncClient() as admin:
            found = await admin.get(
                f"{gw}/admin/audit",
                params={"ref": body["ref"]},
                headers={"Authorization": f"Bearer {ADMIN}"},
            )
        assert found.status_code == 200
        event = found.json()[0]
        assert (event["server"], event["tool"], event["kind"]) == (
            "translator",
            "translate",
            "call_denied",
        )


async def test_scene1_lists_tools_directly_without_linkud(monkeypatch):
    async with stack(monkeypatch) as (http, _):
        body = (await http.get("/driver/scene/1")).json()
        assert body["tools"] == ["translate"]


async def test_raw_tool_is_real_definition_with_rule_highlights(monkeypatch):
    async with stack(monkeypatch) as (http, _):
        body = (await http.get("/driver/raw-tool")).json()
        sample = demo_server.sample_tool(demo_server.TRANSLATOR_SAMPLE)
        assert body["name"] == "translate"
        assert body["description"] == sample["description"]
        assert body["inputSchema"] == sample["inputSchema"]
        assert body["highlights"]
        for h in body["highlights"]:
            assert 0 <= h["start"] < h["end"] <= len(body["description"])
        marked = " ".join(body["description"][h["start"] : h["end"]] for h in body["highlights"])
        assert "id_rsa" in marked


async def test_eval_numbers_come_from_results_file(monkeypatch):
    async with stack(monkeypatch) as (http, _):
        body = (await http.get("/driver/eval")).json()
        rules = RESULTS["detection"]["summary"]["rules"]
        assert body["detection"] == {"found": rules["tp"], "total": rules["p"]}
        assert body["false_positive"] == {"count": rules["fp"], "total": rules["n"]}
        rug = RESULTS["rugpull"][0]
        assert body["rugpull"] == {"hidden": rug["hidden_after_change"], "total": rug["total"]}
        assert body["measured_at"] == RESULTS["meta"]["time"]


async def test_scene5_rugpull_hides_tool_after_change(monkeypatch):
    async with stack(monkeypatch) as (http, _):
        before = (await http.post("/driver/scene/5/before")).json()
        assert before["visible_tool"] is True
        after = (await http.post("/driver/scene/5/after")).json()
        assert after["visible_tool"] is False
        assert after["description"] != before["description"]
        # 리허설을 다시 해도 같은 결과
        again = (await http.post("/driver/scene/5/before")).json()
        assert again["visible_tool"] is True


@pytest.mark.parametrize("judge", ["claude", "fake", "", "anything"])
async def test_status_reports_judge_mode_fail_closed(monkeypatch, judge):
    async with stack(monkeypatch, judge=judge) as (http, _):
        body = (await http.get("/driver/status")).json()
        assert body["judge"] == ("claude" if judge == "claude" else "fake")
        assert body["gateway"] is True


async def test_only_fixed_scenarios_are_accepted(monkeypatch):
    async with stack(monkeypatch) as (http, _):
        bad = [
            http.post("/driver/scene/3", json={"tool": "translator__translate", "arguments": {}}),
            http.post("/driver/scene/3", content=b"x"),
            http.post("/driver/scene/3?tool=notes__save_note"),
            http.get("/driver/raw-tool?name=save_note"),
        ]
        for req in bad:
            assert (await req).status_code == 400
        assert (await http.post("/driver/scene/4")).status_code == 404
        assert (await http.post("/driver/call")).status_code == 404
        assert (await http.get("/driver/scene/3")).status_code == 405
        assert (await http.post("/driver/raw-tool")).status_code == 405


async def test_token_never_appears_in_responses(monkeypatch):
    async with stack(monkeypatch) as (http, _):
        calls = [
            http.get("/driver/status"),
            http.get("/driver/scene/1"),
            http.get("/driver/raw-tool"),
            http.get("/driver/eval"),
            http.post("/driver/scene/3"),
            http.post("/driver/scene/5/before"),
            http.post("/driver/scene/5/after"),
            http.post("/driver/scene/3", json={"x": 1}),
            http.get("/driver/nope"),
        ]
        for req in calls:
            r = await req
            assert AGENT not in r.text
            assert AGENT not in json.dumps(dict(r.headers))


async def test_gateway_down_reports_disconnected_without_details():
    dead = f"http://127.0.0.1:{free_port()}"
    app = demo_driver.make_app(settings(dead, dead, dead))
    async with serve(app) as drv, httpx.AsyncClient(base_url=drv, timeout=30) as http:
        r = await http.post("/driver/scene/3")
        assert r.status_code == 502
        assert r.json() == {"error": "연결 끊김"}
        status = (await http.get("/driver/status")).json()
        assert status["gateway"] is False


def test_settings_require_agent_token():
    with pytest.raises(SystemExit):
        demo_driver.settings_from_env({"DEMO_JUDGE": "fake"})
    s = demo_driver.settings_from_env({"LINKUD_AGENT_TOKEN": AGENT, "DEMO_JUDGE": "claude"})
    assert s.agent_token == AGENT and s.judge == "claude"
    assert AGENT not in repr(s)
