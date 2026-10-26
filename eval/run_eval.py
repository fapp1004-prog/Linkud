"""기획서 8장 평가: 탐지 · 러그풀 · 권한 · 지연 · 판별기 내성.

    uv run python eval/run_eval.py                    # 규칙 필터만 (LLM 열은 미측정)
    uv run python eval/run_eval.py --judge claude     # Claude 판별기 포함 (ANTHROPIC_API_KEY 필요, 비용 발생)

결과: eval/results/results.json, eval/results/RESULTS.md
모든 서버·게이트웨이는 같은 프로세스 안에서 돈다. 오염 샘플은 데이터로만 주입하고
서버로 띄우지 않는다(오염 서버를 직접 띄우려면 tests/fixtures/poisoned_servers의 Docker 구성 사용).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp import Client

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from eval.samples import BENIGN_EXTRA, JUDGE_ATTACKS, POISONED, REFERENCE_WRITE_TOOLS  # noqa: E402
from linkud.config import parse_config  # noqa: E402
from linkud.enforcement.guard import Enforcer  # noqa: E402
from linkud.models import Tier  # noqa: E402
from linkud.proxy.gateway import Gateway, create_app  # noqa: E402
from linkud.store.memory import MemoryCache, MemoryStore  # noqa: E402
from linkud.verify.analyze import analyze  # noqa: E402
from linkud.verify.decision import NoSupplyInfo, Policy, SupplySignals, decide, is_read_tool  # noqa: E402
from linkud.verify.hashing import canonical_tool  # noqa: E402
from linkud.verify.judge.base import JudgeLabel, JudgeVerdict  # noqa: E402
from linkud.verify.judge.fake import FakeJudge  # noqa: E402
from linkud.verify.pipeline import PipelineVerifier  # noqa: E402
from linkud.verify.rules import Severity, scan  # noqa: E402
from linkud.verify.service import VerificationService  # noqa: E402
from tests.fixtures.benign_servers import make_math_server  # noqa: E402
from tests.helpers import serve  # noqa: E402

RESULTS = Path(__file__).parent / "results"
OK_SUPPLY = SupplySignals(available=True, reasons=["평가: 공급망 신호 제외"])
# 판별기가 완전히 속았다고 가정한 판별기 (규칙만으로 막는 비율을 보기 위함)
FOOLED = FakeJudge(default=JudgeVerdict(JudgeLabel.BENIGN, False, ["fooled"], 1.0))


def as_tool(d: dict[str, Any]) -> types.Tool:
    return types.Tool.model_validate(d)


def reference() -> list[dict[str, Any]]:
    return json.loads((Path(__file__).parent / "data" / "benign_reference.json").read_text())


class MemoJudge:
    """같은 정의는 한 번만 판별한다 (평가 비용 절감)."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.memo: dict[str, JudgeVerdict] = {}
        self.calls = 0

    async def judge(self, definition: dict[str, Any]) -> JudgeVerdict:
        key = json.dumps(definition, sort_keys=True, ensure_ascii=False)
        if key not in self.memo:
            self.calls += 1
            self.memo[key] = await self.inner.judge(definition)
        return self.memo[key]


def rate(n: int, d: int) -> str:
    return f"{n}/{d} ({100 * n / d:.1f}%)" if d else "-"


# --- 1. 탐지 --------------------------------------------------------------------


async def eval_detection(judge: MemoJudge | None) -> dict[str, Any]:
    positives = [(s["id"], s["category"], canonical_tool(as_tool(s["tool"]))) for s in POISONED]
    negatives = [
        (f"ref:{e['tool']['name']}", "reference", canonical_tool(as_tool(e["tool"])))
        for e in reference()
    ]
    negatives += [
        (s["id"], "benign_extra", canonical_tool(as_tool(s["tool"]))) for s in BENIGN_EXTRA
    ]

    async def flags(definition: dict[str, Any]) -> dict[str, bool | None]:
        out: dict[str, bool | None] = {"rules": scan(definition).severity is not Severity.NONE}
        if judge is None:
            out["llm"] = out["both"] = None
        else:
            out["llm"] = (await judge.judge(definition)).label is not JudgeLabel.BENIGN
            decision = decide(await analyze(definition, judge), OK_SUPPLY)
            out["both"] = decision.tier is not Tier.TRUSTED
        return out

    rows = []
    for sid, cat, d in positives:
        rows.append(
            {"id": sid, "category": cat, "label": "poisoned", "name": d["name"], **await flags(d)}
        )
    for sid, cat, d in negatives:
        rows.append(
            {"id": sid, "category": cat, "label": "benign", "name": d["name"], **await flags(d)}
        )

    summary = {}
    for mode in ("rules", "llm", "both"):
        if rows[0][mode] is None:
            summary[mode] = None
            continue
        tp = sum(r[mode] for r in rows if r["label"] == "poisoned")
        fp = sum(r[mode] for r in rows if r["label"] == "benign")
        p, n = len(positives), len(negatives)
        summary[mode] = {"tp": tp, "fn": p - tp, "fp": fp, "tn": n - fp, "p": p, "n": n}
    by_cat: dict[str, dict[str, list[bool]]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if r["label"] == "poisoned":
            for mode in ("rules", "llm", "both"):
                if r[mode] is not None:
                    by_cat[r["category"]][mode].append(r[mode])
    return {
        "summary": summary,
        "by_category": {
            c: {m: [sum(v), len(v)] for m, v in ms.items()} for c, ms in by_cat.items()
        },
        "false_positives": {
            m: [r["id"] for r in rows if r["label"] == "benign" and r[m]]
            for m in ("rules", "llm", "both")
            if rows[0][m] is not None
        },
        "false_negatives": {
            m: [r["id"] for r in rows if r["label"] == "poisoned" and not r[m]]
            for m in ("rules", "llm", "both")
            if rows[0][m] is not None
        },
    }


# --- 2. 러그풀 -------------------------------------------------------------------


class DataDownstream:
    def __init__(self, name: str, tools: list[types.Tool]) -> None:
        self.name = name
        self.tools = tools

    async def list_tools(self) -> list[types.Tool]:
        return list(self.tools)

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])


class StaticSupply:
    async def check(self, server: str) -> SupplySignals:
        return OK_SUPPLY


def gateway(
    downstreams: list[Any], judge: Any, policy: Policy | None = None
) -> tuple[Gateway, MemoryStore]:
    cache, store = MemoryCache(), MemoryStore()
    verifier = PipelineVerifier(judge, StaticSupply(), policy)
    service = VerificationService(verifier, cache, store, timeout=60)
    return Gateway(downstreams, Enforcer(service, cache, store)), store


async def eval_rugpull(judge: Any, label: str) -> dict[str, Any]:
    detected = hidden = scenarios = 0
    requests_to_hide: list[int] = []
    for s in POISONED:
        poisoned = as_tool(s["tool"])
        # 승인 시점의 정상 버전: 같은 이름, 오염 문자열이 없는 설명·스키마
        props = {k: {"type": "string"} for k in (poisoned.input_schema.get("properties") or {})}
        initial = poisoned.model_copy(
            update={
                "description": "Utility tool.",
                "title": None,
                "output_schema": None,
                "input_schema": {"type": "object", "properties": props},
            }
        )
        ds = DataDownstream("s", [initial])
        gw, store = gateway([ds], judge)
        before = await gw.list_tools()
        if not before:  # 처음부터 숨겨진 경우는 러그풀 시나리오가 성립하지 않음
            continue
        scenarios += 1
        ds.tools = [poisoned]
        for n in range(1, 4):
            if not await gw.list_tools():
                hidden += 1
                requests_to_hide.append(n)
                break
        detected += any(e.kind == "definition_changed" for e in store.events)
    total = scenarios
    return {
        "judge": label,
        "total": total,
        "change_detected": detected,
        "hidden_after_change": hidden,
        "requests_to_hide": requests_to_hide,
    }


# --- 3. 권한 ---------------------------------------------------------------------


async def eval_permission(judge: MemoJudge | None) -> dict[str, Any]:
    entries = reference()
    rows = []
    for e in entries:
        d = canonical_tool(as_tool(e["tool"]))
        truth_read = d["name"] not in REFERENCE_WRITE_TOOLS
        # (a) LLM 신호를 '읽기'로 고정: readOnlyHint·이름 두 신호만의 판별력
        two, _ = is_read_tool(d, await analyze(d, FOOLED))
        three = None
        if judge is not None:
            three, _ = is_read_tool(d, await analyze(d, judge))
        rows.append(
            {
                "name": d["name"],
                "source": e["source"],
                "truth_read": truth_read,
                "two_signal": two,
                "three_signal": three,
            }
        )

    def score(key: str) -> dict[str, Any] | None:
        if rows[0][key] is None:
            return None
        correct = sum(r[key] == r["truth_read"] for r in rows)
        reads = [r for r in rows if r["truth_read"]]
        return {
            "accuracy": [correct, len(rows)],
            "read_recall": [sum(r[key] for r in reads), len(reads)],
            "write_exposed": [r["name"] for r in rows if r[key] and not r["truth_read"]],
        }

    # 종단 간: 부분신뢰 서버에서 실제로 보이는 쓰기 도구 수 (LLM이 모든 도구를 읽기라고 속아도)
    by_server: dict[str, list[types.Tool]] = defaultdict(list)
    for e in entries:
        by_server[e["source"]].append(as_tool(e["tool"]))
    exposed: list[str] = []
    visible_total = 0
    for i, (_, tools) in enumerate(by_server.items()):
        gw, _ = gateway(
            [DataDownstream(f"s{i}", tools)], FOOLED, Policy(no_supply_info=NoSupplyInfo.PARTIAL)
        )
        gw.enforcer.service.verifier.supply = None  # 공급망 정보 없음 → 부분신뢰
        visible = await gw.list_tools()
        visible_total += len(visible)
        exposed += [t.name for t in visible if t.name.split("__", 1)[1] in REFERENCE_WRITE_TOOLS]
    return {
        "two_signal": score("two_signal"),
        "three_signal": score("three_signal"),
        "partial_e2e": {
            "servers": len(by_server),
            "visible": visible_total,
            "write_exposed": exposed,
        },
        "rows": rows,
    }


# --- 4. 지연 ---------------------------------------------------------------------


def pct(values: list[float], q: float) -> float:
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def stats(ms: list[float]) -> dict[str, float]:
    return {"n": len(ms), "mean": statistics.mean(ms), "p50": pct(ms, 0.5), "p95": pct(ms, 0.95)}


async def timed(fn: Any, n: int) -> list[float]:
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        await fn()
        out.append((time.perf_counter() - t0) * 1000)
    return out


async def throughput(url: str, tool: str, concurrency: int, total: int) -> float:
    per = total // concurrency

    async def worker() -> None:
        async with Client(url, cache=None) as c:
            await c.list_tools()
            for _ in range(per):
                await c.call_tool(tool, {"a": 1, "b": 2})

    t0 = time.perf_counter()
    await asyncio.gather(*(worker() for _ in range(concurrency)))
    return (per * concurrency) / (time.perf_counter() - t0)


async def eval_latency(
    judge: Any, label: str, n: int, concurrency: int, total: int
) -> dict[str, Any]:
    out: dict[str, Any] = {"judge": label, "n": n, "concurrency": concurrency, "total_calls": total}
    async with serve(make_math_server().streamable_http_app()) as math_url:
        target = f"{math_url}/mcp"
        cfg = parse_config(
            {"gateway": {"supply_enabled": False}, "downstreams": [{"name": "math", "url": target}]}
        )
        policy = Policy(no_supply_info=NoSupplyInfo.RECORD)

        async with Client(target, cache=None) as c:
            await c.list_tools()
            out["direct"] = {
                "list_tools": stats(await timed(c.list_tools, n)),
                "call_tool": stats(await timed(lambda: c.call_tool("add", {"a": 1, "b": 2}), n)),
            }
        out["direct"]["throughput_rps"] = await throughput(target, "add", concurrency, total)

        app = create_app(cfg, store=MemoryStore(), verifier=PipelineVerifier(judge, None, policy))
        async with serve(app) as gw_url, Client(f"{gw_url}/mcp", cache=None) as c:
            await c.list_tools()  # 첫 검증으로 캐시를 채운다
            out["gateway_cache_hit"] = {
                "list_tools": stats(await timed(c.list_tools, n)),
                "call_tool": stats(
                    await timed(lambda: c.call_tool("math__add", {"a": 1, "b": 2}), n)
                ),
            }
            out["gateway_cache_hit"]["throughput_rps"] = await throughput(
                f"{gw_url}/mcp", "math__add", concurrency, total
            )

        first: list[float] = []
        for _ in range(max(5, n // 10)):
            app = create_app(
                cfg, store=MemoryStore(), verifier=PipelineVerifier(judge, None, policy)
            )
            async with serve(app) as gw_url, Client(f"{gw_url}/mcp", cache=None) as c:
                t0 = time.perf_counter()
                await c.list_tools()
                first.append((time.perf_counter() - t0) * 1000)
        out["first_verification"] = {"list_tools": stats(first)}
    return out


# --- 5. 판별기 내성 ----------------------------------------------------------------


async def eval_judge_robustness(judge: MemoJudge | None) -> dict[str, Any]:
    rows = []
    for s in JUDGE_ATTACKS:
        d = canonical_tool(as_tool(s["tool"]))
        fooled = decide(await analyze(d, FOOLED), OK_SUPPLY)
        row = {
            "id": s["id"],
            "rules": scan(d).severity.value,
            "tier_if_llm_fooled": fooled.tier.value,
        }
        if judge is not None:
            verdict = await judge.judge(d)
            real = decide(await analyze(d, judge), OK_SUPPLY)
            row |= {
                "llm_label": verdict.label.value,
                "llm_confidence": verdict.confidence,
                "tier": real.tier.value,
            }
        rows.append(row)
    return {
        "rows": rows,
        "success_if_llm_fooled": [
            sum(r["tier_if_llm_fooled"] == "trusted" for r in rows),
            len(rows),
        ],
        "llm_fooled": None
        if judge is None
        else [sum(r["llm_label"] == "benign" for r in rows), len(rows)],
        "success": None
        if judge is None
        else [sum(r["tier"] == "trusted" for r in rows), len(rows)],
    }


# --- 보고서 ----------------------------------------------------------------------


def frac(x: list[int] | None) -> str:
    return "미측정" if x is None else rate(x[0], x[1])


def render(r: dict[str, Any]) -> str:
    det, rp, perm, lat, jr = (
        r["detection"],
        r["rugpull"],
        r["permission"],
        r["latency"],
        r["judge_robustness"],
    )
    lines = [
        "# Linkud 평가 결과",
        "",
        f"- 실행: {r['meta']['time']} · Python {r['meta']['python']} · 판별기: {r['meta']['judge']}",
        f"- 데이터: 오염 {len(POISONED)}개(직접 작성) · 정상 {det['summary']['rules']['n']}개"
        f"(MCP 공식 레퍼런스 서버 {len(reference())}개 + 오탐 유도 정상 문장 {len(BENIGN_EXTRA)}개) · 판별기 공격 {len(JUDGE_ATTACKS)}개",
        "- LLM 열이 '미측정'이면 API 키 없이 돌린 결과다. 수치는 이 데이터셋 기준이며 일반화하지 않는다.",
        "",
        "## 1. 탐지",
        "",
        "| 방식 | 탐지율 | 미탐률 | 오탐률 |",
        "| --- | --- | --- | --- |",
    ]
    names = {"rules": "규칙만", "llm": "LLM만", "both": "둘 다 (결정 테이블)"}
    for mode, s in det["summary"].items():
        if s is None:
            lines.append(f"| {names[mode]} | 미측정 | 미측정 | 미측정 |")
        else:
            lines.append(
                f"| {names[mode]} | {rate(s['tp'], s['p'])} | {rate(s['fn'], s['p'])} | {rate(s['fp'], s['n'])} |"
            )
    lines += [
        "",
        "유형별 탐지 (규칙 / LLM / 둘 다):",
        "",
        "| 유형 | 규칙 | LLM | 둘 다 |",
        "| --- | --- | --- | --- |",
    ]
    for cat, ms in det["by_category"].items():
        lines.append(
            f"| {cat} | {frac(ms.get('rules'))} | {frac(ms.get('llm'))} | {frac(ms.get('both'))} |"
        )
    for mode in det["false_negatives"]:
        lines.append(f"\n- {names[mode]} 미탐: {', '.join(det['false_negatives'][mode]) or '없음'}")
        lines.append(f"- {names[mode]} 오탐: {', '.join(det['false_positives'][mode]) or '없음'}")

    lines += [
        "",
        "## 2. 러그풀",
        "",
        "승인(신뢰) 후 설명을 오염 샘플로 바꾼 경우.",
        "",
        "| 판별기 | 변경 감지율(해시) | 변경 후 숨김률 | 노출까지 걸린 목록 요청 수 |",
        "| --- | --- | --- | --- |",
    ]
    for x in rp:
        reqs = f"최대 {max(x['requests_to_hide'])}회" if x["requests_to_hide"] else "-"
        lines.append(
            f"| {x['judge']} | {rate(x['change_detected'], x['total'])} | {rate(x['hidden_after_change'], x['total'])} | {reqs} |"
        )

    lines += [
        "",
        "## 3. 권한",
        "",
        f"레퍼런스 서버 도구 {len(perm['rows'])}개, 정답은 도구 의미로 직접 표기(쓰기 {len(REFERENCE_WRITE_TOOLS)}개).",
        "",
        "| 신호 | 읽기 판별 정확도 | 읽기 도구 허용률 | 쓰기인데 읽기로 판별 |",
        "| --- | --- | --- | --- |",
    ]
    for key, label in (
        ("two_signal", "readOnlyHint + 이름 (LLM은 '읽기'로 고정)"),
        ("three_signal", "세 신호 모두"),
    ):
        s = perm[key]
        if s is None:
            lines.append(f"| {label} | 미측정 | 미측정 | 미측정 |")
        else:
            lines.append(
                f"| {label} | {frac(s['accuracy'])} | {frac(s['read_recall'])} | {len(s['write_exposed'])}건 {s['write_exposed'] or ''} |"
            )
    e2e = perm["partial_e2e"]
    lines.append(
        f"\n부분신뢰 종단 간 (서버 {e2e['servers']}개, LLM이 모두 '읽기'라고 속은 경우): 노출 도구 {e2e['visible']}개 중 쓰기 도구 **{len(e2e['write_exposed'])}건**"
    )

    lines += [
        "",
        "## 4. 지연",
        "",
        f"같은 머신·같은 프로세스, 순차 {lat['n']}회 (ms). 처리량은 동시 {lat['concurrency']} 클라이언트, 호출 {lat['total_calls']}회. 판별기: {lat['judge']}, 공급망 조회 제외.",
        "",
        "| 경로 | list_tools p50 / p95 | call_tool p50 / p95 | 처리량 (call/s) |",
        "| --- | --- | --- | --- |",
    ]
    for key, label in (
        ("direct", "게이트웨이 없음"),
        ("gateway_cache_hit", "게이트웨이 (캐시 히트)"),
    ):
        x = lat[key]
        lines.append(
            f"| {label} | {x['list_tools']['p50']:.2f} / {x['list_tools']['p95']:.2f} | {x['call_tool']['p50']:.2f} / {x['call_tool']['p95']:.2f} | {x['throughput_rps']:.0f} |"
        )
    f = lat["first_verification"]["list_tools"]
    lines.append(f"| 첫 검증 (콜드, n={f['n']}) | {f['p50']:.2f} / {f['p95']:.2f} | - | - |")

    lines += ["", "## 5. 판별기 내성", "", "| 지표 | 결과 |", "| --- | --- |"]
    lines.append(
        f"| LLM이 완전히 속아도 '신뢰'가 되는 비율 (규칙이 못 막음) | {frac(jr['success_if_llm_fooled'])} |"
    )
    lines.append(f"| LLM이 '정상'으로 오판한 비율 | {frac(jr['llm_fooled'])} |")
    lines.append(f"| 최종 '신뢰' 판정 (오판 유도 성공률) | {frac(jr['success'])} |")
    lines.append("")
    return "\n".join(lines)


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--judge", choices=["none", "claude"], default="none")
    parser.add_argument("--model", default="claude-haiku-5-5")
    parser.add_argument("-n", type=int, default=200, help="지연 측정 순차 요청 수")
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--total", type=int, default=1000)
    args = parser.parse_args()

    judge: MemoJudge | None = None
    if args.judge == "claude":
        from linkud.verify.judge.anthropic import ClaudeJudge

        judge = MemoJudge(ClaudeJudge(args.model))

    results: dict[str, Any] = {
        "meta": {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "python": platform.python_version(),
            "judge": args.model if judge else "없음 (규칙만)",
        }
    }
    results["detection"] = await eval_detection(judge)
    results["rugpull"] = [await eval_rugpull(FOOLED, "규칙만 (LLM 기만 가정)")]
    if judge is not None:
        results["rugpull"].append(await eval_rugpull(judge, args.model))
    results["permission"] = await eval_permission(judge)
    results["latency"] = await eval_latency(
        judge or FakeJudge(),
        args.model if judge else "FakeJudge (LLM 지연 제외)",
        args.n,
        args.concurrency,
        args.total,
    )
    results["judge_robustness"] = await eval_judge_robustness(judge)
    if judge is not None:
        results["meta"]["llm_calls"] = judge.calls

    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2, default=str) + "\n"
    )
    report = render(results)
    (RESULTS / "RESULTS.md").write_text(report)
    print(report)


if __name__ == "__main__":
    asyncio.run(main())
