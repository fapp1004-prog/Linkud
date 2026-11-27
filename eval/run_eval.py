"""B 평가. 기본은 무료 규칙 검사, 유료 LLM은 --live로 명시한다."""
import argparse
import collections
import hashlib
import json
import sys
import time
from pathlib import Path

from checkers.b_config import load_config
from checkers.b_prompt import PROMPT_VERSION, fingerprint
from checkers.injection import Inspector, combine_results
from checkers import rules
from eval.datasets import load_samples
from eval.metrics import summarize, paired, consistency
from gateway.policy import decide, load_policy, policy_fp, validate_result


def b_grade(result, policy):
    # B 기여분만 측정: C를 실제 실행한 것처럼 기록하지 않는다.
    others_clean = {name: {'checker': name, 'risk': 0, 'hard_block': False, 'signals': [], 'evidence': '', 'latency_ms': 0}
                    for name in policy['weights'] if name != 'injection'}
    return decide({**others_clean, 'injection': result}, policy).grade


def run(samples, inspector, policy, *, method='rules', live=False, repeats=1, fresh=False):
    rows = []
    methods = ['rules', 'llm', 'combined'] if method == 'compare' else [method]
    for trial in range(1, repeats + 1):
        for sample in samples:
            outcomes = {}
            for selected in methods:
                start = time.monotonic()
                result, error = None, None
                # compare는 같은 회차의 실제 결과/오류를 사용한다. 다른 회차 캐시와 섞지 않는다.
                cache_only = not live or (method == 'compare' and selected == 'combined')
                inspector.last_meta = {}
                try:
                    if method == 'compare' and selected == 'combined':
                        inspector.last_meta = {'api_called': False, 'cache_hit': False,
                                               'method': selected, 'reused_llm_result': True}
                        if isinstance(outcomes['rules'], BaseException):
                            raise outcomes['rules']
                        result = combine_results(outcomes['rules'], outcomes['llm'])
                    else:
                        result = inspector.check(sample.tool, method=selected, cache_only=cache_only,
                                                 fresh=fresh and selected != 'rules')
                    validate_result('injection', result)
                    grade = b_grade(result, policy)
                    outcomes[selected] = result
                except Exception as exc:
                    outcomes[selected] = exc
                    error = {'type': type(exc).__name__, 'message': str(exc)[:300]}
                    grade = 'restrict'
                rows.append({'id': sample.id, 'label': sample.label, 'pair_id': sample.pair_id,
                             'variant': sample.variant, 'attack_type': sample.attack_type, 'subtype': sample.subtype,
                             'review_status': sample.review_status, 'method': selected, 'repeat': trial,
                             'grade': grade, 'result': result, 'error': error,
                             'latency_ms': round((time.monotonic() - start) * 1000), **inspector.last_meta})
    return rows


def signature(inputs, config, policy, method, repeats):
    root = Path(__file__).resolve().parent.parent
    modules = [*root.glob('checkers/b_*.py'), root / 'checkers/rules.py', root / 'checkers/injection.py',
               root / 'checkers/llm_cache.py', root / 'checkers/llm_client.py',
               root / 'eval/datasets.py', root / 'eval/metrics.py', root / 'eval/run_eval.py']
    return {'inputs': [{'path': str(p.resolve()), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in inputs],
            'model': config.model, 'prompt_version': PROMPT_VERSION, 'prompt_fp': fingerprint(config),
            'runtime': {'timeout_seconds': config.timeout, 'max_output_tokens': config.max_output_tokens,
                        'budget_usd': config.budget_usd, 'input_price': config.input_per_million,
                        'output_price': config.output_per_million},
            'rules_version': rules.VERSION, 'rules_sha256': hashlib.sha256(Path(rules.__file__).read_bytes()).hexdigest(),
            'injection_sha256': hashlib.sha256(Path(sys.modules[Inspector.__module__].__file__).read_bytes()).hexdigest(),
            'code_sha256': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in modules},
            'policy_fp': policy_fp(policy), 'mode': config.mode, 'method': method, 'repeats': repeats}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, nargs='+', required=True)
    p.add_argument('--method', choices=['rules', 'llm', 'combined', 'compare'], default='rules')
    p.add_argument('--limit', type=int, default=10, help='0이면 전체. 기본 10개로 먼저 점검')
    p.add_argument('--live', action='store_true', help='유료 API 호출을 허용. 생략하면 캐시만 사용')
    p.add_argument('--fresh', action='store_true', help='캐시를 읽지 않고 재측정 (추가 과금)')
    p.add_argument('--repeats', type=int, default=1)
    p.add_argument('--stage', choices=['exploratory', 'supplement', 'final'], default='exploratory')
    p.add_argument('--freeze', type=Path, help='최종 평가 설정/데이터 해시 파일')
    p.add_argument('--write-freeze', action='store_true', help='설정만 고정하고 평가/API 호출 없이 종료')
    p.add_argument('--dry-run', action='store_true', help='개수만 확인, 검사/API 호출 없음')
    p.add_argument('--output', type=Path, default=Path('eval/reports/result.json'))
    args = p.parse_args(argv)
    if args.limit < 0 or args.repeats < 1:
        p.error('limit은 0 이상, repeats는 1 이상이어야 합니다.')
    if args.repeats > 1 and args.method != 'rules' and not (args.fresh and args.live):
        p.error('반복 LLM 평가는 --fresh --live가 필요합니다. 캐시 재사용을 반복 측정으로 세지 않습니다.')
    if args.fresh and not args.live:
        p.error('--fresh는 --live와 함께 쓰세요.')
    samples = load_samples(args.input)
    if args.dry_run:
        print(json.dumps({'count': len(samples), 'labels': dict(collections.Counter(s.label for s in samples)),
                          'review_status': dict(collections.Counter(s.review_status for s in samples)), 'api_calls': 0}, ensure_ascii=False, indent=2))
        return 0
    config, policy = load_config(), load_policy()
    if config.mode != 'real':
        p.error('평가에서는 LINKUD_DEV_CHECKERS를 해제하세요.')
    frozen = signature(args.input, config, policy, args.method, args.repeats)
    if args.stage == 'final' or args.write_freeze:
        if args.limit != 0 or not args.freeze:
            p.error('최종 평가/고정에는 --limit 0 --freeze <파일>이 필요합니다.')
        if any(s.review_status == 'unreviewed' for s in samples):
            p.error('검토 전 보완셋은 final에 넣지 마세요. --stage supplement로 별도 보고하세요.')
        if args.write_freeze:
            args.freeze.parent.mkdir(parents=True, exist_ok=True)
            with args.freeze.open('x', encoding='utf-8') as f:
                json.dump(frozen, f, ensure_ascii=False, indent=2)
            print('데이터와 설정을 고정했습니다. API는 호출하지 않았습니다.')
            return 0
        if json.loads(args.freeze.read_text(encoding='utf-8')) != frozen:
            p.error('고정한 데이터 또는 설정과 다릅니다.')
        if args.output.exists():
            p.error('기존 최종 평가 결과를 덮어쓰지 않습니다. 출력 경로를 확인하세요.')
    chosen = samples[:args.limit] if args.limit else samples
    inspector = Inspector(config)
    rows = run(chosen, inspector, policy, method=args.method, live=args.live, repeats=args.repeats, fresh=args.fresh)
    groups = collections.defaultdict(list)
    for r in rows:
        groups[r['method'] + '/' + (r['attack_type'] or r['label']) + '/' + (r['variant'] or 'original')].append(r)
    report = {'scope': 'B-only under A policy, assuming both C results are clean; not an end-to-end gateway evaluation.',
              'stage': args.stage, 'preliminary_labels': any(s.review_status != 'reviewed' for s in chosen),
              'execution': {'live': args.live, 'fresh': args.fresh, 'repeats': args.repeats,
                            'latency_note': 'Wall-clock time including cache reuse; compare/combined reuses the exact current-trial LLM result and is not a fresh inference latency.'},
              'config': frozen, 'available_samples': len(samples), 'evaluated_unique_samples': len(chosen),
              'by_method': {m: summarize([r for r in rows if r['method'] == m]) for m in {r['method'] for r in rows}},
              'by_type': {name: summarize(group) for name, group in groups.items()},
              'paired': paired(rows),
              'paired_by_method_and_type': {m + '/' + t: paired([r for r in rows if r['method'] == m and r['attack_type'] == t])
                                            for m in {r['method'] for r in rows}
                                            for t in {r['attack_type'] for r in rows if r['pair_id']}},
              'repeat_consistency': {m: consistency([r for r in rows if r['method'] == m]) for m in {r['method'] for r in rows}},
              'rows': rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'report': str(args.output.resolve()), 'by_method': report['by_method']}, ensure_ascii=False, indent=2))
    return 2 if any(r['error'] for r in rows) else 0


if __name__ == '__main__':
    raise SystemExit(main())
