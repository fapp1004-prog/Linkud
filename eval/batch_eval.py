"""최종 평가 Batch: prepare(무료) → submit --live → status → collect.

submit만 원문을 OpenAI에 업로드하고 과금을 시작한다. 실제 제출은 자동 재시도하지 않는다.
정답/출처는 업로드하지 않고, custom_id로 순서가 섞인 결과를 원래 회차에 연결한다.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

from checkers import b_prompt, llm_client
from checkers.b_config import load_config
from checkers.b_metadata import canonical_tool, text_fields
from checkers.batch_client import BatchClient
from checkers.injection import combine_results, request_cost, rules_result, verdict_result
from checkers.llm_cache import LLMCache
from eval.datasets import load_samples
from eval.metrics import summarize, paired, consistency
from eval.run_eval import b_grade, signature
from gateway.cache import tool_hash
from gateway.policy import load_policy, validate_result

TERMINAL = {'completed', 'failed', 'expired', 'cancelled'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def check_data_hash(inputs):
    if len(inputs) != 1:
        raise ValueError('최종 평가는 동결한 final JSONL 파일 하나를 사용합니다.')
    path = Path(inputs[0])
    expected = path.with_name('FINAL_HASH.txt').read_text(encoding='ascii').strip()
    actual = digest(path.read_bytes())
    if expected != actual:
        raise ValueError('최종 데이터가 FINAL_HASH.txt의 SHA-256과 다릅니다.')
    return actual


def make_requests(samples, config, repeats):
    requests, mapping, reserves = [], [], {}
    for trial in range(1, repeats + 1):
        for index, sample in enumerate(samples):
            cid = f'r{trial:03d}-s{index:06d}'
            body = b_prompt.request_body(canonical_tool(sample.tool), config)
            requests.append({'custom_id': cid, 'method': 'POST', 'url': '/v1/responses', 'body': body})
            mapping.append({'custom_id': cid, 'sample_index': index, 'repeat': trial})
            reserves[cid] = request_cost(body, config, batch=True)
    payload = b'\n'.join(encoded(row) for row in requests) + b'\n'
    if len(requests) > 50_000 or len(payload) > 200_000_000:
        raise ValueError('Batch의 50,000개/200MB 제한을 넘습니다.')
    return payload, mapping, reserves


def prepare(inputs, freeze_path, job, config, policy, repeats=3):
    if config.mode != 'real' or type(repeats) is not int or not 1 <= repeats <= 100:
        raise ValueError('실제 모드와 유효한 반복 횟수가 필요합니다.')
    inputs, job = [Path(p) for p in inputs], Path(job)
    data_sha256 = check_data_hash(inputs)
    samples = load_samples(inputs)
    if any(s.review_status == 'unreviewed' or s.pair_id for s in samples):
        raise ValueError('검토 전 자료/보완 짝은 최종 평가에 넣지 않습니다.')
    frozen = signature(inputs, config, policy, 'compare', repeats)
    if json.loads(Path(freeze_path).read_text(encoding='utf-8')) != frozen:
        raise ValueError('동결한 입력·코드·모델·설정과 다릅니다.')
    payload, mapping, reserves = make_requests(samples, config, repeats)
    run_key = digest(encoded(frozen) + payload)
    plan = {'format': 1, 'run_key': run_key, 'config': frozen, 'mapping': mapping, 'data_sha256': data_sha256,
            'request_sha256': digest(payload), 'reservations': reserves,
            'cache_path': str(config.cache_path.resolve()), 'request_count': len(mapping),
            'reserved_usd_upper_bound': sum(reserves.values()) / 1_000_000,
            'note': 'Final labels may be source/assistant labels. No quality result exists before collection.'}
    job.mkdir(parents=True, exist_ok=False)
    (job / '.gitignore').write_text('*\n!.gitignore\n', encoding='utf-8')
    (job / 'requests.jsonl').write_bytes(payload)
    (job / 'plan.json').write_bytes(encoded(plan))
    return plan


def load_job(job, config, policy):
    job = Path(job)
    plan = json.loads((job / 'plan.json').read_text(encoding='utf-8'))
    if plan.get('format') != 1 or plan['cache_path'] != str(config.cache_path.resolve()):
        raise ValueError('Batch 형식/예산 DB가 준비할 때와 다릅니다.')
    frozen = plan['config']
    inputs = [Path(p['path']) for p in frozen['inputs']]
    if check_data_hash(inputs) != plan['data_sha256']:
        raise ValueError('동결한 최종 데이터 해시가 바뀌었습니다.')
    if config.mode != 'real' or signature(inputs, config, policy, 'compare', frozen['repeats']) != frozen:
        raise ValueError('준비 이후 입력·검사 코드·설정이 바뀌었습니다.')
    samples = load_samples(inputs)
    payload, mapping, reserves = make_requests(samples, config, frozen['repeats'])
    if (payload != (job / 'requests.jsonl').read_bytes() or digest(payload) != plan['request_sha256']
            or mapping != plan['mapping'] or reserves != plan['reservations']
            or digest(encoded(frozen) + payload) != plan['run_key']):
        raise ValueError('Batch 요청/회차 매핑/예약액이 변경되었습니다.')
    return plan, samples, payload


def submit(job, config, policy, client):
    plan, _, payload = load_job(job, config, policy)
    cache = LLMCache(config.cache_path)
    cache.reserve_batch(plan['run_key'], plan['reservations'], config.model, config.mode, config.budget_usd)
    try:
        file_id = client.upload(payload)
        cache.update_batch(plan['run_key'], 'creating', file_id=file_id)
        remote = client.create(file_id, plan['run_key'])
        verify_remote(remote, plan, file_id)
        cache.update_batch(plan['run_key'], remote['status'], batch_id=remote['id'])
        return remote
    except Exception:
        cache.update_batch(plan['run_key'], 'submission_uncertain')
        raise


def verify_remote(remote, plan, file_id):
    if (remote.get('input_file_id') != file_id or remote.get('endpoint') != '/v1/responses'
            or remote.get('metadata', {}).get('linkud_run') != plan['run_key']):
        raise ValueError('이 계획의 Batch가 아닙니다. 다른 평가 결과를 연결하지 않습니다.')
    BatchClient._id(remote.get('id'), 'batch')


def status(job, config, policy, client, *, recover_id=None):
    plan, _, _ = load_job(job, config, policy)
    cache = LLMCache(config.cache_path)
    saved = cache.batch_run(plan['run_key'])
    if not saved:
        raise ValueError('이 DB에 Batch 제출 기록이 없습니다.')
    if recover_id and saved['batch_id'] and recover_id != saved['batch_id']:
        raise ValueError('이미 연결된 Batch ID를 교체하지 않습니다.')
    batch_id = recover_id or saved['batch_id']
    if not batch_id:
        raise ValueError('제출 결과가 불확실합니다. 콘솔에서 ID 확인 후 recover --batch-id를 사용하세요.')
    remote = client.retrieve(batch_id)
    verify_remote(remote, plan, saved['input_file_id'])
    cache.update_batch(plan['run_key'], remote['status'], batch_id=remote['id'])
    return remote


def parse_lines(contents, expected):
    records = {}
    for content in contents:
        for line in content.splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            cid = row.get('custom_id') if isinstance(row, dict) else None
            if cid not in expected or cid in records:
                raise ValueError('알 수 없거나 중복된 Batch custom_id입니다.')
            records[cid] = row
    return records


def collect(job, config, policy, client):
    plan, samples, _ = load_job(job, config, policy)
    remote = status(job, config, policy, client)
    if remote['status'] not in TERMINAL:
        raise ValueError('Batch가 아직 끝나지 않았습니다. 나중에 status로 확인하세요.')
    contents = [client.content(remote[k]) for k in ('output_file_id', 'error_file_id') if remote.get(k)]
    records = parse_lines(contents, {m['custom_id'] for m in plan['mapping']})
    rows, cache = [], LLMCache(config.cache_path)
    for mapping in plan['mapping']:
        sample = samples[mapping['sample_index']]
        cid = mapping['custom_id']
        verdict, usage, charged, llm = None, {}, 0, None
        try:
            row = records.get(cid)
            if row is None:
                raise llm_client.LLMError('Batch 결과 누락: 재호출하지 않고 오류로 집계합니다.')
            response = row.get('response') or {}
            if row.get('error') or response.get('status_code') != 200:
                raise llm_client.LLMError('Batch 요청 오류: 원격 오류 본문은 기록하지 않았습니다.')
            raw, usage = llm_client.parse_response(response.get('body'))
            verdict = llm_client.parse_verdict(raw, [s for _, s in text_fields(sample.tool)])
            charged = math.ceil((usage['input_tokens'] * config.input_per_million
                                 + usage['output_tokens'] * config.output_per_million) * 0.5)
            llm = verdict_result(verdict, config)
        except Exception as exc:
            llm = exc
        cache.import_batch(plan['run_key'], cid, (tool_hash(sample.tool), b_prompt.PROMPT_VERSION, config.model, config.mode),
                           digest(canonical_tool(sample.tool).encode('utf-8')), b_prompt.fingerprint(config), verdict, usage, charged)
        try:
            rule = rules_result(sample.tool)
            rule['latency_ms'] = 0  # Batch 재수집 시 측정하지 않은 시간으로 보고서가 달라지지 않음
        except Exception as exc:
            rule = exc
        for method in ('rules', 'llm', 'combined'):
            result, error = None, None
            try:
                if method == 'rules':
                    if isinstance(rule, Exception):
                        raise rule
                    result = rule
                elif method == 'llm':
                    if isinstance(llm, Exception):
                        raise llm
                    result = llm
                else:
                    if isinstance(rule, Exception):
                        raise rule
                    result = combine_results(rule, llm)
                validate_result('injection', result)
                grade = b_grade(result, policy)
            except Exception as exc:
                error = {'type': type(exc).__name__, 'message': 'Batch 검사 실패/누락. 과거 성공 캐시로 대체하지 않음.'}
                grade = 'restrict'
            rows.append({'id': sample.id, 'label': sample.label, 'pair_id': sample.pair_id,
                         'variant': sample.variant, 'attack_type': sample.attack_type, 'subtype': sample.subtype,
                         'review_status': sample.review_status, 'repeat': mapping['repeat'], 'method': method,
                         'grade': grade, 'result': result, 'error': error, 'latency_ms': 0,
                         'custom_id': cid, 'cache_hit': False, 'api_called': method == 'llm',
                         'reused_llm_result': method == 'combined'})
    report = {'stage': 'final', 'scope': 'B-only under A policy, assuming both C results are clean.',
              'config': plan['config'], 'run_key': plan['run_key'], 'batch_id': remote['id'],
              'execution': {'backend': 'batch', 'status': remote['status'], 'repeats': plan['config']['repeats'],
                            'request_count': len(plan['mapping']), 'latency_measured': False,
                            'latency_note': 'Batch has no measured per-request inference latency; latency_ms placeholders are zero.'},
              'evaluated_unique_samples': len(samples),
              'preliminary_labels': any(s.review_status != 'reviewed' for s in samples),
              'by_method': {m: summarize([r for r in rows if r['method'] == m]) for m in ('rules', 'llm', 'combined')},
              'repeat_consistency': {m: consistency([r for r in rows if r['method'] == m]) for m in ('rules', 'llm', 'combined')},
              'paired': paired(rows), 'rows': rows}
    for stats in report['by_method'].values():
        # Never advertise a zero/placeholder Batch latency as a speed measurement.
        for key in list(stats):
            if 'latency' in key or key in ('median_ms', 'p95_ms'):
                stats[key] = None
    output = Path(job) / 'report.json'
    data = encoded(report)
    if output.exists():
        if output.read_bytes() != data:
            raise ValueError('이미 저장한 최종 보고서와 다릅니다. 덮어쓰지 않습니다.')
    else:
        with output.open('xb') as f:
            f.write(data)
    return report


def require_final_report(path):
    report = json.loads(Path(path).read_text(encoding='utf-8'))
    execution = report.get('execution', {})
    if (report.get('stage') != 'final' or execution.get('backend') != 'batch'
            or execution.get('status') != 'completed' or not report.get('run_key') or not report.get('rows')):
        raise ValueError('먼저 완료된 최종 Batch 평가 보고서가 필요합니다.')
    return report


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--input', nargs='+', type=Path, required=True)
    prep.add_argument('--freeze', type=Path, required=True)
    prep.add_argument('--repeats', type=int, default=3)
    for name in ('submit', 'status', 'collect', 'recover'):
        action = sub.add_parser(name)
        action.add_argument('--job', type=Path, required=True)
        if name == 'submit':
            action.add_argument('--live', action='store_true', help='원문 업로드·유료 Batch 실행 허용')
        if name == 'recover':
            action.add_argument('--batch-id', required=True)
    prep.add_argument('--job', type=Path, required=True)
    args = p.parse_args(argv)
    if args.action == 'submit' and not args.live:
        p.error('제출은 원문 업로드와 과금이 발생할 수 있습니다. 직접 --live를 지정하세요.')
    config, policy = load_config(), load_policy()
    if args.action == 'prepare':
        plan = prepare(args.input, args.freeze, args.job, config, policy, args.repeats)
        print(json.dumps({k: plan[k] for k in ('run_key', 'request_count', 'reserved_usd_upper_bound')}))
        return 0
    client = BatchClient(config.api_key)
    if args.action == 'submit':
        result = submit(args.job, config, policy, client)
    elif args.action in ('status', 'recover'):
        result = status(args.job, config, policy, client, recover_id=getattr(args, 'batch_id', None))
    else:
        result = collect(args.job, config, policy, client)
        print(json.dumps({'report': str((args.job / 'report.json').resolve()), 'by_method': result['by_method']}, ensure_ascii=False))
        return 2 if any(r['error'] for r in result['rows']) else 0
    print(json.dumps({k: result.get(k) for k in ('id', 'status', 'request_counts')}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
