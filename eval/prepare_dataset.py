"""데이터를 바꾸지 않고 개수·해시·짝·중복·검토 상태를 점검한다. API 호출 없음."""
import argparse
import collections
import hashlib
import json
from pathlib import Path

from eval.datasets import load_samples

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUTS = [ROOT / 'eval/dataset/aws_normal307.jsonl', ROOT / 'eval/dataset/mcptox200.jsonl',
                  ROOT / 'eval/supplement/supplement_attacks.jsonl', ROOT / 'eval/supplement/supplement_baselines.jsonl']


def inventory(paths):
    samples = load_samples(paths)
    by_source, pairs = collections.defaultdict(list), collections.defaultdict(list)
    for s in samples:
        by_source[s.source].append(s)
        if s.pair_id:
            pairs[s.pair_id].append(s)
    invalid_pairs = [key for key, values in pairs.items() if sorted(s.variant for s in values) != ['attack', 'baseline']]
    main = [s for s in samples if not s.pair_id and s.label == 'malicious']
    supplement = [s for s in samples if s.pair_id]
    return {
        'total': len(samples), 'labels': dict(collections.Counter(s.label for s in samples)),
        'review_status': dict(collections.Counter(s.review_status for s in samples)),
        'sources': [{'path': name, 'count': len(group), 'sha256': hashlib.sha256(Path(name).read_bytes()).hexdigest(),
                     'labels': dict(collections.Counter(s.label for s in group))} for name, group in by_source.items()],
        'pairs': len(pairs), 'invalid_pairs': invalid_pairs,
        'duplicate_full_tool_definitions': len(samples) - len({s.digest for s in samples}),
        'main_supplement_base_id_overlap': sorted({s.base_id for s in main} & {s.base_id for s in supplement}),
        'main_supplement_server_overlap': sorted({s.server_group for s in main} & {s.server_group for s in supplement}),
        'notes': ['기본형 80개도 악성입니다. 정상 개수에 합치지 않습니다.',
                  '보완셋은 별도 시험입니다. 같은 원문/서버가 있으면 독립 표본으로 합산하지 마세요.',
                  'AWS 정상은 assistant 검토 라벨이며 공식 AWS 정답 라벨이 아닙니다.',
                  '개발/최종 분할을 자동 생성하지 않았습니다. 이미 보관한 평가셋으로 튜닝하지 마세요.'],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, nargs='+', default=DEFAULT_INPUTS)
    p.add_argument('--output', type=Path, default=ROOT / 'eval/reports/data_inventory.json')
    args = p.parse_args()
    report = inventory(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'total': report['total'], 'labels': report['labels'], 'pairs': report['pairs'],
                      'review_status': report['review_status'], 'report': str(args.output.resolve())}, ensure_ascii=False, indent=2))
    return 2 if report['invalid_pairs'] or report['main_supplement_base_id_overlap'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
