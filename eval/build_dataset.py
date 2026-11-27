"""B 데이터 구성: 원본 보존, 서버 분리, 유사 중복 제거, 부족하면 생성 중단.

기본 실행은 점검뿐이다. --write는 정해진 수량/라벨을 모두 만족할 때만 사본을 쓴다.
헷갈리는 정상은 별도 검토 파일 {"hard_benign_ids": [...]}로 지정한다. 자동 라벨링 없음.
"""
import argparse
import collections
import difflib
import hashlib
import json
import random
import unicodedata
from pathlib import Path

from checkers.b_metadata import canonical_tool
from eval.datasets import load_samples

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUTS = [ROOT / 'eval/dataset/aws_normal307.jsonl', ROOT / 'eval/dataset/mcptox200.jsonl']
TARGETS = {'dev': {'benign': 50, 'malicious': 50, 'hard_benign': 10},
           'final': {'benign': 300, 'malicious': 300, 'hard_benign': 40}}


def normalized(tool):
    return ' '.join(unicodedata.normalize('NFKC', canonical_tool(tool)).casefold().split())


def read_records(paths):
    records = {}
    for path in paths:
        path = Path(path)
        text = path.read_text(encoding='utf-8-sig')
        rows = json.loads(text) if path.suffix.lower() == '.json' else [json.loads(s) for s in text.splitlines() if s.strip()]
        for row in rows:
            # load_samples validates duplicates/types before this function is called.
            records[row['id']] = row
    return records


def deduplicate(samples, threshold=0.9):
    """유사 문장 묶음의 라벨이 서로 충돌하면 그 묶음 전체를 보류한다."""
    texts = [normalized(s.tool) for s in samples]
    parent = list(range(len(samples)))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    order = sorted(range(len(samples)), key=lambda i: (len(texts[i]), samples[i].id))
    for offset, i in enumerate(order):
        for j in order[offset + 1:]:
            if 2 * len(texts[i]) / (len(texts[i]) + len(texts[j])) < threshold:
                break
            matcher = difflib.SequenceMatcher(None, texts[i], texts[j], autojunk=False)
            if matcher.quick_ratio() >= threshold and matcher.ratio() >= threshold:
                parent[find(j)] = find(i)
    clusters = collections.defaultdict(list)
    for i, sample in enumerate(samples):
        clusters[find(i)].append(sample)
    kept, excluded = [], []
    for group in clusters.values():
        group.sort(key=lambda s: s.id)
        conflict = len({s.label for s in group}) > 1
        if not conflict:
            kept.append(group[0])
        for s in group if conflict else group[1:]:
            excluded.append({'id': s.id, 'reason': 'label_conflict' if conflict else 'similar_duplicate',
                             'representative': None if conflict else group[0].id})
    return sorted(kept, key=lambda s: s.id), excluded


def counts(samples, hard):
    result = dict.fromkeys(('benign', 'malicious', 'hard_benign'), 0)
    for s in samples:
        result[s.label] += 1
        result['hard_benign'] += s.id in hard
    return result


def shortage(actual, target):
    return {k: max(0, target[k] - actual[k]) for k in target}


def allocate(groups, hard, targets, seed):
    """고정 seed의 제한된 탐색. 실패를 데이터 부족의 수학적 증명으로 보고하지 않는다."""
    rng, best, best_score = random.Random(seed), None, float('inf')
    for _ in range(512):
        remaining = {stage: dict(target) for stage, target in targets.items()}
        chosen = {stage: [] for stage in targets}
        shuffled = sorted(groups)
        rng.shuffle(shuffled)
        for server in shuffled:
            items = list(groups[server])
            rng.shuffle(items)
            choices = {}
            for stage, need in remaining.items():
                trial = dict(need)
                take = []
                # 검토된 hard benign을 먼저 확보하되 원문은 수정하지 않는다.
                ranked = sorted(items, key=lambda s: not (s.id in hard and trial['hard_benign'] > 0))
                for s in ranked:
                    if len(take) == 3:
                        break
                    if trial[s.label] > 0:
                        take.append(s)
                        trial[s.label] -= 1
                        if s.id in hard:
                            trial['hard_benign'] = max(0, trial['hard_benign'] - 1)
                if take:
                    choices[stage] = (take, trial)
            if not choices:
                continue
            stages = list(choices)
            weights = [sum(remaining[s].values()) for s in stages]
            stage = rng.choices(stages, weights=weights, k=1)[0]
            take, remaining[stage] = choices[stage]
            chosen[stage].extend(take)
        score = sum(sum(v.values()) for v in remaining.values())
        if score < best_score:
            best, best_score = chosen, score
        if score == 0:
            break
    return best


def build(paths, *, hard_benign_ids=(), targets=None, seed=42):
    targets = TARGETS if targets is None else targets
    if set(targets) != {'dev', 'final'} or any(set(t) != {'benign', 'malicious', 'hard_benign'} for t in targets.values()):
        raise ValueError('dev/final의 benign, malicious, hard_benign 목표가 필요합니다.')
    if any(type(v) is not int or v < 0 for t in targets.values() for v in t.values()) or any(t['hard_benign'] > t['benign'] for t in targets.values()):
        raise ValueError('목표 수량이 잘못되었습니다.')
    samples = load_samples(paths)
    records = read_records(paths)
    hard = set(hard_benign_ids)
    by_id = {s.id: s for s in samples}
    if any(sid not in by_id or by_id[sid].label != 'benign' for sid in hard):
        raise ValueError('hard_benign_ids는 입력의 정상 표본 ID만 지정할 수 있습니다.')
    eligible, excluded = [], []
    for s in samples:
        row = records[s.id]
        if s.pair_id or s.review_status == 'unreviewed':
            excluded.append({'id': s.id, 'reason': 'supplement_or_unreviewed'})
        elif not isinstance(row.get('server_name') or row.get('base_server'), str) or not (row.get('server_name') or row.get('base_server')).strip():
            excluded.append({'id': s.id, 'reason': 'missing_server'})
        else:
            # normalize only grouping, never replace an original data field
            s.server_group = unicodedata.normalize('NFKC', s.server_group).strip().casefold()
            eligible.append(s)
    unique, duplicate_report = deduplicate(eligible)
    excluded.extend(duplicate_report)
    groups = collections.defaultdict(list)
    for s in unique:
        groups[s.server_group].append(s)
    capacity = {k: sum(min(3, counts(group, hard)[k]) for group in groups.values())
                for k in ('benign', 'malicious', 'hard_benign')}
    required = {k: sum(t[k] for t in targets.values()) for k in capacity}
    upper_shortfall = shortage(capacity, required)
    selected = allocate(groups, hard, targets, seed) if not any(upper_shortfall.values()) else {'dev': [], 'final': []}
    actual = {stage: counts(rows, hard) for stage, rows in selected.items()}
    missing = {stage: shortage(actual[stage], targets[stage]) for stage in targets}
    ready = not any(upper_shortfall.values()) and not any(v for t in missing.values() for v in t.values())
    if ready:
        assert not ({s.server_group for s in selected['dev']} & {s.server_group for s in selected['final']})
        assert max(collections.Counter(s.server_group for rows in selected.values() for s in rows).values(), default=0) <= 3
    report = {'ready': ready, 'seed': seed, 'similarity': 0.9, 'max_per_server': 3,
              'original_count': len(samples), 'original_labels': counts(samples, hard),
              'eligible_unique': len(unique), 'servers': len(groups), 'targets': targets,
              'capacity_upper_bounds': capacity, 'proven_shortfall': upper_shortfall,
              'selected': actual, 'selection_shortfall': missing,
              'selection_status': 'ready' if ready else ('insufficient_capacity' if any(upper_shortfall.values()) else 'bounded_search_exhausted'),
              'hard_benign_label_source': 'explicit_review_ids_only', 'excluded': excluded,
              'inputs': [{'name': Path(p).name, 'sha256': hashlib.sha256(Path(p).read_bytes()).hexdigest()} for p in paths]}
    return report, {stage: [records[s.id] for s in sorted(rows, key=lambda s: s.id)] for stage, rows in selected.items()}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', nargs='+', type=Path, default=DEFAULT_INPUTS)
    p.add_argument('--hard-benign', type=Path, help='검토한 ID 목록 JSON, 원본 데이터에 라벨을 덧쓰지 않음')
    p.add_argument('--targets', type=Path, help='별도로 확정한 수량 JSON. 생략하면 결정안 100/600')
    p.add_argument('--output-dir', type=Path, default=Path('eval/dataset/splits'))
    p.add_argument('--report', type=Path, help='선택: 명시한 경우에만 점검 보고서를 저장')
    p.add_argument('--write', action='store_true')
    args = p.parse_args(argv)
    review = json.loads(args.hard_benign.read_text(encoding='utf-8')) if args.hard_benign else {}
    target = json.loads(args.targets.read_text(encoding='utf-8')) if args.targets else None
    report, selected = build(args.input, hard_benign_ids=review.get('hard_benign_ids', []), targets=target)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    if args.write and report['ready']:
        args.output_dir.mkdir(parents=True, exist_ok=False)
        (args.output_dir / '.gitignore').write_text('*\n!.gitignore\n!FINAL_HASH.txt\n', encoding='utf-8')
        for stage, rows in selected.items():
            with (args.output_dir / (stage + '.jsonl')).open('x', encoding='utf-8', newline='\n') as f:
                for row in rows:
                    f.write(json.dumps(row, ensure_ascii=False) + '\n')
        digest = hashlib.sha256((args.output_dir / 'final.jsonl').read_bytes()).hexdigest()
        (args.output_dir / 'FINAL_HASH.txt').write_text(digest + '\n', encoding='ascii')
    print(json.dumps({'ready': report['ready'], 'written': bool(args.write and report['ready'])}))
    return 0 if report['ready'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
