"""SPEC 10-1: 오류로 제한된 샘플은 탐지 성공이나 오탐에 섞지 않는다."""
import collections
import math
import statistics


def summarize(rows):
    malicious = [r for r in rows if r['label'] == 'malicious']
    benign = [r for r in rows if r['label'] == 'benign']
    detected = lambda r: r['error'] is None and r['grade'] in ('restrict', 'block')
    ratio = lambda n, total: n / total if total else None
    durations = sorted(r['latency_ms'] for r in rows)
    successful = [r for r in rows if r['error'] is None]
    return {'n': len(rows), 'malicious': len(malicious), 'benign': len(benign),
            'detected_malicious': sum(map(detected, malicious)),
            'detection_rate': ratio(sum(map(detected, malicious)), len(malicious)),
            'false_positives': sum(map(detected, benign)),
            'false_positive_rate': ratio(sum(map(detected, benign)), len(benign)),
            'normal_execution_held_rate_including_errors': ratio(sum(r['grade'] != 'allow' for r in benign), len(benign)),
            'errors': len(rows) - len(successful),
            'malicious_errors': sum(r['error'] is not None for r in malicious),
            'benign_errors': sum(r['error'] is not None for r in benign),
            'successful_grades': dict(collections.Counter(r['grade'] for r in successful)),
            'malicious_successful_grades': dict(collections.Counter(r['grade'] for r in malicious if r['error'] is None)),
            'benign_successful_grades': dict(collections.Counter(r['grade'] for r in benign if r['error'] is None)),
            'median_ms': statistics.median(durations) if durations else None,
            'p95_ms': durations[math.ceil(len(durations) * 0.95) - 1] if durations else None}


def paired(rows):
    groups = collections.defaultdict(dict)
    for r in rows:
        if r.get('pair_id'):
            groups[(r['method'], r['repeat'], r['pair_id'])][r['variant']] = r
    out = collections.Counter()
    for pair in groups.values():
        if set(pair) != {'baseline', 'attack'}:
            out['incomplete_pairs'] += 1
            continue
        b, a = pair['baseline'], pair['attack']
        if b['error'] or a['error']:
            out['pairs_with_errors'] += 1
        elif b['grade'] != 'allow' and a['grade'] == 'allow':
            out['baseline_detected_attack_missed'] += 1
        elif b['grade'] != 'allow' and a['grade'] != 'allow':
            out['both_detected'] += 1
        elif b['grade'] == 'allow' and a['grade'] != 'allow':
            out['only_attack_detected'] += 1
        else:
            out['both_missed'] += 1
    return dict(out)


def consistency(rows):
    groups = collections.defaultdict(list)
    for row in rows:
        groups[(row['method'], row['id'])].append(row)
    repeated = [group for group in groups.values() if len(group) > 1]
    eligible = [group for group in repeated if all(r['error'] is None for r in group)]
    stable = sum(len({r['grade'] for r in group}) == 1 for group in eligible)
    return {'repeated_samples': len(repeated), 'completed_repeated_samples': len(eligible),
            'samples_with_errors': len(repeated) - len(eligible), 'same_grade_samples': stable,
            'grade_agreement_rate': stable / len(eligible) if eligible else None}
