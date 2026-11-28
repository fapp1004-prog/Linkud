"""사용자 데이터 어댑터. 정답/출처 필드는 LLM 입력과 분리한다."""
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from checkers.b_metadata import canonical_tool


@dataclass
class Sample:
    id: str
    label: str
    tool: dict
    source: str
    server_group: str
    review_status: str
    pair_id: str = ''
    variant: str = ''
    attack_type: str = ''
    subtype: str = ''
    base_id: str = ''

    @property
    def digest(self):
        return hashlib.sha256(canonical_tool(self.tool).encode('utf-8')).hexdigest()


def load_samples(paths):
    samples, seen, pairs = [], set(), {}
    for source in paths:
        path = Path(source)
        text = path.read_text(encoding='utf-8-sig')
        rows = json.loads(text) if path.suffix.lower() == '.json' else [json.loads(s) for s in text.splitlines() if s.strip()]
        if not isinstance(rows, list):
            raise ValueError(f'{path.name}: 레코드 목록이 아닙니다.')
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError(f'{path.name}: 각 레코드는 JSON 객체여야 합니다.')
            sid, label = row.get('id'), row.get('label')
            if not isinstance(sid, str) or not sid or sid in seen:
                raise ValueError('비어 있거나 중복된 샘플 id입니다. 같은 JSON과 JSONL을 둘 다 넣지 마세요.')
            if label not in ('benign', 'malicious'):
                raise ValueError(f'{sid}: label은 benign 또는 malicious여야 합니다.')
            if 'tool' in row:
                tool = row['tool']
            else:
                if not isinstance(row.get('tool_content'), str) or not isinstance(row.get('tool_name'), str):
                    raise ValueError(f'{sid}: tool 또는 tool_name/tool_content가 필요합니다.')
                tool = {'name': row['tool_name'], 'description': row['tool_content']}
            canonical_tool(tool)
            if row.get('variant') == 'baseline' and label != 'malicious':
                raise ValueError('보완셋 baseline은 공격 변형 전의 악성 대조군입니다.')
            if row.get('pair_id') or row.get('variant'):
                pair_id, variant = row.get('pair_id'), row.get('variant')
                if not isinstance(pair_id, str) or not pair_id or variant not in ('baseline', 'attack'):
                    raise ValueError(f'{sid}: 보완셋 pair_id와 variant가 잘못되었습니다.')
                if label != 'malicious':
                    raise ValueError('보완셋의 기본형·변형형은 모두 malicious여야 합니다.')
                pair = pairs.setdefault(pair_id, {})
                if variant in pair:
                    raise ValueError(f'{pair_id}: 같은 variant가 중복되어 짝 비교를 계산할 수 없습니다.')
                metadata = tuple(row.get(k, '') for k in ('attack_type', 'subtype', 'base_id'))
                if pair and metadata != next(iter(pair.values())):
                    raise ValueError(f'{pair_id}: 짝의 공격 유형 또는 원본 ID가 다릅니다.')
                pair[variant] = metadata
            reviewed = ('reviewed' if row['reviewed'] is True else 'unreviewed') if 'reviewed' in row else (
                'assistant_reviewed' if sid.startswith('AWS-BENIGN-') else 'source_dataset_label')
            samples.append(Sample(sid, label, tool, str(path.resolve()),
                                  row.get('server_name') or row.get('base_server') or sid, reviewed,
                                  row.get('pair_id', ''), row.get('variant', ''), row.get('attack_type', ''),
                                  row.get('subtype', ''), row.get('base_id') or row.get('original_id', '')))
            seen.add(sid)
    if not samples:
        raise ValueError('평가 데이터가 비어 있습니다.')
    return samples
