"""공식 Files/Batch REST API 어댑터. 키·응답 오류 본문을 로그에 남기지 않는다."""
import json
import re

import httpx

from checkers.llm_client import LLMError


class BatchClient:
    def __init__(self, api_key, transport=None):
        if not api_key:
            raise ValueError('.env의 OPENAI_API_KEY가 필요합니다.')
        self.key = api_key
        self.transport = transport

    def _request(self, method, path, *, limit=2_000_000, **kwargs):
        try:
            with httpx.Client(timeout=60, follow_redirects=False, trust_env=False,
                              transport=self.transport) as client:
                with client.stream(method, 'https://api.openai.com/v1' + path,
                                   headers={'Authorization': 'Bearer ' + self.key}, **kwargs) as response:
                    if response.status_code != 200:
                        raise LLMError(f'Batch API HTTP {response.status_code}. 응답 본문은 기록하지 않았습니다.')
                    chunks, size = [], 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > limit:
                            raise LLMError('Batch 응답 크기 제한을 넘었습니다.')
                        chunks.append(chunk)
                    return b''.join(chunks)
        except LLMError:
            raise
        except Exception:
            raise LLMError('Batch 연결·시간 제한·응답 읽기 실패. 제출은 자동 재시도하지 않습니다.') from None

    @staticmethod
    def _id(value, prefix):
        if not isinstance(value, str) or not re.fullmatch(prefix + r'[-_][A-Za-z0-9_-]+', value):
            raise ValueError('Batch/File ID 형식이 잘못되었습니다.')
        return value

    def upload(self, payload):
        data = json.loads(self._request('POST', '/files', data={'purpose': 'batch'},
                                       files={'file': ('requests.jsonl', payload, 'application/jsonl')}))
        return self._id(data.get('id'), 'file')

    def create(self, file_id, run_key):
        data = json.loads(self._request('POST', '/batches', json={
            'input_file_id': self._id(file_id, 'file'), 'endpoint': '/v1/responses',
            'completion_window': '24h', 'metadata': {'linkud_run': run_key}}))
        self._id(data.get('id'), 'batch')
        return data

    def retrieve(self, batch_id):
        return json.loads(self._request('GET', '/batches/' + self._id(batch_id, 'batch')))

    def content(self, file_id):
        return self._request('GET', '/files/' + self._id(file_id, 'file') + '/content', limit=256_000_000)
