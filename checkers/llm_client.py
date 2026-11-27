"""OpenAI Responses API. 도구 권한 없음, 엄격 JSON, 전체 요청 시간 제한, 자동 재시도 없음."""
import asyncio
import json
import math

import httpx


class LLMError(RuntimeError):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('중복 JSON 키')
        result[key] = value
    return result


def parse_verdict(value, original_strings):
    try:
        data = json.loads(value, object_pairs_hook=_unique) if isinstance(value, str) else value
        if not isinstance(data, dict) or set(data) != {'attack_probability', 'reason', 'evidence'}:
            raise ValueError()
        probability = data['attack_probability']
        if type(probability) not in (int, float) or not math.isfinite(probability) or not 0 <= probability <= 1:
            raise ValueError()
        if not isinstance(data['reason'], str) or not data['reason'].strip() or len(data['reason']) > 1000:
            raise ValueError()
        quote = data['evidence']
        if not isinstance(quote, str) or len(quote) > 500:
            raise ValueError()
        if probability >= 0.5 and (not quote.strip() or not any(quote in s for s in original_strings)):
            raise ValueError()
        if quote and not any(quote in s for s in original_strings):
            raise ValueError()
        return data
    except (ValueError, TypeError, KeyError):
        raise LLMError('판별 JSON의 형식·확률·원문 근거가 유효하지 않습니다.') from None


def parse_response(data):
    if not isinstance(data, dict) or data.get('status') != 'completed':
        raise LLMError('판별 응답이 완료되지 않았습니다.')
    texts = []
    for item in data.get('output', []):
        if item.get('type') == 'message':
            for content in item.get('content', []):
                if content.get('type') == 'refusal':
                    raise LLMError('판별 모델이 응답을 거부했습니다.')
                if content.get('type') == 'output_text':
                    texts.append(content['text'])
    if not texts:
        raise LLMError('판별 응답에 JSON 텍스트가 없습니다.')
    usage = data.get('usage')
    if not isinstance(usage, dict) or any(type(usage.get(k)) is not int or usage[k] < 0 for k in ('input_tokens', 'output_tokens')):
        raise LLMError('판별 응답의 토큰 사용량이 없습니다.')
    return ''.join(texts), {k: usage[k] for k in ('input_tokens', 'output_tokens')}


async def _post(body, api_key, timeout):
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        async with client.stream('POST', 'https://api.openai.com/v1/responses',
                                 headers={'Authorization': 'Bearer ' + api_key}, json=body) as response:
            if response.status_code != 200:
                raise LLMError(f'판별 API HTTP {response.status_code}. 응답 본문은 기록하지 않았습니다.')
            chunks, size = [], 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > 128_000:
                    raise LLMError('판별 API 응답 크기 제한을 넘었습니다.')
                chunks.append(chunk)
            return json.loads(b''.join(chunks))


async def _bounded(body, api_key, timeout):
    return await asyncio.wait_for(_post(body, api_key, timeout), timeout=timeout)


def request(body, api_key, timeout):
    try:
        return parse_response(asyncio.run(_bounded(body, api_key, timeout)))
    except LLMError:
        raise
    except Exception:
        # HTTP 오류 객체/응답 본문/헤더를 A의 감사 로그로 넘기지 않는다.
        raise LLMError('판별 API 연결·시간 제한·응답 해석에 실패했습니다.') from None
