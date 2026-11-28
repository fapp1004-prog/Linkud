"""B 공개 인터페이스 check(tool, server). 결과 등급은 A가 결정한다."""
import hashlib
import json
import math
import time
from decimal import Decimal, ROUND_HALF_UP

from gateway.cache import tool_hash
from checkers import rules, b_prompt, llm_client
from checkers.b_config import load_config
from checkers.b_metadata import canonical_tool, text_fields
from checkers.llm_cache import LLMCache


def rules_result(tool):
    start = time.monotonic()
    result = rules.inspect(tool)
    result['latency_ms'] = int((time.monotonic() - start) * 1000)
    return result


def verdict_result(verdict, config, latency_ms=0):
    """결정안 ⑦: 전체 확신도 구간에서 p*100 반올림. 온라인/Batch 공통."""
    probability = float(verdict['attack_probability'])
    # 소수 첫째 자리가 5이면 올림. 이진 부동소수 오차와 round의 짝수 반올림을 피한다.
    risk = int((Decimal(str(probability)) * 100).quantize(Decimal('1'), rounding=ROUND_HALF_UP))
    return {'checker': 'injection', 'risk': risk, 'hard_block': False,
            'signals': ['llm_flagged'] if probability >= 0.5 else [],
            'confidence': probability, 'model': config.model, 'prompt_version': b_prompt.PROMPT_VERSION,
            'evidence': json.dumps(verdict, ensure_ascii=True), 'latency_ms': latency_ms}


def request_cost(body, config, *, batch=False):
    """예약액은 UTF-8 byte 기반 상한, usage 정산은 별도. 단위는 micro USD."""
    bound = len(json.dumps(body, ensure_ascii=False).encode('utf-8')) + 2048
    return math.ceil((bound * config.input_per_million + config.max_output_tokens * config.output_per_million)
                     * (0.5 if batch else 1))


def combine_results(rule_result, llm_result):
    """같은 평가 회차의 결과를 결합한다. 실패한 LLM 대신 과거 캐시를 가져오지 않는다."""
    if rule_result['hard_block']:
        return {**rule_result, 'signals': list(rule_result['signals'])}
    if isinstance(llm_result, BaseException):
        raise llm_result
    result = {**llm_result, 'risk': max(rule_result['risk'], llm_result['risk']),
              'signals': list(dict.fromkeys(rule_result['signals'] + llm_result['signals'])),
              'evidence': (rule_result['evidence'] + '\n' + llm_result['evidence']).strip()[:4500],
              'latency_ms': rule_result['latency_ms'] + llm_result['latency_ms']}
    return result


class Inspector:
    def __init__(self, config=None, transport=None):
        self.config = config or load_config()
        self.transport = transport or llm_client.request
        self.last_meta = {}

    def check(self, tool, server=None, *, method='combined', cache_only=False, fresh=False):
        if method not in ('rules', 'llm', 'combined'):
            raise ValueError('method는 rules, llm, combined 중 하나여야 합니다.')
        started = time.monotonic()
        payload = canonical_tool(tool)
        base = rules_result(tool) if method != 'llm' else {
            'checker': 'injection', 'risk': 0, 'hard_block': False,
            'signals': [], 'evidence': '', 'latency_ms': 0}
        self.last_meta = {'api_called': False, 'cache_hit': False, 'method': method}
        if method == 'rules' or base['hard_block']:
            return base
        c = self.config
        # API 키가 없더라도 cache-only 평가는 가능하다. 빈 캐시일 때만 설정 오류.
        cache = LLMCache(c.cache_path, deadline=started + c.timeout)
        key = (tool_hash(tool), b_prompt.PROMPT_VERSION, c.model, c.mode)
        payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        prompt_fp = b_prompt.fingerprint(c)
        body = b_prompt.request_body(payload, c)
        # 보수적인 UTF-8 byte 수 + 메시지 여유분. 정확한 과금은 API usage로 정산한다.
        reserve = request_cost(body, c)
        if not c.api_key and not cache_only:
            cache_only = True
        ticket = cache.acquire(key, payload_hash, prompt_fp, reserve, c.budget_usd,
                               deadline=started + c.timeout, cache_only=cache_only, fresh=fresh)
        originals = [value for _, value in text_fields(tool)]
        if 'cached' in ticket:
            verdict = llm_client.parse_verdict(ticket['cached'], originals)
            self.last_meta.update(cache_hit=True, usage=ticket['usage'])
        else:
            self.last_meta['api_called'] = True
            try:
                remaining = started + c.timeout - time.monotonic()
                if remaining <= 0.05:
                    raise TimeoutError('LLM 호출 전 검사 시간이 초과되었습니다.')
                raw, usage = self.transport(body, c.api_key, remaining)
                verdict = llm_client.parse_verdict(raw, originals)
                charged = math.ceil(usage['input_tokens'] * c.input_per_million + usage['output_tokens'] * c.output_per_million)
                cache.complete(ticket, key, payload_hash, prompt_fp, verdict, usage, charged)
                self.last_meta['usage'] = usage
            except Exception:
                cache.failed(ticket)
                raise
        llm_result = verdict_result(verdict, c, int((time.monotonic() - started) * 1000))
        result = llm_result if method == 'llm' else combine_results(base, llm_result)
        result['latency_ms'] = int((time.monotonic() - started) * 1000)
        return result


def check(tool, server):
    # 치명 규칙은 LLM/API 설정 장애와 무관하게 즉시 차단 결과를 반환한다.
    result = rules_result(tool)
    if result['hard_block']:
        return result
    return Inspector().check(tool, server)
