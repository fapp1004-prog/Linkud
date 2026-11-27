"""C 데모 정의를 B 규칙으로 확인한다. 평가 데이터/실제 GPT 성적이 아니며 API는 호출하지 않는다."""
import json

from checkers.injection import rules_result
from gateway.policy import validate_result
from testservers.calc_ok.server import TOOLS as CLEAN
from testservers.calc_poison.server import TOOLS as POISON


def main():
    results = []
    for kind, tool in [('normal', CLEAN[0]), ('poison_add', POISON[0]), ('subtle_multiply', POISON[1])]:
        result = rules_result(tool)
        validate_result('injection', result)
        results.append({'demo': kind, 'signals': result['signals'], 'hard_block': result['hard_block']})
    assert not results[0]['signals']
    assert results[1]['hard_block']
    assert not results[2]['signals']  # 실제 LLM이 잡는지는 API 시연에서 별도 확인해야 한다.
    print(json.dumps({'api_calls': 0, 'results': results}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
