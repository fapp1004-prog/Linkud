"""B 설정. .env를 읽지만 os.environ을 바꾸거나 자식 서버에 키를 전달하지 않는다."""
import math
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Config:
    api_key: str = field(default='', repr=False)
    model: str = 'gpt-5.4-mini-2026-03-17'
    effort: str = 'low'
    timeout: float = 8.0
    max_output_tokens: int = 1200
    cache_path: Path = ROOT / 'data/llm_cache.db'
    budget_usd: float = 35.0
    input_per_million: float = 0.75
    output_per_million: float = 4.5
    mode: str = 'real'

    def __post_init__(self):
        if self.mode not in ('real', 'dev') or self.effort not in ('none', 'low', 'medium', 'high', 'xhigh'):
            raise ValueError('B 실행 모드 또는 추론 강도가 잘못되었습니다.')
        if not self.model or not 0 < self.timeout <= 8.5 or not 256 <= self.max_output_tokens <= 4096:
            raise ValueError('B 모델·시간 제한·출력 토큰 설정을 확인하세요.')
        for n in (self.budget_usd, self.input_per_million, self.output_per_million):
            if not math.isfinite(n) or n <= 0:
                raise ValueError('B 예산과 토큰 단가는 유한한 양수여야 합니다.')
        if self.budget_usd > 40:
            raise ValueError('팀 예산 한도는 $40입니다.')


def load_config(env_file=None) -> Config:
    # interpolate=False: 파일 내용을 임의 환경변수로 치환하지 않는다.
    values = dotenv_values(env_file or ROOT / '.env', interpolate=False)

    def setting(name, default):
        return os.environ.get(name, values.get(name) or default)

    model = setting('LINKUD_B_MODEL', 'gpt-5.4-mini-2026-03-17')
    if model not in ('gpt-5.4-mini', 'gpt-5.4-mini-2026-03-17'):
        if not all(setting(k, '') for k in ('LINKUD_B_INPUT_PRICE', 'LINKUD_B_OUTPUT_PRICE')):
            raise ValueError('다른 모델은 입력·출력 단가를 명시해야 합니다.')
    return Config(
        api_key=values.get('OPENAI_API_KEY') or '',  # 시스템 환경변수 키를 자동 사용하지 않는다.
        model=model, effort=setting('LINKUD_B_EFFORT', 'low'),
        timeout=float(setting('LINKUD_B_TIMEOUT', '8')),
        max_output_tokens=int(setting('LINKUD_B_MAX_OUTPUT_TOKENS', '1200')),
        cache_path=Path(setting('LINKUD_B_CACHE', str(ROOT / 'data/llm_cache.db'))),
        budget_usd=float(setting('LINKUD_B_BUDGET_USD', '35')),
        input_per_million=float(setting('LINKUD_B_INPUT_PRICE', '0.75')),
        output_per_million=float(setting('LINKUD_B_OUTPUT_PRICE', '4.5')),
        mode='dev' if os.environ.get('LINKUD_DEV_CHECKERS') == '1' else 'real',
    )
