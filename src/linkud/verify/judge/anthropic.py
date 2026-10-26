"""Claude API 판별기 어댑터.

판별 LLM은 격리한다: 도구(tools)를 주지 않고, 프롬프트에 비밀값을 넣지 않으며, 구조화
출력으로 받은 JSON만 파싱한다. API 키는 SDK가 환경변수(ANTHROPIC_API_KEY)에서 읽는다.
"""

from __future__ import annotations

from typing import Any

import anthropic

from linkud.verify.judge.base import OUTPUT_SCHEMA, JudgeLabel, JudgeVerdict, parse_output
from linkud.verify.judge.prompt import SYSTEM_PROMPT, build_user_message

DEFAULT_MODEL = "claude-haiku-5-5"


class ClaudeJudge:
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        timeout: float = 20.0,
        max_retries: int = 1,
        client: anthropic.AsyncAnthropic | None = None,
    ) -> None:
        self.model = model
        self.client = client or anthropic.AsyncAnthropic(timeout=timeout, max_retries=max_retries)

    async def judge(self, definition: dict[str, Any]) -> JudgeVerdict:
        message, _ = build_user_message(definition)
        # API 오류·타임아웃은 그대로 올려 보낸다: 검증 실패 → 도구 숨김(fail-closed)
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": message}],
            output_config={
                "effort": "low",
                "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA},
            },
        )
        if response.stop_reason == "refusal":
            return JudgeVerdict(JudgeLabel.SUSPICIOUS, None, ["판별 모델이 응답을 거부함"], 0.0)
        if response.stop_reason == "max_tokens":
            return JudgeVerdict(JudgeLabel.SUSPICIOUS, None, ["판별 모델 출력이 잘림"], 0.0)
        text = next((b.text for b in response.content if b.type == "text"), "")
        verdict = parse_output(text)
        return JudgeVerdict(
            verdict.label,
            verdict.is_write,
            verdict.reasons,
            verdict.confidence,
            {**verdict.details, "model": self.model},
        )
