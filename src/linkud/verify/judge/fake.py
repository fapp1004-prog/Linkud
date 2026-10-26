"""테스트용 판별기. 외부 API를 부르지 않는다."""

from __future__ import annotations

from typing import Any

from linkud.verify.judge.base import JudgeLabel, JudgeVerdict, parse_output


class FakeJudge:
    """도구 이름별로 정해 둔 판정을 돌려준다. 없으면 기본값.

    `raw`에 문자열을 주면 모델 출력처럼 `parse_output`을 거친다(파싱 실패 경로 시험용).
    """

    def __init__(
        self,
        default: JudgeVerdict | None = None,
        by_name: dict[str, JudgeVerdict] | None = None,
        raw: str | None = None,
        error: Exception | None = None,
    ) -> None:
        self.default = default or JudgeVerdict(JudgeLabel.BENIGN, False, ["fake: benign"], 0.9)
        self.by_name = by_name or {}
        self.raw = raw
        self.error = error
        self.seen: list[dict[str, Any]] = []

    async def judge(self, definition: dict[str, Any]) -> JudgeVerdict:
        self.seen.append(definition)
        if self.error is not None:
            raise self.error
        if self.raw is not None:
            return parse_output(self.raw)
        return self.by_name.get(definition.get("name", ""), self.default)
