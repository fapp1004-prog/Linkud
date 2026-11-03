# 시연 드라이버 이미지 (빌드 컨텍스트: 레포 루트)
# Linkud 패키지를 함께 설치한다: 규칙 검사(linkud.verify.rules)로 오염 문장 위치를 실제로 계산하기 위해서다
# 베이스 이미지는 다이제스트로 고정한다 (태그 python:3.12-slim, 2026-10-27 기준)
FROM python:3.12-slim@sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f AS build
# uv 0.11.32 (다이제스트 고정)
COPY --from=ghcr.io/astral-sh/uv:0.11.32@sha256:df4cae8f3a96d175e2e5f992e597550000edbe78fdc2594d5cd8de1a217f504c /uv /bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim@sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f
RUN useradd --uid 10001 --create-home app
COPY --from=build /app/.venv /app/.venv
WORKDIR /app
# 평가 수치는 지어내지 않고 평가 결과 파일을 그대로 읽는다
COPY eval/results/results.json results.json
COPY demo/driver/demo_driver.py demo_driver.py
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1 LINKUD_IN_DOCKER=1 DEMO_RESULTS_PATH=/app/results.json
USER app
EXPOSE 8100
CMD ["python", "demo_driver.py"]
