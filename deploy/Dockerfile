# syntax=docker/dockerfile:1
# Linkud 게이트웨이 이미지 (빌드 컨텍스트: 레포 루트)

FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
# 공급망 검증용 syft: 릴리스 체크섬을 확인하고 설치한다
ARG SYFT_VERSION=1.18.1
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && cd /tmp \
    && curl -sSfLO "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
    && curl -sSfLO "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_checksums.txt" \
    && grep " syft_${SYFT_VERSION}_linux_amd64.tar.gz$" "syft_${SYFT_VERSION}_checksums.txt" | sha256sum -c - \
    && tar -xzf "syft_${SYFT_VERSION}_linux_amd64.tar.gz" -C /usr/local/bin syft \
    && rm -f /tmp/syft_* \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home app \
    && mkdir /data && chown app:app /data
COPY --from=build /app/.venv /app/.venv
WORKDIR /app
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]
CMD ["linkud", "--config", "/app/config.yaml"]
