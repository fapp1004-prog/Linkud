# syntax=docker/dockerfile:1
# Linkud 게이트웨이 이미지 (빌드 컨텍스트: 레포 루트)

# 베이스 이미지는 다이제스트로 고정한다 (태그 python:3.12-slim, 2026-10-27 기준). Dependabot이 갱신 PR을 연다
FROM python:3.12-slim@sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f AS build
# uv 0.11.32 (다이제스트 고정)
COPY --from=ghcr.io/astral-sh/uv:0.11.32@sha256:df4cae8f3a96d175e2e5f992e597550000edbe78fdc2594d5cd8de1a217f504c /uv /bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

# 공급망 검증용 syft를 수정된 Go 툴체인으로 직접 빌드한다.
# 배포 바이너리(최신 1.55.0 포함)가 Go 1.26.8로 빌드돼 stdlib CVE(crypto/x509·crypto/tls·net/http, HIGH)가
# Trivy에 잡히는데 아직 고친 릴리스가 없다. Go 체크섬 DB(sumdb)가 모듈 무결성을 확인한다.
# golang:1.27.3-bookworm (다이제스트 고정, 2026-10-27 기준)
FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS syft
ARG SYFT_VERSION=1.55.0
# syft 1.55.0이 끌어오는 go-jose v4.1.5에 CVE-2026-116587(HIGH, 수정판 4.1.6)이 있어 수정판으로 올린다.
# 임시 모듈에서 syft와 고친 의존성을 함께 요구해 빌드한다(모듈 무결성은 go.sum·sumdb가 확인)
ARG GO_JOSE_VERSION=4.1.7
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
WORKDIR /build
RUN go mod init linkud.local/syft-build \
    && go get "github.com/anchore/syft/cmd/syft@v${SYFT_VERSION}" \
              "github.com/go-jose/go-jose/v4@v${GO_JOSE_VERSION}" \
    && go build -ldflags "-s -w" -o /go/bin/syft github.com/anchore/syft/cmd/syft

FROM python:3.12-slim@sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f
# CVE-2026-109518(apt·libapt-pkg7.0, HIGH): 베이스 이미지(2026-10-28 빌드)의 apt 3.0.3을 데비안 보안 저장소의
# 수정판(3.0.4 이상)으로 올린다. 수정판을 못 받으면 빌드를 멈춘다(취약한 이미지가 조용히 나가지 않게).
# apt 목록 캐시는 같은 RUN에서 지운다. 이 단계는 root로 돌고, 아래에서 비 root 사용자로 바꾼다
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade apt libapt-pkg7.0 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' apt)" ge 3.0.4 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 10001 --create-home app \
    && mkdir /data && chown app:app /data
COPY --from=syft /go/bin/syft /usr/local/bin/syft
COPY --from=build /app/.venv /app/.venv
WORKDIR /app
# syft가 실행될 때 외부로 새 버전 확인 요청을 보내지 않게 한다
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1 SYFT_CHECK_FOR_APP_UPDATE=false
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]
CMD ["linkud", "--config", "/app/config.yaml"]
