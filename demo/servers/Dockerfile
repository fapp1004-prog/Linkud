# 시연용 MCP 서버 이미지 (빌드 컨텍스트: 레포 루트). tests/fixtures/poisoned_servers와 같은 격리 방식
# 베이스 이미지는 다이제스트로 고정한다 (태그 python:3.12-slim, 2026-10-27 기준)
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
# CVE-2026-109518(apt·libapt-pkg7.0, HIGH): 베이스 이미지(2026-10-28 빌드)의 apt 3.0.3을 데비안 보안 저장소의
# 수정판(3.0.4 이상)으로 올린다. 수정판을 못 받으면 빌드를 멈춘다(취약한 이미지가 조용히 나가지 않게).
# apt 목록 캐시는 같은 RUN에서 지운다. 이 단계는 root로 돌고, 아래에서 비 root 사용자로 바꾼다
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade apt libapt-pkg7.0 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' apt)" ge 3.0.4 \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "mcp>=2.2,<3" "uvicorn>=0.30" \
    && useradd --create-home --uid 10001 app
WORKDIR /app
# 오염 문장은 복사하지 않고 평가 샘플 파일을 그대로 넣어 import한다
COPY eval/samples.py samples.py
COPY demo/servers/demo_server.py demo_server.py
USER app
ENV LINKUD_IN_DOCKER=1 PORT=9000
EXPOSE 9000
CMD ["python", "demo_server.py"]
