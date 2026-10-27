# 오염 테스트 MCP 서버 이미지 (빌드 컨텍스트: 레포 루트)
# 베이스 이미지는 다이제스트로 고정한다 (태그 python:3.12-slim, 2026-10-27 기준). Dependabot이 갱신 PR을 연다
FROM python:3.12-slim@sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f
RUN pip install --no-cache-dir "mcp>=2.2,<3" "uvicorn>=0.30" \
    && useradd --create-home --uid 10001 app
WORKDIR /app
COPY eval/samples.py samples.py
COPY tests/fixtures/poisoned_servers/server.py server.py
USER app
ENV LINKUD_IN_DOCKER=1 PORT=9000
EXPOSE 9000
CMD ["python", "server.py"]
