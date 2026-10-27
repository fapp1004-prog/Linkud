# 오염 테스트 MCP 서버 이미지 (빌드 컨텍스트: 레포 루트)
FROM python:3.12-slim
RUN pip install --no-cache-dir "mcp>=2.2,<3" "uvicorn>=0.30" \
    && useradd --create-home --uid 10001 app
WORKDIR /app
COPY eval/samples.py samples.py
COPY tests/fixtures/poisoned_servers/server.py server.py
USER app
ENV LINKUD_IN_DOCKER=1 PORT=9000
EXPOSE 9000
CMD ["python", "server.py"]
