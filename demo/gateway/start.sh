#!/bin/sh
# 시연용 게이트웨이 시작: 토큰 파일을 환경변수로 넘기고, ANTHROPIC_API_KEY가 있을 때만 AI 판사를 켠다.
# 토큰 파일이 없으면 시작하지 않는다(fail-closed).
set -eu
SECRETS="${DEMO_SECRETS_DIR:-/run/demo-secrets}"
CONFIG_DIR="${DEMO_CONFIG_DIR:-/demo}"
LINKUD_AUTH_TOKENS="$(cat "$SECRETS/agent")"
LINKUD_ADMIN_TOKENS="$(cat "$SECRETS/admin")"
export LINKUD_AUTH_TOKENS LINKUD_ADMIN_TOKENS
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    CONFIG="$CONFIG_DIR/config.claude.yaml"
else
    CONFIG="$CONFIG_DIR/config.fake.yaml"
fi
exec linkud --config "$CONFIG"
