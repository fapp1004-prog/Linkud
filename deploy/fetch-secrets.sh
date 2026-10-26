#!/usr/bin/env bash
# SSM Parameter Store에서 비밀값을 받아 .env(권한 600)로 쓴다. EC2 인스턴스 역할로 인증한다.
#   필요한 파라미터: /linkud/ANTHROPIC_API_KEY, /linkud/LINKUD_AUTH_TOKENS (SecureString)
set -euo pipefail
PREFIX="${SSM_PREFIX:-/linkud}"
OUT="${1:-.env}"
umask 077
tmp="$(mktemp)"
for name in ANTHROPIC_API_KEY LINKUD_AUTH_TOKENS; do
  value="$(aws ssm get-parameter --with-decryption --name "${PREFIX}/${name}" --query Parameter.Value --output text)"
  printf '%s=%s\n' "$name" "$value" >> "$tmp"
done
mv "$tmp" "$OUT"
echo "비밀값 ${OUT} 갱신 (값은 출력하지 않음)"
