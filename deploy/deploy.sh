#!/usr/bin/env bash
# EC2에서 실행: 비밀값 갱신 → 설정 생성 → 새 이미지로 교체 → 헬스체크
#   GitHub Actions가 ssh로 부른다: LINKUD_IMAGE=<이미지> DOMAIN=<도메인> ./deploy.sh
set -euo pipefail
cd "$(dirname "$0")"
: "${DOMAIN:?DOMAIN 필요}"
export LINKUD_IMAGE="${LINKUD_IMAGE:-ghcr.io/fapp1004-prog/linkud:latest}"

./fetch-secrets.sh .env
if [ ! -f config.yaml ]; then
  # 처음 한 번만 템플릿에서 만든다. 다운스트림 목록은 서버에서 직접 관리한다
  DOMAIN="$DOMAIN" envsubst '${DOMAIN}' < config.prod.yaml > config.yaml
fi

docker compose pull gateway
docker compose up -d --remove-orphans
for i in $(seq 1 30); do
  if curl -fsS "https://${DOMAIN}/healthz" >/dev/null; then
    echo "배포 완료: ${LINKUD_IMAGE}"
    docker image prune -f >/dev/null
    exit 0
  fi
  sleep 2
done
echo "헬스체크 실패" >&2
docker compose logs --tail 100 gateway >&2
exit 1
