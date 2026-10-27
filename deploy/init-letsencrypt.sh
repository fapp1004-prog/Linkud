#!/usr/bin/env bash
# 최초 1회: 임시 인증서로 nginx를 띄우고 Let's Encrypt 인증서를 발급받아 교체한다.
#   DOMAIN=gw.example.com EMAIL=me@example.com ./init-letsencrypt.sh
set -euo pipefail
cd "$(dirname "$0")"
: "${DOMAIN:?DOMAIN 필요}" "${EMAIL:?EMAIL 필요}"
export DOMAIN
live="/etc/letsencrypt/live/${DOMAIN}"

# nginx는 시작할 때 gateway 업스트림을 찾으므로 게이트웨이도 함께 띄울 준비를 한다
./fetch-secrets.sh .env
[ -f config.yaml ] || envsubst '${DOMAIN}' < config.prod.yaml > config.yaml

docker compose run --rm --entrypoint sh certbot -c "
  mkdir -p ${live} && [ -f ${live}/fullchain.pem ] || openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -keyout ${live}/privkey.pem -out ${live}/fullchain.pem -subj /CN=localhost"
docker compose up -d nginx
docker compose run --rm --entrypoint sh certbot -c "rm -rf ${live} /etc/letsencrypt/archive/${DOMAIN} /etc/letsencrypt/renewal/${DOMAIN}.conf"
docker compose run --rm --entrypoint certbot certbot certonly --webroot -w /var/www/certbot \
  -d "${DOMAIN}" --email "${EMAIL}" --agree-tos --no-eff-email
docker compose exec nginx nginx -s reload
echo "인증서 발급 완료: ${DOMAIN}"
