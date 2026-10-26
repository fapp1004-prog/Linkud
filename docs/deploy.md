# 배포 (기획서 7장)

EC2 한 대에서 Docker Compose로 게이트웨이·nginx(TLS)·certbot을 돌린다. `main`에 push하면
GitHub Actions가 테스트 → 이미지 빌드(GHCR) → SSH 배포를 한다.

```
에이전트 ──HTTPS(Bearer 토큰)──▶ nginx(:443, TLS·레이트 리밋·SSE 버퍼링 끔) ──▶ gateway(:8000, 비 root·읽기 전용 FS)
                                                                              └─ /data/linkud.db (판정 이력·감사 로그)
```

## 1. AWS 준비 (한 번)

1. **EC2**: t3.small, Ubuntu 24.04, 디스크 20GB 이상.
   보안 그룹 인바운드는 80·443(전체), 22(내 IP와 GitHub Actions에서만, 또는 SSM Session Manager 사용).
2. **도메인**: A 레코드를 EC2 탄력적 IP로 연결 (예: `gw.example.com`).
3. **비밀값**: SSM Parameter Store에 SecureString으로 저장.
   ```bash
   aws ssm put-parameter --type SecureString --name /linkud/ANTHROPIC_API_KEY --value 'sk-ant-...'
   aws ssm put-parameter --type SecureString --name /linkud/LINKUD_AUTH_TOKENS --value "$(openssl rand -hex 32)"
   ```
   토큰을 여러 개 쓰려면 쉼표로 잇는다(에이전트별 발급·회수용).
4. **IAM 역할**: EC2 인스턴스 프로파일에 최소 권한만 준다.
   ```json
   {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ssm:GetParameter",
     "Resource": "arn:aws:ssm:<region>:<account>:parameter/linkud/*"}]}
   ```
   (SecureString이 기본 KMS 키가 아니면 해당 키의 `kms:Decrypt`도 필요)

## 2. 서버 준비 (한 번)

```bash
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 awscli gettext-base curl
sudo usermod -aG docker ubuntu && newgrp docker
sudo mkdir -p /opt/linkud && sudo chown ubuntu /opt/linkud
# GHCR 패키지가 비공개면 read:packages 권한 토큰으로 로그인
echo "<PAT>" | docker login ghcr.io -u <github-user> --password-stdin
```

레포의 `deploy/` 내용을 `/opt/linkud/`에 복사한 뒤(첫 배포 Action이 해도 됨), 인증서를 발급한다.

```bash
cd /opt/linkud
DOMAIN=gw.example.com EMAIL=me@example.com ./init-letsencrypt.sh
```

`config.yaml`은 처음 한 번 `config.prod.yaml`에서 만들어지고, 이후로는 서버에서 직접 고친다
(다운스트림 목록, 각 서버의 `registry` 이름 등). 바꾼 뒤 `docker compose restart gateway`.

## 3. GitHub 설정

Settings → Secrets and variables → Actions:

| 이름 | 값 |
| --- | --- |
| `EC2_HOST` | EC2 주소 |
| `EC2_USER` | `ubuntu` |
| `EC2_SSH_KEY` | 배포 전용 SSH 개인키 (ed25519) |
| `EC2_KNOWN_HOSTS` | `ssh-keyscan <EC2_HOST>` 결과 |
| `LINKUD_DOMAIN` | `gw.example.com` |

`EC2_HOST`가 없으면 배포 워크플로는 이미지만 올리고 배포 단계를 건너뛴다.

## 4. 동작 확인

```bash
curl https://gw.example.com/healthz                       # {"status":"ok",...}
curl -X POST https://gw.example.com/mcp                   # 401 (토큰 없음)
```

에이전트(예: Claude Code)에 원격 MCP 서버로 등록한다.

```bash
claude mcp add --transport http linkud https://gw.example.com/mcp \
  --header "Authorization: Bearer <LINKUD_AUTH_TOKENS 중 하나>"
```

## 보안 메모

- 게이트웨이는 루프백이 아닌 주소에 바인딩할 때 접속 토큰이 없으면 시작하지 않는다(fail-closed).
- `allowed_hosts`로 Host 헤더를 검사한다(DNS 리바인딩 방지).
- 컨테이너: 비 root(uid 10001), 읽기 전용 루트 FS, 모든 capability 제거, `no-new-privileges`.
- 다운스트림 응답: 타임아웃(`call_timeout`)과 결과 크기 상한(`max_result_bytes`).
- 비밀값은 SSM → `.env`(권한 600)로만 들어가고 이미지·레포·로그·판별 프롬프트에 넣지 않는다.
- 공급망 검증용 syft는 이미지 빌드 때 릴리스 체크섬을 확인하고 설치한다. 패키지는 내려받아 풀기만 한다.
