# 배포 (기획서 7장)

EC2 한 대에서 Docker Compose로 게이트웨이·nginx(TLS)·certbot을 돌린다. `main`에 push하면
GitHub Actions가 테스트 → 이미지 빌드(GHCR) → SSH 배포를 한다.

```
에이전트 ──HTTPS(Bearer 토큰)──▶ nginx(:443, TLS·레이트 리밋·SSE 버퍼링 끔) ──▶ gateway(:8000, 비 root·읽기 전용 FS)
                                                                              └─ /data/linkud.db (판정 이력·감사 로그)
```

## 1. AWS 준비 (한 번)

1. **EC2**: t3.small, Ubuntu 24.04, 디스크 20GB 이상.
   보안 그룹 인바운드는 80·443(전체)만 연다. 22번은 열지 않고 SSM Session Manager로 접속한다(아래 1-2).
   SSH 배포 워크플로(`deploy.yml`)를 쓸 때만 22번을 GitHub Actions·내 IP로 제한해 연다.
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

## 1-1. 계정·인스턴스 보안 기본값 (한 번)

**루트 계정 MFA와 일상 사용 금지**
- 루트 사용자에 MFA(하드웨어 키 또는 TOTP)를 등록하고, 루트 액세스 키는 만들지 않는다(있으면 삭제).
- 일상 작업은 IAM Identity Center 사용자나 MFA를 건 IAM 사용자로 한다.
  ```bash
  aws iam get-account-summary --query 'SummaryMap.{RootMFA:AccountMFAEnabled,RootKeys:AccountAccessKeysPresent}'
  # 기대값: RootMFA = 1, RootKeys = 0
  ```

**예산 알림** — 판별 LLM 호출·EC2 비용이 예상을 넘으면 메일을 받는다.
```bash
aws budgets create-budget --account-id <account> \
  --budget '{"BudgetName":"linkud-monthly","BudgetLimit":{"Amount":"30","Unit":"USD"},"TimeUnit":"MONTHLY","BudgetType":"COST"}' \
  --notifications-with-subscribers '[
    {"Notification":{"NotificationType":"ACTUAL","ComparisonOperator":"GREATER_THAN","Threshold":80,"ThresholdType":"PERCENTAGE"},
     "Subscribers":[{"SubscriptionType":"EMAIL","Address":"me@example.com"}]},
    {"Notification":{"NotificationType":"FORECASTED","ComparisonOperator":"GREATER_THAN","Threshold":100,"ThresholdType":"PERCENTAGE"},
     "Subscribers":[{"SubscriptionType":"EMAIL","Address":"me@example.com"}]}]'
```
Claude API 쪽 지출 한도는 Anthropic 콘솔의 워크스페이스 한도로 따로 건다.

**IMDSv2 필수 + 응답 홉 제한 1** — 인스턴스 메타데이터(인스턴스 역할 자격 증명)를 토큰 없이 못 읽게 하고,
홉 제한 1로 컨테이너(브리지 네트워크는 홉이 하나 더 늘어남)에서는 아예 닿지 않게 한다.
비밀값을 받는 `fetch-secrets.sh`는 호스트에서 돌므로 영향이 없다.
```bash
aws ec2 modify-instance-metadata-options --instance-id <i-...> \
  --http-tokens required --http-put-response-hop-limit 1 --http-endpoint enabled

# 확인 (로컬에서)
aws ec2 describe-instances --instance-ids <i-...> \
  --query 'Reservations[].Instances[].MetadataOptions.{Tokens:HttpTokens,Hop:HttpPutResponseHopLimit}'
# 기대값: Tokens = required, Hop = 1

# 확인 (인스턴스에서): 토큰 없는 IMDSv1 요청은 401
curl -s -o /dev/null -w '%{http_code}\n' http://169.254.169.254/latest/meta-data/   # 401
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id   # 성공

# 확인 (컨테이너에서): 홉 제한 때문에 토큰 발급부터 실패해야 한다
docker run --rm curlimages/curl:8.10.1 -s -m 3 -X PUT http://169.254.169.254/latest/api/token \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' || echo "컨테이너에서 IMDS 접근 불가 (정상)"
```
새로 만드는 인스턴스는 시작 템플릿에 `MetadataOptions: {HttpTokens: required, HttpPutResponseHopLimit: 1}`를 넣는다.

## 1-2. 22번 대신 SSM Session Manager로 접속

1. 인스턴스 역할에 관리형 정책 `AmazonSSMManagedInstanceCore`를 붙인다(Ubuntu 24.04 AMI에는 SSM 에이전트가 들어 있다).
2. 보안 그룹에서 22번 인바운드를 지운다.
3. 로컬에 Session Manager 플러그인을 설치하고 접속한다.
   ```bash
   aws ssm start-session --target <i-...>
   aws ssm describe-instance-information --query 'InstanceInformationList[].{Id:InstanceId,Ping:PingStatus}'  # Online 확인
   ```
4. 세션 기록이 필요하면 Session Manager 기본 설정에서 CloudWatch Logs·S3 기록을 켠다.

22번을 닫으면 SSH 기반 `deploy.yml`은 쓸 수 없다. 대신 GitHub OIDC + SSM Run Command로 배포하는
`deploy-oidc.yml`을 쓴다(아래 6장).

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

## 4-1. 접속 토큰 무중단 교체

게이트웨이는 `LINKUD_AUTH_TOKENS`의 토큰을 모두 받아 주므로, 새 토큰과 옛 토큰을 잠시 함께 등록해 끊김 없이 바꾼다.
관리 토큰(`LINKUD_ADMIN_TOKENS`)도 같은 방법으로 바꾼다.

1. **새 토큰을 추가** (옛 토큰은 유지)
   ```bash
   NEW=$(openssl rand -hex 32)
   OLD=$(aws ssm get-parameter --with-decryption --name /linkud/LINKUD_AUTH_TOKENS --query Parameter.Value --output text)
   aws ssm put-parameter --overwrite --type SecureString --name /linkud/LINKUD_AUTH_TOKENS --value "${OLD},${NEW}"
   ```
2. **재배포** — `main`에 push하거나 워크플로를 수동 실행(`deploy.sh`가 SSM에서 `.env`를 다시 받고 컨테이너를 교체).
   이제 옛 토큰과 새 토큰이 모두 통한다.
3. **에이전트 설정을 새 토큰으로 바꾼다** (`claude mcp add ... --header "Authorization: Bearer <새 토큰>"`).
   감사 로그·nginx 접근 로그에서 옛 토큰을 쓰는 요청이 더 없는지 확인한다(401이 없어야 함).
4. **옛 토큰 제거 후 다시 재배포**
   ```bash
   aws ssm put-parameter --overwrite --type SecureString --name /linkud/LINKUD_AUTH_TOKENS --value "${NEW}"
   ```
5. 확인: 옛 토큰으로 `curl -X POST -H "Authorization: Bearer $OLD" https://gw.example.com/mcp` → 401.

토큰이 유출됐다면 1~3을 건너뛰고 바로 4(옛 토큰 제거 + 재배포)를 한다.

## 5. 승인 대기 처리 (확장)

**관리 API** — SSM에 `/linkud/LINKUD_ADMIN_TOKENS`를 넣으면 열린다(에이전트 토큰과 별개).

```bash
H="Authorization: Bearer <관리 토큰>"
curl -H "$H" https://gw.example.com/admin/pending          # 승인 대기 도구와 근거
curl -H "$H" https://gw.example.com/admin/servers          # 서버 등급
curl -H "$H" "https://gw.example.com/admin/audit?limit=50" # 감사 로그
curl -H "$H" -X POST https://gw.example.com/admin/decisions \
  -d '{"server":"s","tool":"t","tool_hash":"<pending의 해시>","tier":"partial","note":"검토함"}'
```

확정은 그 정의(해시)에만 적용된다. 승인 뒤 설명이 바뀌면 다시 검증 경로를 탄다.

**Slack 승인 버튼**
1. Slack 앱을 만들고 Incoming Webhooks를 켜서 채널 웹훅 URL을 받는다 → `/linkud/SLACK_WEBHOOK_URL`
2. Interactivity를 켜고 Request URL을 `https://gw.example.com/slack/actions`로 둔다
3. Basic Information의 Signing Secret → `/linkud/SLACK_SIGNING_SECRET`
4. (권장) 승인할 사람의 Slack 사용자 ID 목록 → `/linkud/SLACK_APPROVERS` (쉼표 구분)

nginx 설정(`deploy/nginx/templates/linkud.conf.template`)은 `/mcp`, `/healthz`, `/admin`, `/slack/actions`만 넘긴다.

## 6. 대안: GitHub OIDC + SSM Run Command 배포 (`deploy-oidc.yml`)

> **검증하지 않음.** 이 워크플로와 아래 정책은 문서와 AWS CLI 형식에 맞춰 작성했지만 실제 AWS 계정에서
> 동작을 확인하지 않았다. 처음 쓸 때는 시험용 인스턴스에서 먼저 돌려 본다.

SSH 키·22번 포트·장기 AWS 액세스 키 없이 배포한다. GitHub이 발급한 OIDC 토큰으로 IAM 역할을 잠시
맡고(임시 자격 증명), SSM Run Command로 인스턴스에서 `deploy.sh`를 실행한다. 배포 파일은 압축해 명령에
실어 보낸다. 수동 실행(`workflow_dispatch`)이며 `main` 브랜치에서만 돈다.

**1. OIDC 공급자 (계정에 한 번)**
```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com --client-id-list sts.amazonaws.com
```

**2. 배포 역할의 신뢰 정책** — `sub`를 이 레포의 `main` 브랜치로 고정한다(다른 브랜치·PR·포크는 맡을 수 없음).
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::<account>:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:fapp1004-prog/Linkud:ref:refs/heads/main"
      }
    }
  }]
}
```
`StringLike`와 와일드카드(`repo:fapp1004-prog/Linkud:*`)는 쓰지 않는다. 그러면 모든 브랜치·PR이 역할을 맡을 수 있다.
GitHub Environment로 승인 단계를 두려면 sub가 `repo:fapp1004-prog/Linkud:environment:<이름>` 형식으로 바뀌므로
신뢰 정책도 그에 맞춘다.

**3. 배포 역할의 권한 정책** — 이 인스턴스에 `AWS-RunShellScript`를 보내고 결과를 읽는 것만 허용한다.
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "ssm:SendCommand",
     "Resource": ["arn:aws:ssm:<region>::document/AWS-RunShellScript",
                  "arn:aws:ec2:<region>:<account>:instance/<i-...>"]},
    {"Effect": "Allow", "Action": ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations"], "Resource": "*"}
  ]
}
```
인스턴스 쪽에는 1-2의 `AmazonSSMManagedInstanceCore`가 필요하다.

**4. GitHub 시크릿**

| 이름 | 값 |
| --- | --- |
| `AWS_DEPLOY_ROLE_ARN` | 위 역할 ARN |
| `AWS_REGION` | 예: `ap-northeast-2` |
| `EC2_INSTANCE_ID` | `i-...` |
| `LINKUD_DOMAIN` | `gw.example.com` |

Actions 탭에서 **Deploy (OIDC + SSM)** 를 수동 실행한다. 이미지를 비우면 `ghcr.io/<owner>/linkud:latest`를 배포한다.
이 방식으로 옮기면 `deploy.yml`의 SSH 배포 단계(`EC2_HOST` 등 시크릿)는 지운다.

## 보안 메모

- 게이트웨이는 루프백이 아닌 주소에 바인딩할 때 접속 토큰이 없으면 시작하지 않는다(fail-closed).
- `allowed_hosts`로 Host 헤더를 검사한다(DNS 리바인딩 방지).
- 컨테이너: 비 root(uid 10001), 읽기 전용 루트 FS, 모든 capability 제거, `no-new-privileges`.
- 다운스트림 응답: 타임아웃(`call_timeout`)과 결과 크기 상한(`max_result_bytes`).
- 인자 검사: 허용된 도구라도 `~/.ssh`·클라우드 자격 증명·개인키 내용 등으로 부르면 거부(값은 로그에 남기지 않음).
- 비밀값은 SSM → `.env`(권한 600)로만 들어가고 이미지·레포·로그·판별 프롬프트에 넣지 않는다.
- 공급망 검증용 syft는 이미지 빌드 때 다이제스트 고정 Go 툴체인으로 소스에서 빌드한다(모듈 무결성은 Go sumdb 확인).
  배포 바이너리가 취약한 Go 버전으로 빌드돼 있어서다. 패키지는 레지스트리 해시를 확인하고 풀기만 한다.
- CI는 pip-audit(의존성)·Trivy(이미지, Critical·High 수정판 있는 취약점이면 실패)·syft 이미지 SBOM 첨부를 돌린다.
