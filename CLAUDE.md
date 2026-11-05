# Linkud

AI 에이전트와 MCP 서버 사이의 보안 게이트웨이. 도구 정의(`tools/list`)를 에이전트에게 보여주기 전에 검증하고,
서버별 신뢰 등급(신뢰 / 부분신뢰 / 불신 / 승인 대기)에 따라 도구 노출과 호출을 통제한다.
전체 기획은 `docs/기획서.md`가 기준이다. 설계 판단이 필요하면 먼저 거기를 읽고, 기획서와 다르게 가야 하면 이유를 PR 설명에 적는다.

## 기술 스택
- Python 3.12, MCP Python SDK (게이트웨이는 에이전트 쪽에선 서버, 다운스트림 쪽에선 클라이언트)
- 통신: Streamable HTTP. 다운스트림은 원격 HTTP MCP 서버만 등록받는다 (stdio 서버 실행 금지)
- 저장소: 1차는 SQLite + 파이썬 메모리 캐시. 반드시 인터페이스(`Store`, `Cache`) 뒤에 숨겨서 나중에 PostgreSQL/Redis로 바꿀 수 있게 한다
- LLM 판별기: 모델 미정. `Judge` 인터페이스 + 테스트용 `FakeJudge`를 두고, 실제 공급자는 어댑터로 붙인다
- 공급망: MCP Registry API, syft, OSV API
- 패키지 관리: uv, 테스트: pytest (+ pytest-asyncio), 린트/포맷: ruff
- 배포: Docker Compose on EC2, nginx(TLS, SSE 버퍼링 off), GitHub Actions

## 폴더 구조 (목표)
```
src/linkud/
  proxy/        # 투명 프록시: 에이전트용 서버면 + 다운스트림 클라이언트
  enforcement/  # 목록 필터, 호출 가드 (런타임 경로: 캐시만 조회, LLM 호출 금지)
  verify/       # 검증 경로
    hashing.py  # 도구 정의 정규화·해시
    rules.py    # 규칙 필터
    judge/      # LLM 판별기 인터페이스·어댑터
    supply/     # Registry → 패키지 → SBOM → OSV, annotations 불일치
    decision.py # 결정 테이블 → 등급
  store/        # Cache, Store 인터페이스와 구현
  admin/        # 관리 API (확장)
  config.py
tests/
  fixtures/poisoned_servers/  # 오염 테스트 MCP 서버 (Docker 안에서만 실행)
eval/           # 탐지·지연 평가 스크립트
deploy/         # Dockerfile, compose, nginx, Actions
docs/기획서.md
```

## 반드시 지킬 원칙
1. **런타임 경로와 검증 경로를 분리한다.** `tools/call` 가드는 캐시 조회만 한다. LLM·네트워크 호출 금지.
2. **fail-closed.** 검증 실패·타임아웃·예외가 나면 해당 도구는 숨기고 호출은 거부한다. 절대 "통과"로 떨어지지 않게 한다.
3. **러그풀 = 해시 변경.** 도구 정의(이름·설명·inputSchema·annotations)를 정규화해서 해시하고, 해시가 바뀌면 캐시 미스로 재검증한다. 같은 도구에 대한 동시 검증은 락으로 1회만 돈다.
4. **서버 등급 = 가장 위험한 도구 기준.** 결정 테이블은 점수 합산이 아니라 위에서부터 첫 매칭 (`docs/기획서.md` 5장).
5. **읽기 도구 판별은 보수적으로.** readOnlyHint, 이름 패턴, LLM 판단 세 신호가 모두 "읽기"일 때만 읽기. 하나라도 애매하면 쓰기.
6. **판별 LLM 격리.** 판별기에 도구·파일·네트워크 접근을 주지 않는다. 프롬프트에 API 키·설정·환경변수를 넣지 않는다. 출력은 정해진 JSON 스키마(verdict, is_write, reasons)만 파싱하고, 파싱 실패는 "의심"으로 처리한다. 검사 대상 설명은 구분자로 감싼다.
7. **공급망 검증 시 패키지는 내려받기만 한다.** 설치·실행 금지 (npm install 스크립트 등).
8. **비밀값은 코드·로그·프롬프트에 넣지 않는다.** 환경변수로 받고, 운영에서는 AWS SSM/Secrets Manager.
9. 판정에는 항상 **근거(reasons)** 를 남기고 감사 로그에 기록한다.

## 작업 방식
- 외부 API(LLM, Registry, OSV)를 부르는 코드는 테스트에서 반드시 목/픽스처로 대체한다. 클라우드 세션 네트워크는 허용 목록 기반이라 실제 호출이 막힐 수 있다.
- 새 모듈은 테스트와 함께 추가한다. 커밋 전 `uv run pytest`와 `uv run ruff check`를 통과시킨다.
- 한 작업은 한 브랜치에서 하나의 모듈 범위만 건드린다. 다른 모듈의 인터페이스를 바꿔야 하면 PR 설명에 명시한다.
- 주석과 문서는 한국어, 코드 식별자는 영어.
- 사용자에게 보내는 모든 메시지(중간 진행 상황, 보고, PR 설명)는 한국어로 쓴다. 코드 식별자·명령어·로그 원문은 그대로 둔다.

## 범위 밖 (구현하지 않음)
도구 응답 안의 인젝션 탐지, SPIFFE/mTLS, 원격 서버 소스코드 분석, stdio 서버 실행.
