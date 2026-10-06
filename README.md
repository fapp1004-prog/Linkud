# Linkud — MCP 도구 신뢰도 판정 게이트웨이

AI 에이전트가 MCP 서버의 도구를 **연결하기 전에** 검증하고, 신뢰 등급에 따라 실행 권한을 자동으로 정하는 중계 게이트웨이.

> 링커스 20기 링커슈 팀 **링커드(Linkus guard)** 의 확정 주제
> 「MCP 도구 설명 프롬프트 인젝션 탐지 기반 신뢰도-권한 자동 매핑 게이트웨이」의 개인 구현 (이정우)

```
에이전트 ──MCP──▶ [ Linkud 게이트웨이 ] ──MCP──▶ 다운스트림 MCP 서버들
(Claude 등)          │ 등록 시점: 무거운 검증 (규칙 필터 → LLM 판별 → OSV 조회)
                     │ 런타임:   해시 → 캐시된 등급만 조회 (LLM 호출 없음)
                     └ 변경 감지: 도구 정의 해시가 바뀌면 재검증 (러그풀 방어)
```

## 왜 필요한가

- 도구 포이즈닝은 **도구 설명(description)·스키마가 LLM 컨텍스트에 들어가는 순간** 성립한다. 모델 자체 안전장치로는 막기 어렵다(MCPTox: 평균 공격 성공률 36.5%, 최고 72.8%).
- MCP 스펙은 신뢰되지 않은 서버의 도구 정보를 untrusted로 다루라고만 하고, 실제 검증·접근통제는 구현자에게 맡긴다.
- 기존 도구(MCPProxy, Snyk Agent Scan 등)는 스캔·피닝 같은 개별 기능 단위다. 이 프로젝트는 **탐지 → 등급 산출 → 권한 집행**을 하나의 파이프라인으로 묶는다.

## 설계 원칙 (실무자 인터뷰 반영)

| 원칙 | 근거 |
|---|---|
| 무거운 검증은 등록·변경 시점에, 런타임은 해시·캐시만 확인 | 유연호 교수님 인터뷰 Q7·Q8 |
| 워크로드 신원만으로는 도구 설명·기능을 신뢰할 수 없음 → 도구 수준 검증 계층 | 인터뷰 Q6 |
| LLM은 자연어(도구 설명) 판별에만, SBOM·CVE 조회는 규칙 기반 | 팀 Decision Log 4단계 |
| 확실한 악성만 자동 차단, 애매하면 사람이 2차 판단 | 팀 4차 회의 |

### 개인 구현에서 정할 것 (초안)

- BLOCK 도구는 호출만 막지 않고 `tools/list`에서 제거 — 설명문이 컨텍스트에 들어가는 것 자체가 공격이므로
- 다운스트림은 원격 HTTP MCP 서버만 허용 — 게이트웨이에서 검증 안 된 명령을 실행하지 않기 위해
- 검증 실패 시 fail-closed
- 등급 합산은 가중합 점수 대신 결정 테이블 — 판정 근거를 설명할 수 있도록

## 로드맵

- [ ] **1단계 — 투명 프록시**: 다운스트림 도구를 모아서 보여주고, 호출을 그대로 전달
- [ ] **2단계 — 판정 파이프라인**: 도구 정의 해시, 등급 캐시, 러그풀 감지, 규칙 필터, LLM 판별, 결정 테이블(ALLOW / REVIEW / BLOCK)
- [ ] **3단계 — 테스트 서버·평가**: 정상·오염·러그풀 서버, MCPTox 기반 탐지율·오탐률, 지연 측정
- [ ] **4단계 — 배포**: EC2 + nginx(TLS), 게이트웨이 인증, Secrets Manager, Redis/DB, REVIEW 승인 API, CI/CD
- [ ] **5단계 — 정리**: 평가 결과, 한계(런타임 응답 인젝션 미탐지 등)

## 폴더 구조

```
gateway/        게이트웨이 본체
test_servers/   검증용 MCP 서버 (정상 / 오염 / 러그풀)
tests/          테스트
deploy/         배포 설정 (docker, nginx 등)
config.example.yaml   게이트웨이 설정 예시
```

## 참고

- MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers (arXiv 2508.14925)
- Invariant Labs, MCP Security Notification: Tool Poisoning Attacks (2025.04)
- OWASP GenAI Security Project, Top 10 for Agentic Applications (ASI04), MCP Top 10 (MCP03)
- MCP Specification 2026-07-28 — Tools
