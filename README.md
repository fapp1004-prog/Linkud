# 링커드 MCP Trust Gateway

AI가 쓰는 도구(MCP 서버)를 **AI에게 보여주기 전에** 검사해서, 위험한 도구는 AI 눈에 안 보이게 막는 검문소 프로그램.
링커슈 팀 AI:SHOOT 프로젝트 (7일 구현).

- 발표 이름: MCP 도구 설명 프롬프트 인젝션 탐지 기반 신뢰도-권한 자동 매핑 게이트웨이
- 전체 설명·용어집·일정: 팀 통합본 문서 참고

## 폴더 구조 (괄호 안이 담당자, 남의 폴더는 건드리지 않는다)

```
gateway/       proxy.py  cache.py  policy.py  audit.py  dashboard.py   (A)
checkers/      base.py — 약속 1, 셋이 같이
               injection.py  rules.py                                  (B)
               supply_chain.py  identity.py                            (C)
testservers/   calc_ok/  calc_poison/  rugpull/  vuln_dep/             (C)
eval/          dataset/  run_eval.py                                   (B)
policy.yaml    약속 2, 셋이 같이
.env           API 키 (GitHub에 올리지 않음, .env.example 복사해서 만들기)
```

## 시작하기

```bash
git clone https://github.com/fapp1004-prog/Linkud.git
cd Linkud
git checkout -b feat/proxy            # 내 갈래 (A: feat/proxy, B: feat/injection, C: feat/supply-chain)
python -m venv .venv                  # 가상환경 (선택)
pip install -r requirements.txt
cp .env.example .env                  # 키는 .env에만
```

매일: `main` 최신화 → 내 갈래에 merge → 작업 → push → PR → 다른 한 명이 훑어보고 Merge.

## 꼭 지킬 것

- API 키는 `.env`에만. 실수로 올렸으면 즉시 폐기하고 새로 발급.
- `main`에 직접 올리지 않는다. 각자 갈래에서 PR.
- 남의 폴더는 고치지 않는다. 고쳐야 하면 단톡에 먼저.
- `checkers/base.py`, `policy.yaml`을 바꾸면 셋 다 영향받으니 단톡에 먼저.

## D1 회의에서 정할 것

1. **검사기 입력 모양** — 결과 모양(약속 1)은 정했지만 입력은 아직. 제안: `check(tool: dict, server_dir: str) -> CheckResult`
2. **신호 이름 목록** — `ssh_key_access`, `critical_vuln`처럼 `signals`에 쓸 이름을 미리 맞춰둔다. `policy.yaml`의 `restrict_if_signals`가 이 이름을 본다.
3. **하드 룰 표현** — 결과에 확신도 필드가 없어서, "AI 확신도 0.8 이상 → 차단"은 B가 `hard_block=True`로 넘기는 것으로 정리함 (`policy.yaml` 참고). 이대로 갈지 확인.
4. **시연 장면 3개** — 완료 기준 참고: 포이즈닝 계산기 차단 / 러그풀 재검사 후 차단 / 취약 의존성 서버 제한→승인

## 완료 기준

- [ ] 포이즈닝 계산기 연결 → AI 앱 도구 목록에서 `add`가 사라지고 대시보드에 "차단 — ssh_key_access"
- [ ] 러그풀 서버 → 처음엔 허용, 설명이 바뀌면 지문 불일치로 재검사 후 차단
- [ ] 취약 의존성 서버 → "제한" 등급, 대시보드에서 승인해야 실행
- [ ] 성적표 → 탐지율·오탐률 수치 확보
