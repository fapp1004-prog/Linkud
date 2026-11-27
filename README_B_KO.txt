Linkud B 검사기·평가 코드 — 2026-11-27 검토본

이 변경은 B 담당 코드와 안내 문서만 포함합니다.
기준: A PR #23(e8f81d940146c628064b256b7a79405b976afb67)의 SPEC 3·4·6·10-1·13·14장.
https://github.com/fapp1004-prog/Linkud/pull/23
PR #23이 아직 main에 병합되지 않아 feat/a-decisions 위에 B 전용 브랜치를 쌓았습니다.
A PR 병합 후 B PR의 기준 브랜치를 main으로 바꾸어 검토해야 합니다.

1. B의 호출 위치
A가 checkers.injection.check(tool, server)를 호출합니다. 별도 B 서버는 없습니다.
- rules.scan(text) -> list[str]: A 정제 검사에서도 쓰는 규칙 함수.
- injection.check: 규칙 + LLM, CheckResult 반환. 오류는 raise하여 A가 제한 처리.
- b_metadata: 이름·설명·중첩 inputSchema·annotations·outputSchema·확장 필드 검사.
- b_prompt / llm_client: 판별 전용 지시, 엄격 JSON, 도구 권한 없는 OpenAI API 호출.
- llm_cache: LLM 결과·동시 요청·예산 장부. A 판정/승인 DB와 별개.
- b_config: .env를 읽되 API 키를 os.environ에 넣지 않음.
- eval/: 데이터 읽기, 점검, 유형별/짝별/반복 평가, 최종 설정 고정.

2. 설치·무료 코드 테스트 (프로젝트 루트 PowerShell)
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
.\.venv\Scripts\python.exe -m unittest discover -s checkers/tests -t . -v

B 테스트 48개입니다. C PR #25가 없으면 C 시연 연결 1개를 건너뜁니다.
테스트는 모의 API 응답만 사용합니다. 실제 API 키나 데이터셋 없이 실행 가능합니다.
검토 결과: A PR #23 기준 B 47개 통과·1개 건너뜀, C PR #25를 더한 참조 환경은 B 48개+C 27개 모두 통과.
A 게이트웨이 테스트는 52개 중 51개 통과, B 미구현을 전제한 기존 테스트 1개 실패(전달 문서 참조).
A/C 소스, checkers/base.py, policy.yaml, docs/SPEC.md, requirements.txt는 수정하지 않았습니다.

3. 데이터는 따로 넣기
GitHub에는 평가 원문과 정답을 포함하지 않았습니다.
이미 받은 로컬 Linkud_B_code.zip의 eval/dataset, eval/supplement 데이터 폴더를 같은 위치에 복사하세요.
다음 네 파일을 읽습니다.
- eval/dataset/aws_normal307.jsonl: AWS 정상 설명 307개 (assistant 검토 라벨).
- eval/dataset/mcptox200.jsonl: MCPTox 악성 200개.
- eval/supplement/supplement_attacks.jsonl: 보완 공격 80개.
- eval/supplement/supplement_baselines.jsonl: 공격 변형 전 기본형 80개. 이것도 악성입니다.

.\.venv\Scripts\python.exe -m eval.prepare_dataset
.\.venv\Scripts\python.exe -m eval.run_eval --input eval/dataset/aws_normal307.jsonl --dry-run

점검만 하며 API를 호출하지 않습니다. 네 파일 전체는 total 667, benign 307, malicious 360, pairs 80입니다.
보완셋의 reviewed=false는 그대로 유지합니다. AWS 자료에 없는 inputSchema를 만들어 채우지 않습니다.
tool 또는 tool_name/tool_content만 검사 입력으로 변환합니다. label·notes·base_id·출처는 모델에 보내지 않습니다.
같은 pair_id에 같은 variant가 두 번 있거나 짝의 원본/공격 유형이 다르면 평가 전에 오류로 거절합니다.
JSON과 JSONL에 같은 데이터가 있으면 한 쪽만 입력하세요.
기존 200과 보완셋은 원본 ID가 겹치지 않지만 서버 34개가 겹칩니다. 서로를 dev/final로 나누지 마세요.

4. API 설정
.env가 없다면 .env.b.example을 복사하여 프로젝트 루트 .env로 저장하세요.
이미 .env가 있으면 필요한 LINKUD_B_ 설정만 추가하세요.
발급받은 키는 .env의 OPENAI_API_KEY= 뒤에 적습니다. 실제 키를 GitHub에 올리지 마세요.
기본 모델은 gpt-5.4-mini-2026-03-17, 추론 low, 요청 전체 시간 제한 8초입니다.
모델과 위험도 수치는 B 초기 제안이며 팀 확정값은 eval/B_HANDOFF.txt를 보고 합의해야 합니다.

5. 실제 LLM 확인 (직접 실행하면 과금될 수 있음)
평가 실행기의 기본 method는 rules라서 무료입니다.
LLM/combined/compare에서 --live를 주어야 새 API 요청을 허용합니다. 생략하면 캐시만 읽습니다.
개발용으로 정한 파일 10개부터 비용·시간을 확인하세요. 사용한 표본은 최종 평가에서 제외합니다.

.\.venv\Scripts\python.exe -m eval.run_eval --input eval/dataset/dev.jsonl --method combined --limit 10 --live --output eval/reports/dev_pilot.json

dev.jsonl은 자동 생성하지 않았습니다. 별도로 확정한 개발용 파일 경로를 입력하세요.
API 실패·잘못된 JSON·예산 초과·크기 초과는 성공으로 바꾸지 않고 오류로 올립니다.
키가 없고 저장된 LLM 결과도 없으면 CacheMiss입니다. 파일 위치와 키를 확인하세요.

6. 보완 시험 (프롬프트·규칙 확정 후 별도 평가)
.\.venv\Scripts\python.exe -m eval.run_eval --input eval/supplement/supplement_attacks.jsonl eval/supplement/supplement_baselines.jsonl --method compare --stage supplement --limit 0 --live --output eval/reports/supplement.json

compare는 규칙만/LLM만/결합을 비교합니다. 결합은 같은 회차의 LLM 결과를 재사용하여 추가 호출하지 않습니다.
LLM이 실패하면 결합에서도 그 오류를 사용합니다. 예전 성공 캐시로 바꾸지 않습니다.
단, 규칙에서 확실한 hard_block이 나오면 합의대로 차단이 오류보다 우선합니다.
반복 LLM 측정은 --repeats 3 --fresh --live가 필요하며 추가 비용이 발생합니다.
검토 전 라벨은 결과에 표시하고 최종 평가와 분리합니다. 캐시/재사용 시간은 새 API 추론 속도가 아닙니다.

7. 최종 평가 준비
본 평가 후보는 정상 307 + 악성 200입니다. SPEC의 300/300을 채웠다고 보고하지 않습니다.
개발/최종 데이터 분할과 라벨 확정은 자동 처리하지 않았습니다.
확정한 입력 파일에 --write-freeze --limit 0 --freeze eval/dataset/FINAL_HASH.txt를 주면 API 없이 해시를 기록합니다.
같은 입력/모델/규칙/시간 제한/정책으로 --stage final --freeze 경로를 주어 평가합니다.
검토 전 보완셋은 final에서 거절합니다. 기존 최종 출력 경로는 다시 사용하지 마세요.
오류로 제한된 악성은 탐지 성공이 아니며, 정상 오류도 오탐과 분리하여 실행 보류율에 따로 집계합니다.
이 평가의 등급은 C가 모두 정상이라는 조건에서 A 정책을 적용한 B 기여분입니다. 전체 게이트웨이 방어 성적은 아닙니다.

8. 캐시·예산
data/llm_cache.db를 사용합니다. 삭제하면 재호출뿐 아니라 로컬 예산 기록도 초기화됩니다.
키: (A tool_hash, prompt_version, model, mode). 검사 원문 전체와 프롬프트 설정 지문도 대조합니다.
동시 최초 DB 생성 잠금은 짧게 재시도하고, 같은 도구의 동시 LLM 요청은 하나만 보냅니다.
API 요청 자체는 자동 재시도하지 않습니다. 실패한 요청은 과금 여부가 불확실하여 예약액을 유지합니다.
기본 로컬 한도는 $35입니다. 발표용 $5를 남기는 초기 설정입니다.
다른 PC/이 DB 밖의 API 사용량까지 제한하지는 못하므로 계정 전체 사용량은 제공자 콘솔에서도 확인하세요.

9. 남은 확인
실제 GPT 호출은 하지 않았습니다. 탐지율·오탐률·속도·multiply 판별 성공은 아직 측정하지 않았습니다.
A의 outputSchema 해시 누락, B 설정 변경 시 A 캐시 무효화, 환경변수 전달, 기존 테스트 가정 문제는
eval/B_HANDOFF.txt에 전달 사항으로만 기록했습니다. A/C 구현은 수정하지 않았습니다.

공식 API 문서 (2026-11-27 확인)
https://developers.openai.com/api/docs/models/gpt-5.4-mini
https://developers.openai.com/api/docs/guides/structured-outputs
