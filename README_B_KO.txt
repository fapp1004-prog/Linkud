Linkud B 검사기·평가 코드 — 2026-11-28

B 전용 PR #26. A PR #23의 feat/a-decisions를 기준으로 합니다.
https://github.com/fapp1004-prog/Linkud/pull/26
A/C 구현, SPEC, 공통 인터페이스, 정책, 의존성은 수정하지 않았습니다.
위험도·차단 규칙·모델·프롬프트는 팀 논의 전까지 이전 PR 값을 그대로 유지합니다.
B 검사·결과 캐시·평가 실행 기능을 구현한 상태이며 실제 성능 검증/최종 평가 완료를 뜻하지 않습니다.

1. 설치와 무료 테스트 (프로젝트 루트 PowerShell)
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
.\.venv\Scripts\python.exe -m unittest discover -s checkers/tests -t . -v

테스트는 모의 API와 테스트 전용 fixture만 씁니다. 실제 키/평가 데이터가 필요하지 않습니다.
C PR #25가 없으면 기존 C 시연 연결 테스트 한 개를 건너뜁니다.
기존 A 테스트 중 B 미구현을 전제한 한 개의 기대값은 A가 확인할 사항입니다.
2026-11-28 검증: A #23+C #25 참조 환경에서 B 79개+C 27개=106개 통과.
A 테스트 52개 중 51개 통과, 위 기존 가정의 1개 실패. 해당 A 파일은 수정하지 않았습니다.

2. B 호출과 설정
A가 checkers.injection.check(tool, server)를 호출하고 최종 등급을 정합니다.
B는 rules.scan(text)를 공개하고, LLM 결과는 data/llm_cache.db에 저장합니다.
B는 설명뿐 아니라 이름·중첩 inputSchema·annotations·outputSchema·확장 필드를 검사합니다.
키는 프로젝트 .env의 OPENAI_API_KEY에서 읽으며 os.environ에 넣지 않습니다.
.env가 없으면 .env.b.example을 복사하고, 있으면 필요한 B 설정만 추가하세요.
실제 키는 저장소에 올리지 마세요.

기존 모델 gpt-5.4-mini-2026-03-17, 추론 low, 온라인 시간 제한 8초를 유지합니다.
기존 위험도와 결정안의 차이는 eval/B_HANDOFF.txt에 있습니다. 이번 변경에서 조정하지 않았습니다.
API/파싱/시간 제한 오류는 A에 raise합니다. 오류를 정상 판정으로 바꾸지 않습니다.
B의 정상 확신도는 '악성 가능성 confidence'와 반대이므로 뒤집어 기록하지 않습니다.

3. 원본 데이터
AWS 정상 307개 원본을 그대로 사용합니다. 다른 정상 출처로 교체하거나 내용을 고치지 않습니다.
데이터는 GitHub에 포함하지 않습니다. 로컬에 아래 파일을 별도로 두세요.
- eval/dataset/aws_normal307.jsonl
- eval/dataset/mcptox200.jsonl
- eval/supplement/supplement_attacks.jsonl
- eval/supplement/supplement_baselines.jsonl

보완 baseline도 악성이며, reviewed=false를 자동으로 true로 바꾸지 않습니다.
데이터 정답·출처·분류 메모는 LLM에 전달하지 않습니다.
새 평가용 샘플이나 시연 문장을 생성하지 않았습니다.
수량 조정·실제 dev/final 분할·최종 표본 선정·드라이브 업로드는 이번 작업에서 하지 않았습니다.
별도 수량 보고서도 만들지 않습니다.

4. 데이터 구성 코드 — eval/build_dataset.py
원본을 보존하고, 명시적으로 --write를 주었을 때만 새 폴더에 선택한 레코드의 사본을 씁니다.
결정안의 seed 42, 서버 단위 dev/final 분리, 서버당 최대 3개, 정규화 후 difflib 유사도 0.9를 구현합니다.
원본에 서버 정보가 없으면 가짜 서버 이름을 붙이지 않고 제외합니다.
유사 묶음에 서로 다른 정답이 있으면 그 묶음을 보류합니다.
헷갈리는 정상은 별도 JSON의 hard_benign_ids 목록으로만 지정합니다. 자동 추정하지 않습니다.
목표/검토 라벨이 충족되지 않으면 분할 파일을 만들지 않습니다. 다른 수량을 임의 적용하지 않습니다.
기본 실행은 ready/written 여부만 출력하고 보고서를 저장하지 않습니다.
--report를 직접 지정할 때만 상세 점검 기록을 저장합니다.
--targets는 팀에서 별도로 확정한 수량 JSON을 받은 경우에만 사용하세요.

조건을 모두 충족한 --write 실행은 dev.jsonl, final.jsonl, FINAL_HASH.txt를 새 output-dir에 만듭니다.
FINAL_HASH.txt는 final.jsonl의 SHA-256 한 줄입니다. 데이터 원문과 로컬 경로는 들어가지 않습니다.
원본 JSON 필드/도구 설명/정답은 그대로 보존하며 입력 파일을 덮어쓰지 않습니다.
분할 탐색은 고정 seed로 제한된 횟수만 실행합니다. 탐색 실패는 수학적인 분할 불가능 증명이 아닙니다.

5. 개발 평가 — 온라인, 최대 5개 동시 실행
아래 dev.jsonl은 별도로 확정하여 준비한 개발 파일입니다. 이 PR에 자동 생성되어 있지 않습니다.
.\.venv\Scripts\python.exe -m eval.run_eval --input eval/dataset/dev.jsonl --method compare --limit 10 --workers 5 --live --output eval/reports/dev_pilot.json

--live를 직접 지정하면 원문이 OpenAI에 전송되고 과금될 수 있습니다. 생략하면 저장된 LLM 결과만 사용합니다.
기본 method는 무료 rules입니다. workers 기본 5, 허용 범위 1~5입니다.
작업마다 Inspector를 따로 두고 DB만 공유하여 서로의 API 호출/캐시 메타데이터가 섞이지 않습니다.
compare의 규칙/LLM/결합은 같은 회차 결과를 사용합니다. 실패를 예전 성공 캐시로 대체하지 않습니다.
반복 온라인 LLM 측정은 --repeats 3 --fresh --live로 새 응답을 받아야 합니다.
최종 평가를 온라인 --stage final로 실행하는 것은 막고, 아래 Batch 경로를 사용합니다.

6. 최종 Batch 평가 — 설정 동결 후 직접 실행
최종 파일/라벨/설정을 확정한 뒤의 사용법입니다. 이 PR 작업 중에는 제출하거나 평가하지 않았습니다.
먼저 데이터와 코드·모델·정책을 동결합니다. 이 단계는 API를 부르지 않습니다.
.\.venv\Scripts\python.exe -m eval.run_eval --input eval/dataset/final.jsonl --method compare --repeats 3 --limit 0 --write-freeze --freeze eval/dataset/FINAL_RUN.json

FINAL_RUN.json은 로컬 실행 설정입니다. GitHub에 올리는 데이터 해시 FINAL_HASH.txt와 별개입니다.
최종 입력은 파일 하나이며 같은 폴더의 FINAL_HASH.txt와 SHA-256이 일치해야 준비·제출·수집할 수 있습니다.
요청 파일을 준비합니다. 이 단계도 업로드/과금이 없습니다.
.\.venv\Scripts\python.exe -m eval.batch_eval prepare --input eval/dataset/final.jsonl --freeze eval/dataset/FINAL_RUN.json --repeats 3 --job eval/batch/final-run

실제 제출은 아래 명령을 직접 실행할 때만 일어납니다.
.\.venv\Scripts\python.exe -m eval.batch_eval submit --job eval/batch/final-run --live

제출 후 Batch ID와 예약액은 같은 B DB에 저장됩니다. PC를 껐다 켜도 다음 명령으로 이어갑니다.
.\.venv\Scripts\python.exe -m eval.batch_eval status --job eval/batch/final-run
.\.venv\Scripts\python.exe -m eval.batch_eval collect --job eval/batch/final-run

완료된 결과는 eval/batch/final-run/report.json에 저장합니다.
결과 순서가 달라도 custom_id로 표본과 회차를 연결합니다. 반복 3회는 서로 다른 요청입니다.
규칙/LLM/결합 비교는 같은 응답을 사용하며, 검증된 응답은 게이트웨이도 재사용할 수 있습니다.
실패·만료·취소·누락은 오류로 분리하고 자동 재시도하지 않습니다.
Batch의 개별 추론 시간은 측정할 수 없어 median_ms/p95_ms는 null로 기록합니다.
B 기여분을 C가 정상인 조건에서 측정한 결과이며 전체 게이트웨이 성능이 아닙니다.
같은 결과를 다시 collect해도 사용량을 중복 기록하거나 최종 보고서를 덮어쓰지 않습니다.

submit 응답을 못 받았으면 다시 제출하지 않습니다.
콘솔에서 해당 Batch ID를 확인한 뒤 다음으로 기존 작업을 연결합니다.
.\.venv\Scripts\python.exe -m eval.batch_eval recover --job eval/batch/final-run --batch-id batch_실제ID
다른 입력 파일/평가의 Batch는 연결할 수 없습니다. 기존 로컬 파일과 DB를 보존하세요.

7. 최종 평가 뒤의 추가 시험
판별기 공격 시험과 모델 비교는 완료된 최종 Batch 보고서를 --after-final로 지정해야 합니다.
보완 자료와 multiply 시연 문장의 라벨/문장 확정은 별도 팀 작업이며 자동 수정하지 않습니다.
.\.venv\Scripts\python.exe -m eval.run_eval --input eval/supplement/supplement_attacks.jsonl eval/supplement/supplement_baselines.jsonl --method compare --stage supplement --after-final eval/batch/final-run/report.json --limit 0 --workers 5 --live --output eval/reports/supplement.json

모델 비교도 --stage model-comparison --after-final 경로를 사용합니다.
사용할 비교 모델/단가/예산을 이번 PR에서 새로 정하지 않았습니다.

8. 예산과 기록
온라인과 Batch가 같은 data/llm_cache.db의 예약/사용량 장부를 사용합니다.
Batch는 일반 API 단가의 50%로 예약·usage 정산합니다. 반환이 불확실한 요청은 예약액을 유지합니다.
기존 로컬 한도 $35를 유지합니다. 다른 PC/다른 DB 사용량까지 합산하는 팀 전체 한도는 아닙니다.
DB 삭제·교체는 예산 기록과 Batch 복구 정보를 잃게 하므로 작업 중 그대로 보존하세요.
실제 API 호출·Batch 제출·탐지율/오탐률 측정은 이번 구현 작업에서 하지 않았습니다.

공식 API 계약 확인:
https://developers.openai.com/api/docs/guides/batch
https://developers.openai.com/api/reference/resources/batches/methods/create
