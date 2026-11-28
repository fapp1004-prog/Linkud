"""B 소유 SQLite: LLM 결과 + 호출 예약/사용량. A의 판정·승인 DB와 별개다."""
import hashlib
import json
import math
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path


class BudgetExceeded(RuntimeError):
    pass


class CacheMiss(RuntimeError):
    pass


class LLMCache:
    def __init__(self, path, *, deadline=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        until = min(deadline if deadline is not None else float('inf'), time.monotonic() + 1.0)
        while True:
            try:
                self._initialize()
                return
            except sqlite3.OperationalError as exc:
                code = getattr(exc, 'sqlite_errorcode', 0) & 255
                if code not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) or time.monotonic() >= until:
                    raise
                # 여러 게이트웨이가 첫 DB를 동시에 만들 때의 잠금만 짧게 재시도.
                # API 요청을 다시 보내는 재시도는 아니다.
                time.sleep(min(0.02, max(0, until - time.monotonic())))

    def _initialize(self):
        with self.connection() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS llm_results (
                    tool_hash TEXT, prompt_version TEXT, model TEXT, mode TEXT,
                    payload_hash TEXT NOT NULL, prompt_fp TEXT NOT NULL,
                    result TEXT NOT NULL, usage TEXT NOT NULL, created REAL NOT NULL,
                    PRIMARY KEY(tool_hash,prompt_version,model,mode));
                CREATE TABLE IF NOT EXISTS llm_calls (
                    id TEXT PRIMARY KEY, model TEXT, mode TEXT, created REAL,
                    status TEXT, charged_micro_usd INTEGER NOT NULL,
                    usage TEXT NOT NULL DEFAULT '{}');
                CREATE TABLE IF NOT EXISTS llm_leases (
                    lease_key TEXT PRIMARY KEY, owner TEXT, expires REAL);
                CREATE TABLE IF NOT EXISTS b_batch_runs (
                    run_key TEXT PRIMARY KEY, state TEXT NOT NULL,
                    input_file_id TEXT, batch_id TEXT);
            ''')

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=0.4)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def acquire(self, key, payload_hash, prompt_fp, reserve, budget, *, deadline, cache_only=False, fresh=False):
        lease_key = hashlib.sha256(json.dumps([key, payload_hash, prompt_fp]).encode()).hexdigest()
        while time.monotonic() < deadline:
            with self.connection() as db:
                db.execute('BEGIN IMMEDIATE')
                row = db.execute('SELECT * FROM llm_results WHERE tool_hash=? AND prompt_version=? AND model=? AND mode=?', key).fetchone()
                if not fresh and row and row['payload_hash'] == payload_hash and row['prompt_fp'] == prompt_fp:
                    return {'cached': json.loads(row['result']), 'usage': json.loads(row['usage'])}
                if cache_only:
                    raise CacheMiss('저장된 LLM 결과가 없습니다. API를 호출하지 않았습니다.')
                db.execute('DELETE FROM llm_leases WHERE expires < ?', (time.time(),))
                busy = db.execute('SELECT owner FROM llm_leases WHERE lease_key=?', (lease_key,)).fetchone()
                if not busy:
                    used = db.execute('SELECT COALESCE(SUM(charged_micro_usd),0) FROM llm_calls').fetchone()[0]
                    if used + reserve > math.floor(budget * 1_000_000):
                        raise BudgetExceeded('로컬 LLM 예산 한도로 호출을 보류했습니다.')
                    owner = uuid.uuid4().hex
                    db.execute('INSERT INTO llm_calls(id,model,mode,created,status,charged_micro_usd) VALUES(?,?,?,?,?,?)',
                               (owner, key[2], key[3], time.time(), 'reserved', reserve))
                    db.execute('INSERT INTO llm_leases VALUES(?,?,?)', (lease_key, owner, time.time() + 15))
                    return {'owner': owner, 'lease_key': lease_key}
            time.sleep(min(0.04, max(0, deadline - time.monotonic())))
        raise TimeoutError('같은 도구의 LLM 검사 대기 시간이 초과되었습니다.')

    def complete(self, ticket, key, payload_hash, prompt_fp, result, usage, charged):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            lease = db.execute('SELECT owner FROM llm_leases WHERE lease_key=?', (ticket['lease_key'],)).fetchone()
            if not lease or lease[0] != ticket['owner']:
                raise TimeoutError('LLM 검사 예약이 만료되었습니다.')
            db.execute('INSERT OR REPLACE INTO llm_results VALUES(?,?,?,?,?,?,?,?,?)',
                       (*key, payload_hash, prompt_fp, json.dumps(result, ensure_ascii=False), json.dumps(usage), time.time()))
            db.execute('UPDATE llm_calls SET status=?, charged_micro_usd=?, usage=? WHERE id=?',
                       ('complete', charged, json.dumps(usage), ticket['owner']))
            db.execute('DELETE FROM llm_leases WHERE lease_key=? AND owner=?', (ticket['lease_key'], ticket['owner']))

    def failed(self, ticket):
        # 타임아웃/파싱 오류도 서버에서 과금됐을 수 있다. 결과는 캐시하지 않고 최대 예약액을 유지.
        with self.connection() as db:
            db.execute('UPDATE llm_calls SET status=? WHERE id=?', ('uncertain', ticket['owner']))
            db.execute('DELETE FROM llm_leases WHERE lease_key=? AND owner=?', (ticket['lease_key'], ticket['owner']))

    def stats(self):
        with self.connection() as db:
            rows = db.execute('SELECT status, COUNT(*) n, SUM(charged_micro_usd) amount FROM llm_calls GROUP BY status').fetchall()
        return {r['status']: {'calls': r['n'], 'usd': r['amount'] / 1_000_000} for r in rows}

    def reserve_batch(self, run_key, reservations, model, mode, budget):
        """온라인과 같은 예산 장부에 원자적 예약. 같은 평가를 두 번 제출하지 않는다."""
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM b_batch_runs WHERE run_key=?', (run_key,)).fetchone():
                raise ValueError('이미 제출을 시도한 Batch입니다. status/collect 또는 recover를 사용하세요.')
            used = db.execute('SELECT COALESCE(SUM(charged_micro_usd),0) FROM llm_calls').fetchone()[0]
            if used + sum(reservations.values()) > math.floor(budget * 1_000_000):
                raise BudgetExceeded('Batch 예약액이 로컬 예산 한도를 넘습니다.')
            db.execute('INSERT INTO b_batch_runs(run_key,state) VALUES(?,?)', (run_key, 'reserved'))
            for custom_id, amount in reservations.items():
                db.execute('INSERT INTO llm_calls(id,model,mode,created,status,charged_micro_usd) VALUES(?,?,?,?,?,?)',
                           (run_key + ':' + custom_id, model, mode, time.time(), 'batch_reserved', amount))

    def batch_run(self, run_key):
        with self.connection() as db:
            row = db.execute('SELECT * FROM b_batch_runs WHERE run_key=?', (run_key,)).fetchone()
        return dict(row) if row else None

    def update_batch(self, run_key, state, *, file_id=None, batch_id=None):
        with self.connection() as db:
            db.execute('UPDATE b_batch_runs SET state=?, input_file_id=COALESCE(?,input_file_id), '
                       'batch_id=COALESCE(?,batch_id) WHERE run_key=?', (state, file_id, batch_id, run_key))

    def import_batch(self, run_key, custom_id, key, payload_hash, prompt_fp, verdict, usage, charged):
        """오류/누락은 예약액 유지. 같은 결과 재수집은 재과금·중복 기록하지 않는다."""
        owner = run_key + ':' + custom_id
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT status FROM llm_calls WHERE id=?', (owner,)).fetchone()
            if not row:
                raise ValueError('이 DB에 해당 Batch 예약이 없습니다.')
            if row[0] == 'batch_complete':
                return
            if verdict is None:
                db.execute('UPDATE llm_calls SET status=? WHERE id=?', ('batch_uncertain', owner))
                return
            db.execute('INSERT OR REPLACE INTO llm_results VALUES(?,?,?,?,?,?,?,?,?)',
                       (*key, payload_hash, prompt_fp, json.dumps(verdict, ensure_ascii=False), json.dumps(usage), time.time()))
            db.execute('UPDATE llm_calls SET status=?,charged_micro_usd=?,usage=? WHERE id=?',
                       ('batch_complete', charged, json.dumps(usage), owner))
