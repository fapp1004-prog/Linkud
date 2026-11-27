"""(C) fingerprint.py — 서버 폴더의 '지문'(해시). 담당: C.

A는 캐시 키에, C(identity)는 신원 비교에 쓴다. (SPEC 6장, 결정안 ⑤)

- file_fp(server): 코드 + 의존성 파일 전체의 지문 → 서버 코드가 바뀌면 달라짐
- dep_fp(server):  의존성 파일만의 지문          → 라이브러리 목록이 바뀌면 달라짐

server 자리에는 A가 넘기는 ServerInfo dict(SPEC 3장, 'dir' 키 사용)와 폴더 경로(str·Path) 둘 다 받는다.

규칙
- 포함: 코드(*.py *.js *.ts *.mjs *.cjs) + 의존성 파일(requirements*.txt, pyproject.toml,
  package.json, package-lock.json, uv.lock, poetry.lock, Pipfile.lock)
- 제외: .env*, *.db, *.sqlite3, *.log, 그리고 .git/ __pycache__/ node_modules/ logs/ data/ .venv/ venv/
- 상대경로를 '/'로 통일해 정렬한 뒤 (경로 + 내용)을 SHA-256. 줄바꿈 CRLF는 LF로 바꿔서 계산
  → Windows/git 설정 차이만으로 '신원 변경'이 뜨지 않게
"""

import fnmatch
import hashlib
import os
from pathlib import Path

CODE_SUFFIXES = {".py", ".js", ".ts", ".mjs", ".cjs"}
DEP_PATTERNS = ("requirements*.txt", "pyproject.toml", "package.json", "package-lock.json",
                "uv.lock", "poetry.lock", "Pipfile.lock")
EXCLUDE_DIRS = {".git", "__pycache__", "node_modules", "logs", "data", ".venv", "venv"}
EXCLUDE_PATTERNS = (".env*", "*.db", "*.sqlite3", "*.log")


def _is_dep(name: str) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in DEP_PATTERNS)


def _excluded(name: str) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in EXCLUDE_PATTERNS)


def _server_dir(server):
    """ServerInfo dict면 'dir' 값을, 아니면 그대로(폴더 경로) 쓴다."""
    return server.get("dir") if isinstance(server, dict) else server


def list_files(server, deps_only: bool = False) -> list[str]:
    """지문에 들어가는 파일의 상대경로 목록 (정렬됨, '/' 구분)."""
    server_dir = _server_dir(server)
    if not server_dir:
        raise ValueError("server dir가 비어 있음 (게이트웨이가 서버 폴더를 넘겨주지 않음)")
    root = Path(server_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"서버 폴더가 없음: {root}")
    out = []
    for cur, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for name in files:
            if _excluded(name):
                continue
            if _is_dep(name) or (not deps_only and Path(name).suffix in CODE_SUFFIXES):
                out.append((Path(cur) / name).relative_to(root).as_posix())
    return sorted(out)


def _digest(root, rels: list[str]) -> str:
    h = hashlib.sha256()
    for rel in rels:
        data = (Path(root) / rel).read_bytes().replace(b"\r\n", b"\n")
        h.update(rel.encode("utf-8") + b"\0" + str(len(data)).encode() + b"\0" + data)
    return h.hexdigest()


def file_fp(server) -> str:
    d = _server_dir(server)
    return _digest(d, list_files(d))


def dep_fp(server) -> str:
    d = _server_dir(server)
    return _digest(d, list_files(d, deps_only=True))
