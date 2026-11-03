"""시연용 토큰 생성기 (compose의 secrets 서비스가 띄울 때마다 한 번 실행한다).

에이전트 토큰(agent)과 관리 토큰(admin)을 무작위로 새로 만들어 공유 볼륨에 0400으로 쓴다.
레포·compose 파일·페이지에는 토큰이 없고, 게이트웨이·드라이버·nginx가 시작할 때 이 파일을 읽어
환경변수로 넘긴다. 띄울 때마다 바뀌므로 이전 시연의 토큰은 쓸 수 없다.

- agent, admin: 게이트웨이·드라이버(uid 10001)가 읽는다
- admin.nginx: admin과 같은 값. nginx는 root로 시작하지만 cap_drop ALL이라 남의 0400 파일을 못 읽으므로
  root 소유 사본을 따로 둔다
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path


def _write(path: Path, value: str, uid: int, gid: int) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, "w") as f:
        f.write(value)
    os.chown(tmp, uid, gid)
    os.replace(tmp, path)


def write_tokens(directory: Path, uid: int, gid: int, nginx_uid: int = 0) -> None:
    agent, admin = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    _write(directory / "agent", agent, uid, gid)
    _write(directory / "admin", admin, uid, gid)
    _write(directory / "admin.nginx", admin, nginx_uid, nginx_uid)


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "/run/demo-secrets")
    write_tokens(target, uid=10001, gid=10001)
    print("시연용 토큰을 새로 만들었다")
