"""거부 참조 번호.

거부마다 새로 만드는 무작위 번호다. 추측으로 남의 기록을 맞히기 어렵고 거부 사이의 연관을 드러내지
않도록 `secrets`로 Crockford Base32 8자(40비트)를 뽑는다. 번호만으로는 원인을 알 수 없다.
"""

from __future__ import annotations

import re
import secrets

# Crockford Base32: 헷갈리는 I·L·O·U를 뺀 32자
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
REF_PATTERN = re.compile(r"LK-[0-9A-HJKMNP-TV-Z]{8}")


def new_ref() -> str:
    return "LK-" + "".join(secrets.choice(_ALPHABET) for _ in range(8))
