"""B 1차 규칙. scan(text)->list[str]은 A의 정제 검사에서도 사용한다.

규칙은 단서이지 의미 판별의 정답이 아니다. 숫자는 B 초기 제안이며 D6 전 고정/합의한다.
"""
import base64
import html
import re
import unicodedata

from checkers.b_metadata import MAX_BYTES, canonical_tool, text_fields

VERSION = 'rules-v1'
RISK = {'hidden_tag': 40, 'secrecy_request': 60, 'ssh_key_access': 60,
        'env_file_access': 50, 'tool_shadowing': 60, 'invisible_chars': 40}
_PATTERNS = {
    'hidden_tag': re.compile(r'<\s*/?\s*(?:important|system|developer|instructions?|hidden|override)\b', re.I),
    'secrecy_request': re.compile(
        r"(?:do\s+not|don['’]?t|never)\s+(?:tell|inform|notify|mention\s+(?:this\s+)?to|reveal\s+(?:this\s+)?to)\s+(?:the\s+)?user"
        r'|(?:hide|conceal)\b.{0,50}\bfrom\s+(?:the\s+)?user'
        r'|사용자.{0,35}(?:말하지\s*(?:마|않)|알리지\s*(?:마|않)|숨겨|비밀로)', re.I),
    'ssh_key_access': re.compile(r'(?:~[/\\])?\.ssh(?:[/\\]|\b)|\bid_(?:rsa|ed25519|ecdsa|dsa)\b', re.I),
    'env_file_access': re.compile(r'(?<![\w])\.env(?:\b|[.])|\.aws[/\\]credentials|\bcredentials\.json\b', re.I),
    'tool_shadowing': re.compile(
        r'\b(?:override|replace|overwrite|ignore|intercept|redirect)\b.{0,100}\b(?:tool|function|instructions?)\b'
        r'|\b(?:must|always|required\s+to)\s+(?:first\s+)?(?:call|invoke|execute|use)\s+[\w.\-]{1,64}\s*(?:tool|function)\b'
        r'|(?:다른|기존)\s*도구.{0,40}(?:무시|대체|덮어|가로채)', re.I),
}
_CONFUSABLES = str.maketrans({'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
                            'і': 'i', 'ѕ': 's', 'у': 'y', 'Α': 'A', 'Ο': 'O'})


def _invisible(c):
    return unicodedata.category(c) in ('Cf', 'Co', 'Cn') or (unicodedata.category(c) == 'Cc' and c not in '\t\r\n')


def inspection_views(text):
    """원문은 그대로 두고 읽기 전용 정규화/디코딩 사본만 검사한다. 실행하지 않는다."""
    normalized = html.unescape(unicodedata.normalize('NFKC', text)).translate(_CONFUSABLES)
    normalized = ''.join(c for c in normalized if not _invisible(c))
    views = [normalized]
    # 식별자 속 단어와 공백으로 쪼갠 단어도 보되 원래 경로 검사본은 유지한다.
    views.append(normalized.replace('_', ' '))
    views.append(re.sub(r'(?<!\w)(?:[A-Za-z] ){3,}[A-Za-z](?!\w)', lambda m: m[0].replace(' ', ''), normalized))
    if '\u202e' in text:
        views.append(normalized[::-1])
    tags = ''.join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
    if tags:
        views.append(tags)
    if re.search(r'\b(?:base64|hex[- ]encoded)\b', normalized, re.I):
        for token in re.findall(r'(?<!\w)[A-Za-z0-9+/=]{24,}(?!\w)', normalized)[:4]:
            if len(token) > 16000:
                continue
            for decode in (lambda t: base64.b64decode(t, validate=True), bytes.fromhex):
                try:
                    views.append(decode(token).decode('utf-8'))
                except (ValueError, UnicodeError):
                    pass
    return views


def scan(text: str) -> list[str]:
    if not isinstance(text, str):
        raise TypeError('scan에는 문자열만 전달하세요.')
    if len(text) > MAX_BYTES:
        raise ValueError('규칙 검사 문자열이 너무 깁니다.')
    views = inspection_views(text)
    hits = [name for name, pattern in _PATTERNS.items() if any(pattern.search(v) for v in views)]
    if any(_invisible(c) for c in text):
        hits.append('invisible_chars')
    return hits


def inspect(tool: dict) -> dict:
    canonical_tool(tool)
    found, evidence, hard = set(), [], False
    for path, text in text_fields(tool):
        hits = set(scan(text))
        if hits:
            found.update(hits)
            # 로그 한 줄을 제어하지 못하게 JSON 유니코드 이스케이프로 보존.
            import json
            evidence.append(json.dumps({'path': path[:160], 'signals': sorted(hits), 'excerpt': text[:240]}, ensure_ascii=True))
        # 서로 다른 정상 필드의 단서를 합쳐 치명 패턴으로 오인하지 않는다.
        if {'hidden_tag', 'secrecy_request'} <= hits and hits & {'ssh_key_access', 'env_file_access'}:
            hard = True
    signals = [name for name in RISK if name in found]
    return {'checker': 'injection', 'risk': 100 if hard else max((RISK[s] for s in signals), default=0),
            'hard_block': hard, 'signals': signals, 'evidence': '\n'.join(evidence)[:3000], 'latency_ms': 0}
