"""Transparent rule-based detection baseline. Scores are heuristic, NOT calibrated probabilities."""
from __future__ import annotations
import functools
import hashlib
import ipaddress
import re
from dataclasses import dataclass

from .identity_rules import (FULLY_MASKED_CATEGORIES, IDENTIFIER_CATEGORIES, IdentityContext, analyse_location,
                             analyse_short_location as _identity_key, classify as classify_identity)

EMAIL = re.compile(r'(?<![\w.+-])[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}(?![\w.-])')
IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
PHONE = re.compile(r'(?<!\w)(?:\+\d[\d\s().-]{7,16}\d|0[234578][\d\s().-]{7,14}\d)(?!\w)')
CARD = re.compile(r'(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)')


class _SecretKeyMatcher:
    """Token-aware credential-key matcher (replaces a substring regex that matched ``author`` via ``auth``).

    A location is split into lower-case tokens on punctuation and camelCase boundaries. Unambiguous credential words match
    as tokens, token suffixes (``clientsecret``) or adjacent token pairs (``api`` + ``key``). Generic words such as
    ``token``/``auth``/``pin`` are ignored when qualified as metadata (``token_type``, ``max_tokens``).
    """
    _SPLIT = re.compile(r'[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])')
    _WORDS = frozenset({'password', 'passwd', 'pwd', 'passphrase', 'passcode', 'secret', 'secrets', 'apikey', 'bearer', 'cookie',
                        'authorization', 'auth', 'jwt', 'sid', 'otp', 'token', 'pin', 'credential', 'credentials'})
    _SUBSTRINGS = ('password', 'passwd', 'passphrase')
    _SUFFIXES = ('secret', 'token', 'apikey')
    _PAIRS = frozenset({('api', 'key'), ('private', 'key'), ('access', 'key'), ('secret', 'key'), ('session', 'id'),
                        ('set', 'cookie'), ('client', 'secret'), ('auth', 'token')})
    _GENERIC = frozenset({'token', 'auth', 'pin', 'sid', 'otp'})
    _METADATA = frozenset({'type', 'count', 'limit', 'length', 'size', 'max', 'min', 'expiry', 'expires', 'ttl', 'usage', 'tokens',
                           'total', 'number', 'num'})

    def tokens(self, location):
        return [t.lower() for t in self._SPLIT.split(str(location)) if t]

    def search(self, location):
        # Locations repeat heavily across messages; cache short ones (bounded: 128 chars x 16,384 entries).
        return self._cached(location) if len(location) <= 128 else self._uncached(location)

    @functools.lru_cache(maxsize=16384)
    def _cached(self, location):
        return self._uncached(location)

    def _uncached(self, location):
        lowered = location.lower()
        for fragment in self._FRAGMENTS:
            if fragment in lowered:
                return self._search(location)
        return None

    def _search(self, location):
        tokens = self.tokens(location)
        if not tokens:
            return None
        has_metadata = any(t in self._METADATA for t in tokens)
        for i, token in enumerate(tokens):
            hit = (token in self._WORDS or any(sub in token for sub in self._SUBSTRINGS)
                   or any(len(token) > len(suf) and token.endswith(suf) for suf in self._SUFFIXES)
                   or (i + 1 < len(tokens) and (token, tokens[i + 1]) in self._PAIRS))
            if hit and not (has_metadata and token in self._GENERIC):
                return True
        return None


# Any location containing none of the fragments any rule can match cannot be a credential key, so most fields skip
# tokenisation entirely (plain substring tests are much cheaper than a regex alternation). Derived from the rule sets so
# the two cannot drift apart.
_SecretKeyMatcher._FRAGMENTS = tuple(sorted(
    _SecretKeyMatcher._WORDS | set(_SecretKeyMatcher._SUBSTRINGS) | set(_SecretKeyMatcher._SUFFIXES)
    | {pair[0] for pair in _SecretKeyMatcher._PAIRS}, key=lambda f: (-len(f), f)))
SECRET_KEYS = _SecretKeyMatcher()
USERNAME_KEYS = re.compile(r'(?:^|[.\[_-])(?:username|user_name|login)(?:$|[.\]_-])',re.I)
NAME_KEYS = re.compile(r'(?:^|[.\[_-])(?:full_?name|first_?name|last_?name)(?:$|[.\]_-])',re.I)


@dataclass(frozen=True)
class Detection:
    pii_type: str
    location: str
    confidence: float
    value: str
    detector: str
    fingerprint: str


def _luhn(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    s=0
    for index,d in enumerate(reversed(digits)):
        if index%2:
            d*=2
            if d>9: d-=9
        s+=d
    return s%10==0


def _mask(value: str) -> str:
    if '@' in value:
        left,right = value.split('@',1)
        return left[:1]+'***@'+right
    if len(value)<=4:
        return '****'
    return value[:2]+'***'+value[-2:]


REDACTED = '[REDACTED]'


def _mask_for(kind: str, value: str) -> str:
    """Default masking. Small-value-space attributes (AGE/GENDER/SEX) are fully redacted; short identifiers show nothing."""
    if kind in FULLY_MASKED_CATEGORIES:
        return REDACTED
    if kind in IDENTIFIER_CATEGORIES and len(value) <= 8:
        return '****'
    return _mask(value)


def client_value_visible(kind: str, location: str) -> bool:
    """Client view: show ordinary matches, retain explicit credential masking.

    A noncredential-looking match *inside* a secret-bearing field remains hidden.
    This is independent of the default redacted CLI/report behaviour.
    """
    return kind != 'CREDENTIAL_OR_TOKEN' and not SECRET_KEYS.search(location)


def _finding(kind: str, location: str, confidence: float, value: str, include_values: bool, detector='rule') -> Detection:
    return Detection(kind,location,confidence,value if include_values else _mask_for(kind, value),detector,hashlib.sha256(value.encode('utf-8')).hexdigest()[:16])


def detect_fields(fields: list[tuple[str,str]], threshold: float=0.8, include_values: bool=False, *, display_nonsecret_values: bool=False) -> list[Detection]:
    if not 0 <= threshold <= 1:
        raise ValueError('threshold must be between 0 and 1')
    detections: list[Detection]=[]
    seen=set()
    identity = IdentityContext(fields)
    def add(kind,loc,score,value):
        if not value or score<threshold:
            return
        key=(kind,loc,value)
        if key in seen or len(detections)>=10000:
            return
        seen.add(key)
        visible = include_values or (display_nonsecret_values and client_value_visible(kind, loc))
        detections.append(_finding(kind,loc,score,value,visible))
    for location,value in fields:
        value=value[:MAX_FIELD_LENGTH]
        for match in EMAIL.finditer(value):
            add('EMAIL',location,0.98,match.group(0))
        for match in IPV4.finditer(value):
            try:
                ipaddress.IPv4Address(match.group(0))
            except ipaddress.AddressValueError:
                continue
            add('IP_ADDRESS',location,0.96,match.group(0))
        for match in PHONE.finditer(value):
            digits=re.sub(r'\D','',match.group(0))
            if 9<=len(digits)<=15:
                add('PHONE',location,0.83,match.group(0))
        for match in CARD.finditer(value):
            if _luhn(match.group(0)):
                add('CREDIT_CARD',location,0.99,match.group(0))
        if SECRET_KEYS.search(location):
            # Avoid categorising public HTTP headers as secrets without an apparent credential.
            if location in ('header.authorization','header.proxy-authorization') or (
                location not in ('header.cookie','header.set-cookie') and value
            ) or (location in ('header.cookie','header.set-cookie') and '=' in value):
                add('CREDENTIAL_OR_TOKEN',location,0.92,value)
        if USERNAME_KEYS.search(location):
            add('USERNAME',location,0.84,value)
        if NAME_KEYS.search(location):
            add('PERSON_NAME_CANDIDATE',location,0.86,value)
        # Context-validated identity/demographic rules (taxonomy v1): explicit field labels only, never inference.
        key_info = _identity_key(location) if len(location) <= 256 else analyse_location(location)
        if key_info is not None and key_info.rule is not None and (
                identity_hit := classify_identity(key_info, value, identity)):
            add(identity_hit[0],location,identity_hit[1],value)
    return detections

MAX_FIELD_LENGTH=100_000
