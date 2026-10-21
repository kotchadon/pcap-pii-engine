"""Context-validated deterministic rules for identity and demographic fields (taxonomy v1).

Contract: ``docs/integration/PII_DETECTION_TAXONOMY.md``.

Scope: these rules only classify a value that is *explicitly transmitted* under an *explicitly labelled* structured field
(JSON key path, query parameter, form field or header name). They never infer an attribute from a name, a username, free
text, writing style or any other indirect signal, and they never inspect ``body.text``.

Each rule needs two independent conditions: a qualifying field key from an exact allowlist (no substring matching, so
``page``/``stage``/``message`` never match ``age`` and ``sexuality`` never matches ``sex``) AND a value that passes the
category's format check. Scores are ordinal heuristics describing the strength of the contextual evidence. They are NOT
calibrated probabilities.

All parsing here is linear: separator splits, set lookups and anchored regexes with no nested quantifiers.
"""
from __future__ import annotations

import functools
import re
from typing import NamedTuple

APPLE_ADVERTISING_ID = 'APPLE_ADVERTISING_ID'
ANDROID_ADVERTISING_ID = 'ANDROID_ADVERTISING_ID'
ADVERTISING_ID = 'ADVERTISING_ID'  # advertising identifier whose platform could not be established
AGE = 'AGE'
GENDER = 'GENDER'
SEX = 'SEX'
DEVICE_ID = 'DEVICE_ID'
USER_ACCOUNT_ID = 'USER_ACCOUNT_ID'

IDENTITY_CATEGORIES = (APPLE_ADVERTISING_ID, ANDROID_ADVERTISING_ID, ADVERTISING_ID, AGE, GENDER, SEX, DEVICE_ID,
                       USER_ACCOUNT_ID)
# Small value spaces: any partial mask (or its length) would disclose the value, so these are always fully redacted.
FULLY_MASKED_CATEGORIES = frozenset({AGE, GENDER, SEX})
IDENTIFIER_CATEGORIES = frozenset({APPLE_ADVERTISING_ID, ANDROID_ADVERTISING_ID, ADVERTISING_ID, DEVICE_ID,
                                   USER_ACCOUNT_ID})

# Ordinal heuristic scores (see the taxonomy contract). All are >= the default 0.8 threshold on purpose.
SCORE_PLATFORM_KEY = 0.90       # platform-specific advertising key (idfa, gaid, ...) with no conflicting context
SCORE_PLATFORM_CONTEXT = 0.88   # generic advertising key + exactly one platform established by independent context
SCORE_UNATTRIBUTED = 0.86       # advertising key whose platform is unknown or conflicting
SCORE_AGE = 0.85
SCORE_GENDER_SEX_TERM = 0.85    # documented term (male, female, non-binary, ...)
SCORE_GENDER_SEX_LETTER = 0.82  # documented single-letter code M/F under an explicit gender/sex key
SCORE_DEVICE_ID = 0.84
SCORE_USER_ACCOUNT_ID = 0.82

_APPLE, _ANDROID = 'apple', 'android'
_PLATFORM_CATEGORY = {_APPLE: APPLE_ADVERTISING_ID, _ANDROID: ANDROID_ADVERTISING_ID}

# Field keys are compared after lower-casing and removing only the separators below. Any other character (including
# non-ASCII letters) is kept, so it can never collapse a different key into an allowlisted one.
_SEPARATORS = re.compile(r'[\s_\-:]+')
_PATH_SPLIT = re.compile(r'[.\[\]]+')
_KEYED_SOURCES = frozenset({'json_body', 'query_parameter', 'form', 'header'})
_MAX_PATH_CHARS = 1024
_MAX_SEGMENTS = 8

_APPLE_AD_KEYS = frozenset({'idfa', 'iosidfa', 'appleidfa', 'iosadvertisingid', 'appleadvertisingid', 'iosadid',
                            'appleadid', 'iosifa', 'appleifa'})
_ANDROID_AD_KEYS = frozenset({'gaid', 'aaid', 'androidadvertisingid', 'googleadvertisingid', 'androidadid',
                              'googleadid', 'gpsadid', 'androidifa'})
# OpenRTB ``ifa`` and generic ``advertising_id`` keys carry no platform on their own. ``ad_id``/``adid`` are excluded:
# they usually name an advertisement/creative, and Adjust's ``adid`` is Adjust's own device identifier.
_GENERIC_AD_KEYS = frozenset({'advertisingid', 'advertisingidentifier', 'ifa', 'maid', 'mobileadvertisingid',
                              'mobileadid', 'deviceadvertisingid'})
_AGE_KEYS = frozenset({'userage', 'personage', 'customerage', 'memberage', 'patientage', 'profileage', 'ageyears',
                       'ageinyears'})
_GENDER_KEYS = frozenset({'usergender', 'persongender', 'customergender', 'membergender', 'patientgender',
                          'profilegender', 'genderidentity'})
_SEX_KEYS = frozenset({'usersex', 'personsex', 'customersex', 'membersex', 'patientsex', 'profilesex', 'sexatbirth',
                       'assignedsexatbirth', 'birthsex', 'biologicalsex', 'legalsex', 'administrativesex'})
_BARE_ATTRIBUTES = {'age': AGE, 'gender': GENDER, 'sex': SEX}
_DEVICE_KEYS = frozenset({'deviceid', 'androidid', 'ssaid', 'idfv', 'identifierforvendor', 'udid', 'hardwareid', 'hwid'})
_ACCOUNT_KEYS = frozenset({'userid', 'accountid', 'customerid', 'memberid', 'subscriberid', 'playerid', 'profileid',
                           'customernumber', 'accountnumber'})
_ID_LEAVES = frozenset({'id', 'uuid', 'guid'})
_PLATFORM_KEYS = frozenset({'os', 'osname', 'platform', 'platformname', 'deviceos', 'ostype', 'deviceplatform',
                            'operatingsystem'})

# A bare ``age``/``gender``/``sex`` key qualifies only at the root of its source or when its nearest meaningful parent
# describes a person. ``product.gender``, ``cache.age`` or ``account.age`` do not qualify.
_PERSON_PARENTS = frozenset({'user', 'profile', 'person', 'people', 'customer', 'member', 'patient', 'subscriber',
                             'player', 'demographic', 'demographics', 'viewer', 'buyer', 'applicant', 'me', 'self',
                             'participant', 'respondent', 'student', 'employee', 'traveler', 'traveller', 'passenger',
                             'guest', 'visitor', 'userproperties', 'userattributes', 'userdata', 'userinfo',
                             'userprofile', 'personaldata', 'personalinfo', 'personaldetails', 'customerinfo',
                             'profileinfo', 'memberinfo'})
_WRAPPERS = frozenset({'data', 'payload', 'body', 'attributes', 'attrs', 'params', 'fields', 'properties', 'props',
                       'info', 'details', 'traits', 'values'})
# ``<parent>.id`` qualifies only for these immediate parents (``user.id`` yes; ``order.id``/``contact.id`` no).
_ACCOUNT_PARENTS = frozenset({'user', 'account', 'customer', 'member', 'subscriber', 'player', 'profile', 'patient'})
_DEVICE_PARENTS = frozenset({'device'})
_PATH_PLATFORM_TOKENS = {'ios': _APPLE, 'ipados': _APPLE, 'iphone': _APPLE, 'ipad': _APPLE, 'apple': _APPLE,
                         'android': _ANDROID, 'google': _ANDROID, 'gms': _ANDROID}

_UUID = re.compile(r'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}')
_NIL_UUID = '00000000-0000-0000-0000-000000000000'  # iOS/Android placeholder when tracking is limited/opted out
_MAX_UUID = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
_AGE_VALUE = re.compile(r'(\d{1,3})(?:\s?(?:y|yrs?|years?)(?:\s+old)?)?', re.I)
_OPAQUE_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:\-]*')
_PLATFORM_VALUE = re.compile(r'(ios|ipados|iphone\s?os|tvos|android)(?:[\s_/\-]*v?\d+(?:\.\d+)*)?', re.I)
_GENDER_SEX_TERMS = frozenset({'male', 'female', 'man', 'woman', 'non binary', 'nonbinary', 'genderqueer', 'agender',
                               'genderfluid', 'gender fluid', 'bigender', 'two spirit', 'transgender', 'trans man',
                               'trans woman', 'transgender man', 'transgender woman', 'trans male', 'trans female',
                               'intersex'})
_GENDER_SEX_LETTERS = frozenset({'m', 'f'})  # documented mapping; O/U/X and numeric codes stay unclassified
_ID_PLACEHOLDERS = frozenset({'null', 'none', 'nil', 'undefined', 'unknown', 'anonymous', 'anon', 'guest', 'me', 'self',
                              'current', 'true', 'false', 'na', 'n/a', 'nan', 'default', 'test', 'empty', _NIL_UUID,
                              _MAX_UUID})


class KeyInfo(NamedTuple):
    rule: str | None             # 'ADID' or a category name; None for a platform-declaration field
    key_platform: str | None     # platform implied by an advertising key itself
    scope: str                   # enclosing structure ('' = whole message) used to match platform evidence
    path_platforms: frozenset    # platforms named by parent path segments


def _compact(segment: str) -> str:
    return _SEPARATORS.sub('', segment.lower())


def _scope(source: str, location: str) -> str:
    if source != 'json_body':
        return ''  # query, form and header fields describe the whole message
    end = len(location)
    while end and location[end - 1] == ']':  # json_body.ids[0] -> scope of ``ids``
        end = location.rfind('[', 0, end)
        if end <= 0:
            return ''
    cut = location.rfind('.', 0, end)
    return location[:cut] if cut > 0 else ''


@functools.lru_cache(maxsize=16384)
def analyse_short_location(location: str) -> KeyInfo | None:
    return _analyse(location)


def analyse_location(location: str) -> KeyInfo | None:
    """Classify a field location (cached for short locations, which repeat heavily across messages)."""
    return analyse_short_location(location) if len(location) <= 256 else _analyse(location)


def _analyse(location: str) -> KeyInfo | None:
    source, _, path = location.partition('.')
    if source == 'body' or (source in _KEYED_SOURCES and not path):
        return None  # free text has no key context
    if source not in _KEYED_SOURCES:
        source, path = '', location
    segments = [s for s in _PATH_SPLIT.split(path[-_MAX_PATH_CHARS:]) if s and not s.isdigit()][-_MAX_SEGMENTS:]
    if not segments:
        return None
    leaf = segments[-1]
    if source == 'header' and leaf[:2].lower() == 'x-':
        leaf = leaf[2:]
    key = _compact(leaf)
    parents = [_compact(s) for s in reversed(segments[:-1])]
    scope = _scope(source, location)

    if key in _APPLE_AD_KEYS or key in _ANDROID_AD_KEYS or key in _GENERIC_AD_KEYS:
        platform = _APPLE if key in _APPLE_AD_KEYS else _ANDROID if key in _ANDROID_AD_KEYS else None
        named = set()
        for segment in segments[:-1]:
            for token in _SEPARATORS.split(segment.lower()):
                if token in _PATH_PLATFORM_TOKENS:
                    named.add(_PATH_PLATFORM_TOKENS[token])
        return KeyInfo('ADID', platform, scope, frozenset(named))
    if key in _AGE_KEYS:
        return KeyInfo(AGE, None, scope, frozenset())
    if key in _GENDER_KEYS:
        return KeyInfo(GENDER, None, scope, frozenset())
    if key in _SEX_KEYS:
        return KeyInfo(SEX, None, scope, frozenset())
    if key in _DEVICE_KEYS:
        return KeyInfo(DEVICE_ID, None, scope, frozenset())
    if key in _ACCOUNT_KEYS:
        return KeyInfo(USER_ACCOUNT_ID, None, scope, frozenset())
    if key in _BARE_ATTRIBUTES:
        if source == 'header':
            return None  # e.g. the standard HTTP ``Age`` cache header
        nearest = next((p for p in parents if p not in _WRAPPERS), None)
        if nearest is None or _is_member(nearest, _PERSON_PARENTS):
            return KeyInfo(_BARE_ATTRIBUTES[key], None, scope, frozenset())
        return None
    if key in _ID_LEAVES and parents:
        if _is_member(parents[0], _ACCOUNT_PARENTS):
            return KeyInfo(USER_ACCOUNT_ID, None, scope, frozenset())
        if _is_member(parents[0], _DEVICE_PARENTS):
            return KeyInfo(DEVICE_ID, None, scope, frozenset())
        return None
    if key in _PLATFORM_KEYS:
        return KeyInfo(None, None, scope, frozenset())
    return None


def _is_member(word: str, allowed: frozenset) -> bool:
    return word in allowed or (len(word) > 3 and word.endswith('s') and word[:-1] in allowed)  # users -> user


def platform_of_value(value: str) -> str | None:
    text = value.strip()
    if len(text) > 32:
        return None
    match = _PLATFORM_VALUE.fullmatch(text)
    if not match:
        return None
    return _ANDROID if match.group(1).lower() == 'android' else _APPLE


def _advertising_uuid(value: str) -> bool:
    return len(value) == 36 and bool(_UUID.fullmatch(value)) and value.lower() not in (_NIL_UUID, _MAX_UUID)


def _age_valid(value: str) -> bool:
    text = value.strip()
    if len(text) > 16:
        return False
    match = _AGE_VALUE.fullmatch(text)
    if not match or match.group(1)[0] == '0':
        return False
    return 1 <= int(match.group(1)) <= 120


def _gender_sex_score(value: str) -> float | None:
    text = value.strip().lower()
    if not text or len(text) > 40:
        return None
    term = ' '.join(t for t in _SEPARATORS.split(text) if t)
    if term in _GENDER_SEX_TERMS:
        return SCORE_GENDER_SEX_TERM
    if term in _GENDER_SEX_LETTERS:
        return SCORE_GENDER_SEX_LETTER
    return None


def _opaque_id(value: str, min_len: int, need_digit: bool) -> bool:
    if not min_len <= len(value) <= 128 or value.lower() in _ID_PLACEHOLDERS or not _OPAQUE_ID.fullmatch(value):
        return False
    significant = value.replace('-', '').replace('.', '').replace(':', '').replace('_', '')
    if not significant.strip('0'):
        return False  # all-zero placeholder
    return not need_digit or any(c.isdigit() for c in value)


class IdentityContext:
    """Per-message state: platform declarations (``os``/``platform`` fields) are scanned lazily, only when an
    advertising-ID key is actually present, so ordinary messages pay nothing for them."""
    __slots__ = ('_fields', '_evidence')
    _MAX_EVIDENCE = 64

    def __init__(self, fields):
        self._fields = fields
        self._evidence = None

    def _platform_evidence(self):
        if self._evidence is None:
            evidence = []
            for location, value in self._fields:
                info = analyse_location(location)
                if info is not None and info.rule is None:
                    platform = platform_of_value(value)
                    if platform:
                        evidence.append((info.scope, platform))
                        if len(evidence) >= self._MAX_EVIDENCE:
                            break
            self._evidence = evidence
        return self._evidence

    def platforms(self, info: KeyInfo) -> set:
        found = set(info.path_platforms)
        scope = info.scope
        for evidence_scope, platform in self._platform_evidence():
            if (not evidence_scope or scope == evidence_scope or scope.startswith(evidence_scope + '.')
                    or scope.startswith(evidence_scope + '[')):
                found.add(platform)
        return found


def identity_finding(location: str, value: str, context: IdentityContext) -> tuple[str, float] | None:
    """Return ``(category, heuristic_score)`` for one field, or None. At most one identity category per field."""
    info = analyse_location(location)
    if info is None or info.rule is None:
        return None
    return classify(info, value, context)


def classify(info: KeyInfo, value: str, context: IdentityContext) -> tuple[str, float] | None:
    """Value validation for a field whose key already qualified (``info.rule`` is not None)."""
    if not value:
        return None
    rule = info.rule
    if rule == 'ADID':
        if not _advertising_uuid(value):
            return None
        platforms = context.platforms(info)
        if info.key_platform is not None:
            if platforms <= {info.key_platform}:
                return _PLATFORM_CATEGORY[info.key_platform], SCORE_PLATFORM_KEY
            return ADVERTISING_ID, SCORE_UNATTRIBUTED  # conflicting platform context: never pick a side
        if len(platforms) == 1:
            return _PLATFORM_CATEGORY[next(iter(platforms))], SCORE_PLATFORM_CONTEXT
        return ADVERTISING_ID, SCORE_UNATTRIBUTED
    if rule == AGE:
        return (AGE, SCORE_AGE) if _age_valid(value) else None
    if rule in (GENDER, SEX):
        score = _gender_sex_score(value)
        return (rule, score) if score is not None else None
    if rule == DEVICE_ID:
        return (DEVICE_ID, SCORE_DEVICE_ID) if _opaque_id(value, 8, True) else None
    if rule == USER_ACCOUNT_ID:
        return (USER_ACCOUNT_ID, SCORE_USER_ACCOUNT_ID) if _opaque_id(value, 1, False) else None
    return None
