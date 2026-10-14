"""Rule baselines evaluated on the same (location, text) -> spans protocol as the BiLSTM.

* ``existing_key_rules``  mirrors the key regexes of ``packet_pii.detect`` (USERNAME_KEYS / NAME_KEYS):
  if the *location* matches, the whole value is the entity. (Copied, not imported: this package
  stays independent of the rules engine.)
* ``strong_rules``        a deliberately generous field-key-aware baseline: broad key vocabulary,
  value-shape guards for ambiguous keys (``name``) and a list of common textual cues
  ("my name is X", "Dear X", "@handle", "logged in as X", ``user=X``, ``/users/X/``).
* ``majority``            predicts no entities (the majority behaviour: most tokens are ``O``).

The baselines were written from general knowledge of such cues, before any model result
was inspected, and were not tuned afterwards.
"""
from __future__ import annotations

import re

Span = tuple[int, int, str]

# ---- copied from packet_pii.detect
_USERNAME_KEYS = re.compile(r'(?:^|[.\[_-])(?:username|user_name|login)(?:$|[.\]_-])', re.I)
_NAME_KEYS = re.compile(r'(?:^|[.\[_-])(?:full_?name|first_?name|last_?name)(?:$|[.\]_-])', re.I)


def majority(location: str, text: str) -> list[Span]:
    return []


def existing_key_rules(location: str, text: str) -> list[Span]:
    if not text.strip():
        return []
    s = len(text) - len(text.lstrip())
    e = len(text.rstrip())
    out: list[Span] = []
    if _USERNAME_KEYS.search(location):
        out.append((s, e, "USERNAME"))
    if _NAME_KEYS.search(location):
        out.append((s, e, "PERSON_NAME"))
    return out


# ------------------------------------------------------------------ strong baseline
def _norm_key(location: str) -> str:
    last = re.split(r"[.]", re.sub(r"\[\d+\]", "", location))[-1]
    return re.sub(r"[_\-\s]", "", last).lower()


PERSON_KEYS = {"fullname", "firstname", "lastname", "givenname", "familyname", "surname", "forename", "fname",
               "lname", "customername", "contactname", "ownername", "displayname", "patientname", "employeename",
               "recipient", "sendername", "guestname", "billingname", "cardholder", "applicant", "passenger",
               "attendee", "participant", "client", "buyer", "student", "signee", "first", "last"}
AMBIGUOUS_PERSON_KEYS = {"name", "author"}
USER_KEYS = {"username", "uname", "login", "handle", "nick", "nickname", "alias", "screenname", "accountname",
             "gamertag", "userhandle", "displayhandle"}
_COMPANY_WORDS = {"labs", "systems", "industries", "group", "holdings", "gmbh", "ltd", "inc", "dynamics",
                  "logistics", "partners", "corp", "foods", "motors", "pro", "max", "mini", "lite", "air", "plus",
                  "ultra", "one", "go", "x200", "3000", "s5"}
_STOP = {"there", "everyone", "team", "all", "folks", "customer", "user", "sir", "madam", "support", "again",
         "morning", "back", "you", "me", "us", "now", "soon", "and", "the", "a"}

_CAP = r"[A-Z\u00c0-\u00de\u0391-\u03a9\u0400-\u042f][\w'’\-]*"
_NAME = rf"(?:{_CAP}(?:\s+(?:[A-Z]\.\s+)?{_CAP}){{0,2}})"
_HANDLE = r"[\w][\w.\-]*"
_TITLE = r"(?:(?:Mr|Ms|Mrs|Dr)\.\s+)?"
_PERSON_CUES = (r"my name is|this is|i'm|i am|dear|hi|hello|hey|thanks,|regards,|sincerely,|best wishes,|cc:|"
                r"contact:|from:|assigned to|prepared by|written by|signed by|message from|reply to|placed by|"
                r"patient:|customer:|name:|full name:|name -|spoke with|meeting with|booking for|invoice for|"
                r"reservation under the name|congratulations|welcome back,?|good morning|shipping to|created by")
_USER_CUES = (r"logged in as|signed in as|login attempt for user|session opened for user|banned user|reported user:?|"
              r"invalid password for|username:|user:|user|player|account|follow|dm from|posted by u/")
_P_RE = re.compile(rf"(?i:\b(?:{_PERSON_CUES}))\s+{_TITLE}({_NAME})")
_U_AT = re.compile(rf"(?<![\w.])@({_HANDLE})")
_U_CUE = re.compile(rf"(?i:\b(?:{_USER_CUES}))\s+@?({_HANDLE})")
_U_KV = re.compile(rf"(?i:\b(?:user|username|login|uid))=({_HANDLE})")
_U_URL = re.compile(rf"/(?:users|u|profile|accounts)/({_HANDLE})")
_FIRST_LAST_KV = re.compile(r"(?i:\b(?:first|last|name))=([^&\s;]+)")


def _trim(text: str, s: int, e: int) -> tuple[int, int]:
    while e > s and text[e - 1] in ".-,;:!?":
        e -= 1
    return s, e


def _looks_like_person(value: str) -> bool:
    toks = re.split(r"[\s,]+", value.strip())
    if not 1 <= len(toks) <= 4 or "." in value.replace(". ", " ", 1) and re.search(r"\.\w", value):
        return False
    if any(t.lower() in _COMPANY_WORDS for t in toks):
        return False
    return all(t.replace("'", "").replace("-", "").replace(".", "").isalpha() for t in toks)


def strong_rules(location: str, text: str) -> list[Span]:
    spans: dict[tuple[int, int], str] = {}
    if not text.strip():
        return []
    key = _norm_key(location)
    s0, e0 = len(text) - len(text.lstrip()), len(text.rstrip())
    if key in USER_KEYS:
        spans[(s0, e0)] = "USERNAME"
    elif key in PERSON_KEYS:
        spans[(s0, e0)] = "PERSON_NAME"
    elif key in AMBIGUOUS_PERSON_KEYS and _looks_like_person(text) and text[:1].isupper():
        spans[(s0, e0)] = "PERSON_NAME"
    for m in _P_RE.finditer(text):
        s, e = _trim(text, m.start(1), m.end(1))
        first = text[s:e].split()[0].lower()
        if first not in _STOP and first not in _COMPANY_WORDS:
            spans.setdefault((s, e), "PERSON_NAME")
    for rx in (_U_AT, _U_CUE, _U_KV, _U_URL):
        for m in rx.finditer(text):
            s, e = _trim(text, m.start(1), m.end(1))
            if e > s and text[s:e].lower() not in _STOP:
                spans.setdefault((s, e), "USERNAME")
    # drop spans nested in / overlapping a longer span already kept
    out = []
    for (s, e), l in sorted(spans.items(), key=lambda x: (-(x[0][1] - x[0][0]), x[0][0])):
        if all(e <= a or s >= b for a, b, _ in out):
            out.append((s, e, l))
    return sorted(out)
