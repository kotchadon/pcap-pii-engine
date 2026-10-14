"""V2 synthetic development distribution (Regime B) for PERSON_NAME / USERNAME spans.

Design goals (see docs/ml/V2_DATASET_AND_GENERALISATION.md):
* realistic, diverse lexicons (frozen Faker dump, ``datasets/lexicons_v2.json``) hash-partitioned across
  train/val/calib so no identity, place, company or username string repeats across splits;
* a much larger bank of cue templates, hash-partitioned across splits (plus a small *common* share, reported);
* key grammar (role x head, snake/camel/kebab/upper, nested paths) with role words partitioned by split;
* frame-sharing hard negatives: the *same* cue frame is filled with persons AND non-persons;
* decoys: capitalised non-person values, person-like company names, usernames that look like names;
* case/punctuation/whitespace noise, percent/plus encoding, Unicode scripts, truncated fragments.

Pure standard library; deterministic per (seed, split, index).
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Sequence

from .spans import spans_to_tags, tokenize

SPLITS = ("train", "val", "calib")
PART = (80, 10, 10)
COMMON_SHARE = 20  # % of cue templates / roles that appear in every split
DEFAULT_SIZES = {"train": 30000, "val": 3000, "calib": 3000}
_LEX_PATH = os.path.join(os.path.dirname(__file__), "datasets", "lexicons_v2.json")


@dataclass(frozen=True)
class Example2:
    id: str
    split: str
    kind: str          # source family: field / text / kv / log / url / header / html / json_text / narrative ...
    template: str      # stable id of the frame (cue template or key grammar) used
    location: str
    text: str
    spans: tuple      # ((start, end, label), ...)
    tags: tuple = ()   # e.g. ("hard_negative", "multi_entity", "unicode", "truncated")

    def to_json(self) -> dict:
        d = dict(self.__dict__); d["spans"] = [list(s) for s in self.spans]; d["tags"] = list(self.tags); return d

    @staticmethod
    def from_json(d: dict) -> "Example2":
        d = dict(d); d["spans"] = tuple(tuple(s) for s in d["spans"]); d["tags"] = tuple(d.get("tags", ())); return Example2(**d)


def _h(s: str, salt: str = "") -> int:
    return int(hashlib.sha256((salt + "|" + s.lower()).encode("utf-8")).hexdigest()[:8], 16) % 100


def bucket(item: str, salt: str = "") -> str:
    """Stable split assignment of a lexical item / template: 'train' | 'val' | 'calib' | 'common'."""
    if _h(item, "common" + salt) < COMMON_SHARE and salt.startswith("cue"):
        return "common"
    v, acc = _h(item, salt), 0
    for s, w in zip(SPLITS, PART):
        acc += w
        if v < acc:
            return s
    return SPLITS[-1]


# ------------------------------------------------------------------ lexicons
def _load_lex() -> dict:
    with open(_LEX_PATH, encoding="utf-8") as f:
        lex = json.load(f)
    low = lambda xs: {x.lower() for x in xs}
    people = low(lex["first"]) | low(lex["last"])
    lex["city"] = [c for c in lex["city"] if c.lower() not in people]
    cities = low(lex["city"])
    lex["company"] = [c for c in lex["company"] if c.lower() not in people | cities]
    lex["username"] = [u for u in lex["username"] if u.lower() not in people | cities]
    lex["word"] = [w for w in lex["word"] if w.lower() not in people | cities]
    return lex


LEX = _load_lex()
POOL: dict[str, dict[str, list[str]]] = {}
for _cat in ("first", "last", "city", "company", "username", "job", "street", "word", "country"):
    POOL[_cat] = {s: [] for s in SPLITS}
    for _w in LEX[_cat]:
        POOL[_cat][bucket(_w, "lex")].append(_w)

# non-Latin names are rendered "Last First" without space for CJK
_CJK = re.compile(r"[぀-ヿ㐀-鿿가-힯]")
import unicodedata as _ud


def _script(w: str) -> str:
    try:
        n = _ud.name(w[0])
    except ValueError:
        return "other"
    return {"LATIN": "latin", "CYRILLIC": "cyr", "GREEK": "greek", "ARABIC": "arab", "HEBREW": "heb", "THAI": "thai",
            "DEVANAGARI": "dev", "HIRAGANA": "cjk", "KATAKANA": "cjk", "CJK": "cjk", "HANGUL": "cjk"}.get(n.split()[0], "other")


POOL_BY_SCRIPT = {cat: {s: {} for s in SPLITS} for cat in ("first", "last")}
for _cat in ("first", "last"):
    for _s in SPLITS:
        for _w in POOL[_cat][_s]:
            POOL_BY_SCRIPT[_cat][_s].setdefault(_script(_w), []).append(_w)

ROLES_PERSON = ("customer client patient guest owner author sender recipient receiver attendee passenger traveler "
                "student teacher employee manager contact buyer seller payer payee cardholder applicant candidate "
                "member subscriber visitor reporter assignee reviewer approver requester creator editor driver rider "
                "tenant landlord borrower lender agent doctor nurse physician parent guardian spouse sibling friend "
                "referrer inviter invitee organizer speaker presenter coach player witness claimant insured "
                "policyholder beneficiary sponsor mentor mentee intern recruiter dependant resident shopper cashier "
                "courier signer notary heir donor volunteer engineer director examiner interviewee billing shipping "
                "emergency account_holder primary secondary").split()
ROLES_NEG = ("company organization org employer vendor supplier store shop brand team department project product "
             "item service device app channel group city region country street file document host server module "
             "package repo branch tag label category theme school hospital hotel airline bank warehouse site "
             "building campus course event venue queue cluster node database table bucket").split()
ROLES_USER = ("admin owner author reporter assignee commit_author sender creator member player account moderator "
              "maintainer reviewer remote x_forwarded git_author ssh sudo db_owner api_client bot_owner subscriber").split()
HEADS_PERSON = ["name", "fullname", "full_name", "displayname", "display_name", "nm", "contact", "who", "person"]
HEADS_USER = ["username", "user_name", "login", "handle", "nick", "nickname", "alias", "screen_name", "account_name",
              "gamertag", "uname", "user", "userid_name", "usr", "login_name"]
HEADS_NEG = ["name", "title", "label", "id", "code", "ref", "slug", "key", "type", "desc", "description", "number"]
NEUTRAL_KEYS = ["value", "text", "data", "q", "query", "search", "content", "msg", "message", "comment", "note",
                "notes", "body", "payload", "raw", "field", "input", "param", "details", "subject", "summary",
                "bio", "log", "line", "entry", "description", "s", "t", "p1", "arg", "v"]
PATH_NOUNS = ["data", "items", "result", "results", "attributes", "payload", "meta", "profile", "user", "account",
              "customer", "order", "ticket", "request", "response", "record", "entry", "node", "info", "details",
              "settings", "contact", "billing", "shipping", "params", "context", "event", "session", "doc"]
# location roots mirror packet_pii.http_extract: json_body.<path>, form.<key>, query_parameter.<key>, header.<name>, body.text
PREFIX_ROOTS = ["json_body."] * 6 + ["form."] * 2 + ["query_parameter."] * 2


def _style(rng: random.Random, words: Sequence[str], parts: str) -> str:
    """join key words by snake/camel/kebab/UPPER/dot/concat."""
    ws = [w for w in words if w]
    r = rng.random()
    if r < .45: return "_".join(ws).lower()
    if r < .65: return ws[0].lower() + "".join(w.capitalize() for w in ws[1:])
    if r < .75: return "-".join(ws).lower()
    if r < .83: return "_".join(ws).upper()
    if r < .90: return "".join(w.capitalize() for w in ws)
    if r < .95: return "".join(ws).lower()
    return ".".join(ws).lower()


def _split_roles(split: str, roles: Sequence[str], salt: str) -> list[str]:
    out = [r for r in roles if bucket(r, "cue" + salt) in (split, "common")]
    return out or list(roles)


def _root_and_path(rng: random.Random, depths=(0, 0, 1, 1, 2, 3)) -> str:
    root = rng.choice(PREFIX_ROOTS)
    if root != "json_body.":  # form / query keys are flat
        return root
    pre = ""
    for _ in range(rng.choice(depths)):
        n = rng.choice(PATH_NOUNS)
        pre += (n + (f"[{rng.randint(0, 5)}]" if rng.random() < .25 else "")) + "."
    return root + pre


def make_key(rng: random.Random, split: str, kind: str) -> tuple[str, str]:
    """Return (location, key-template-id). kind: person | user | neg | neutral | first | last."""
    root = _root_and_path(rng)
    pre = ""
    if kind == "person":
        roles, heads = _split_roles(split, ROLES_PERSON, "p"), HEADS_PERSON
        if rng.random() < .30: key, tid = rng.choice(roles), "bare_role"
        elif rng.random() < .3: key, tid = rng.choice(heads), "head"
        else: key, tid = _style(rng, [rng.choice(roles), rng.choice(["name", "fullname", "nm", "contact"])], ""), "role_head"
    elif kind == "user":
        roles = _split_roles(split, ROLES_USER, "u")
        if rng.random() < .55: key, tid = rng.choice(HEADS_USER), "head"
        else: key, tid = _style(rng, [rng.choice(roles), rng.choice(["user", "username", "login", "handle", "nick"])], ""), "role_head"
    elif kind == "first":
        key = rng.choice(["first_name", "firstname", "given_name", "fname", "forename", "first", "givenName", "given"]); tid = "first"
        if rng.random() < .3: key = _style(rng, [rng.choice(_split_roles(split, ROLES_PERSON, "p")), "first", "name"], "")
    elif kind == "last":
        key = rng.choice(["last_name", "lastname", "surname", "family_name", "lname", "last", "familyName", "family"]); tid = "last"
        if rng.random() < .3: key = _style(rng, [rng.choice(_split_roles(split, ROLES_PERSON, "p")), "last", "name"], "")
    elif kind == "neg":
        roles = _split_roles(split, ROLES_NEG, "n")
        r = rng.random()
        if r < .35: key, tid = rng.choice(roles), "bare_role"
        elif r < .6: key, tid = rng.choice(["name", "title", "label", "description", "user_agent", "user_id", "session_id",
                                            "request_id", "email", "url", "path", "version"]), "head"
        else: key, tid = _style(rng, [rng.choice(roles), rng.choice(HEADS_NEG)], ""), "role_head"
    else:
        key, tid = rng.choice(NEUTRAL_KEYS), "neutral"
    return root + pre + key, f"{kind}:{tid}"


# ------------------------------------------------------------------ entity & filler renderers
_LATIN = re.compile(r"^[A-Za-zÀ-ɏ'’\-]+$")
PERSON_NEG = ("TEAM", "JOB", "ORG", "CITY", "PROD")
USER_NEG = ("HEX", "UUID", "NUMID", "HOST", "SLUG", "TOKEN", "EMAIL")
TEAM_WORDS = ["Support", "Everyone", "Team", "Sales", "Admin", "Customer", "there", "all", "World", "Sir", "Madam",
              "Hiring Manager", "Customer Service", "Engineering", "HR", "Billing", "friend", "folks", "guest",
              "Accounts", "Helpdesk", "Operations", "Management", "Staff", "Colleagues", "Sales Team", "Reception"]
POS_SLOTS = {"P": "PERSON_NAME", "P2": "PERSON_NAME", "F": "PERSON_NAME", "F2": "PERSON_NAME", "L": "PERSON_NAME",
             "L2": "PERSON_NAME", "U": "USERNAME", "U2": "USERNAME"}
_SLOT = re.compile(r"\{(\w+)\}")


class Ctx:
    def __init__(self, rng: random.Random, split: str):
        self.rng, self.split = rng, split
        self.pool = {k: v[split] for k, v in POOL.items()}
        self.persons = {}  # slot -> (first, last)
        r = rng.random()
        self.case = "as" if r < .78 else "lower" if r < .87 else "upper" if r < .92 else "title"
        self.tags: set[str] = set()

    # -- helpers
    def pick(self, cat: str) -> str:
        return self.rng.choice(self.pool[cat])

    def digits(self, lo=1, hi=99) -> str:
        r = self.rng
        return str(r.randint(lo, hi)) if r.random() < .75 else str(r.randint(1970, 2012))

    def person_tokens(self, slot: str) -> tuple[str, str]:
        key = slot[-1] if slot[-1] == "2" else "1"
        if key not in self.persons:
            f = self.pick("first")
            same = POOL_BY_SCRIPT["last"][self.split].get(_script(f))
            l = self.rng.choice(same) if same and self.rng.random() < .93 else self.pick("last")
            self.persons[key] = (f, l)
        return self.persons[key]

    def person(self, slot: str) -> str:
        f, l = self.person_tokens(slot)
        r = self.rng.random()
        cjk = bool(_CJK.search(f)) and bool(_CJK.search(l))
        if slot.startswith("F"): return f
        if slot.startswith("L"): return l
        if cjk: return (l + f) if r < .6 else f"{l} {f}"
        if r < .66: return f"{f} {l}"
        if r < .74: return f"{l}, {f}"
        if r < .81: return f"{f} {self.rng.choice('ABCDEFGHJKLMNPRSTW')}. {l}"
        if r < .86: return f"{f[0]}. {l}"
        if r < .89: return f"{f} {self.pick('first')} {l}"
        return f"{f} {l}"

    def handle(self, slot: str) -> str:
        r = self.rng
        f, l = self.person_tokens(slot)
        ok = lambda s: bool(_LATIN.match(s)) and not _CJK.search(s)
        x = r.random()
        if x < .50 or not (ok(f) and ok(l)):
            h = self.pick("username")
            if r.random() < .25: h += self.digits()
        elif x < .85:
            f, l = f.lower().replace("'", "").replace("’", ""), l.lower().replace("'", "").replace("’", "")
            pat = r.randint(0, 9)
            h = [f"{f[0]}{l}", f"{f}.{l}", f"{f}_{l}", f"{f}{self.digits()}", f"{l}{f[0]}", f"{f}-{l}{self.digits()}",
                 f"{f}{l[:3]}{self.digits()}", f"{f[0]}{l}{self.digits()}", f"{l}.{f}", f"{f}{l}"][pat]
        else:
            w1, w2 = self.pick("word"), self.pick("word")
            pat = r.randint(0, 6)
            h = [f"{w1}{w2}", f"{w1}_{w2}", f"{w1.capitalize()}{w2.capitalize()}{self.digits()}", f"xX{w1}Xx",
                 f"{w1}-{w2}{self.digits()}", f"the_{w1}", f"{w1}.{w2}"][pat]
        return h

    def neg(self, kind: str) -> str:
        r, p = self.rng, self.pick
        if kind == "TEAM": return r.choice(TEAM_WORDS)
        if kind == "JOB": return p("job")
        if kind == "ORG":
            c = p("company")
            return c if r.random() < .6 else c + " " + r.choice(["Inc", "LLC", "GmbH", "Ltd", "Group", "Labs", "Corp"])
        if kind == "CITY": return p("city")
        if kind == "PLACE": return r.choice([p("street"), p("country")])
        if kind == "PROD":
            return f"{(p('word') if r.random() < .6 else p('company').split()[0]).capitalize()} {r.choice(['Pro', 'Max', 'X200', 'Lite', '3', 'Air', 'Plus', 'One', 'S5', 'Go'])}"
        if kind == "FILE": return f"{p('word')}_{p('word')}.{r.choice(LEX['file_ext'])}"
        if kind == "WORD": return p("word")
        if kind == "HEX": return "".join(r.choice("0123456789abcdef") for _ in range(r.choice((6, 8, 12, 16))))
        if kind == "UUID": return "-".join("".join(r.choice("0123456789abcdef") for _ in range(n)) for n in (8, 4, 4, 4, 12))
        if kind == "NUMID": return "".join(r.choice("0123456789") for _ in range(r.randint(4, 10)))
        if kind == "HOST": return r.choice([f"srv-{r.randint(1, 99)}", f"{p('word')}.example.com", f"db{r.randint(1, 9)}-{p('word')[:4]}"])
        if kind == "SLUG": return f"{p('word')}-{p('word')}-{r.randint(1, 999)}"
        if kind == "TOKEN": return "".join(r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") for _ in range(r.randint(10, 22)))
        if kind == "EMAIL": return f"{p('word')}{r.choice(['', '.', '_'])}{p('word')}@{r.choice(['example.com', 'mail.test', p('word') + '.org'])}"
        raise KeyError(kind)

    def fixed(self, name: str) -> str:
        r = self.rng
        if name == "DATE": return f"{r.randint(2019, 2026)}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}"
        if name == "TIME": return f"{r.randint(0, 23):02d}:{r.randint(0, 59):02d}"
        if name == "IP": return ".".join(str(r.randint(1, 254)) for _ in range(4))
        if name == "NUM": return str(r.randint(1, 99999))
        if name == "PHONE": return f"+{r.randint(1, 98)} {r.randint(100, 999)} {r.randint(1000, 9999)}"
        if name == "K": return r.choice(["id", "ref", "ts", "page", "lang", "sort", "theme", "v"])
        if name in ("EMAIL", "CITY", "ORG", "PROD", "FILE", "HEX", "HOST", "SLUG", "WORD", "JOB", "TOKEN", "UUID", "NUMID", "PLACE", "TEAM"):
            return self.neg(name)
        raise KeyError(name)

    def style(self, s: str) -> str:
        if self.case == "as": return s
        if self.case == "lower": return s.lower()
        if self.case == "upper": return s.upper()
        return s.title()


def render_template(tpl: str, ctx: Ctx, negkinds: Sequence[str] = (), p_neg: float = 0.0) -> tuple[list[tuple[str, str | None]], bool]:
    """Fill a template into (text, label|None) pieces. Positive slots become negatives w.p. ``p_neg`` per slot."""
    pieces: list[tuple[str, str | None]] = []
    last, any_neg = 0, False
    for m in _SLOT.finditer(tpl):
        if m.start() > last:
            pieces.append((tpl[last:m.start()], None))
        name = m.group(1)
        if name in POS_SLOTS:
            if negkinds and ctx.rng.random() < p_neg:
                pieces.append((ctx.style(ctx.neg(ctx.rng.choice(negkinds))), None)); any_neg = True
            else:
                val = ctx.handle(name) if name[0] == "U" else ctx.person(name)
                pieces.append((ctx.style(val), POS_SLOTS[name]))
        else:
            v = ctx.fixed(name)
            pieces.append((v if name in ("DATE", "TIME", "IP", "NUM", "PHONE", "K", "EMAIL", "HEX", "UUID") else ctx.style(v), None))
        last = m.end()
    if last < len(tpl):
        pieces.append((tpl[last:], None))
    return pieces, any_neg


def assemble(pieces: Sequence[tuple[str, str | None]]) -> tuple[str, list[tuple[int, int, str]]]:
    text, spans, pos = [], [], 0
    for s, lab in pieces:
        if lab and s:
            spans.append((pos, pos + len(s), lab))
        text.append(s); pos += len(s)
    return "".join(text), spans


# ------------------------------------------------------------------ cue banks (hash-partitioned across splits)
# (template, negkinds): when negkinds is non-empty each positive slot may be replaced by a non-person filler,
# so the SAME frame appears with and without an entity.
def _bank(neg, *tpls):
    return [(t, neg) for t in tpls]


PERSON_WEAK = _bank(PERSON_NEG,
    "Dear {P},", "Hello {F},", "Hi {F}!", "Hey {F},", "Good morning {P},", "Greetings {P}", "Hello Mr. {L},",
    "Dear Ms. {L},", "Dr. {P}", "Mrs. {L} called", "Attn: {P}", "Contact {P} for details", "Please contact {P}",
    "Assigned to {P}", "Assigned to: {P}", "Reviewer: {P}", "Reported by {P}", "Created by {P}", "Approved by {P}",
    "Sent by {P}", "Prepared by {P}", "Prepared for {P}", "Bill to: {P}", "Ship to {P}", "Shipping to {P}",
    "Billing contact: {P}", "Owner: {P}", "Account owner - {P}", "cc: {P}", "To: {P}", "Regarding {P}", "Reply to {P}",
    "Forwarded to {P}", "Escalated to {P}", "Welcome, {F}!", "Welcome back {F}", "Thanks, {F}", "Thanks {F}!",
    "Regards,\n{P}", "Best regards,\n{P}", "Sincerely,\n{P}", "Cheers,\n{F}", "Kind regards, {P}", "— {P}",
    "Signed: {P}", "Yours, {F}", "Cordialement,\n{P}", "Hola {F},", "Bonjour {F},", "Hallo {F},", "Ciao {F}!",
    "Estimado {P}:", "Sehr geehrter Herr {L},", "Cher {F},", "Olá {F}!", "Merhaba {F},",
    "Привет, {F}!", "Здравствуйте, {P}!",
    "Hello {F}, how are you?", "Hi {F}, your order has shipped.", "Hi {F}, your appointment on {DATE} is confirmed.",
    "Congratulations {F} on the promotion!", "Happy birthday {F}!", "Get well soon, {F}", "Is {F} available tomorrow?",
    "Please ask {F} to call me back.", "Tell {F} I said hi", "I spoke with {P} yesterday.", "Meeting with {P} at {TIME}",
    "Call {F} at {PHONE}", "Thank you for your help, {F}.", "Good evening, {P}.", "Hi {F} — quick question",
    "Welcome to the team, {F}", "Re: {P}'s request", "Per {P}'s email", "{F}, please confirm", "Dear Dr. {L},",
    "Pursuant to {P}", "On behalf of {P}", "Introducing {P}", "Thanks to {P} for the review")
PERSON_STRONG = _bank((),
    "My name is {P}", "My name is {P} and I need help with my account.", "I am {P}.", "I'm {F}, nice to meet you.",
    "Name: {P}", "Full name: {P}", "Patient name: {P}", "Passenger: {P}", "Cardholder name: {P}", "Customer name - {P}",
    "Employee: {P}", "{P} wrote:", "{P} commented:", "Posted by {P}", "Author: {P}", "Written by {P}",
    "Reservation under the name {P}", "This is {P} speaking", "{P} joined the call", "{F} and {F2} are attending.",
    "{P} and {P2} will present", "Ticket reassigned from {P} to {P2}", "{L} family reunion", "Booking for {P}, {NUM} guests",
    "Invoice for {P}", "Order placed by {P}", "Applicant: {P}", "Witness: {P}", "Patient {P}, age {NUM}",
    "{P} created the repository", "Message from {P}: see you at {TIME}", "{P} has been added to the project",
    "Next of kin: {P}", "Guardian: {P}, phone {PHONE}", "Spouse: {P}", "Referred by {P}", "Interviewer: {P}",
    "{P} requested a refund of {NUM}", "Please welcome {P}!", "Student: {P}, grade {NUM}", "Mr. {L} and Mrs. {L2}",
    "Dear Mr. {P},", "RSVP: {P} (+{NUM})", "Name on card: {P}", "Account holder: {P}", "Signature of {P}",
    "{P} is the new {JOB}", "{F} {L}")
USER_WEAK_NEG = ("ORG", "CITY", "PROD", "TEAM")
USER_EXPLICIT = _bank((),
    "Logged in as {U}", "Signed in as @{U}", "login: {U}", "Login as {U}", "user {U} logged out", "User '{U}' not found",
    "User {U} created", "Invalid user {U}", "Account {U} locked", "Username: {U}", "Handle: @{U}", "Your username is {U}",
    "Reset password for {U}", "Failed password for {U} from {IP} port {NUM} ssh2", "Accepted publickey for {U} from {IP}",
    "Failed login for {U}", "su: user {U}", "sudo: {U} : TTY=pts/0 ; PWD=/home/{U}", "session opened for user {U} by (uid=0)",
    "[auth] {U} authenticated via sso", "Gamertag: {U}", "IGN: {U}", "Invalid password for {U}", "Banned user {U} for spam",
    "Reported user: {U}", "Your account {U} has been verified", "Unlock user {U}?", "Last login by {U}: {DATE}",
    "Welcome back, @{U}", "@{U} mentioned you in a comment", "Reply from @{U}", "Thanks @{U}!", "Hello @{U}",
    "Hey @{U}, nice work", "DM from @{U}", "Mentioned @{U} and @{U2}", "Reviewed by @{U}", "nick {U} changed to {U2}",
    "{U} \u2192 {U2}", "Session for {U} expired", "Posted by u/{U}", "player {U} joined the lobby")
USER_WEAK = _bank(USER_WEAK_NEG,
    "cc @{U}", "Follow {U} on the platform", "by {U} on {DATE}", "owner: {U}", "assignee: @{U}", "github.com/{U}",
    "twitter.com/{U}", "{U} has left the channel", "{U} joined the chat", "committed by {U}", "added {U} as collaborator",
    "{U} pushed {NUM} commits to main", "Added {U} to the group", "{U} is typing...", "Kicked {U} from #general",
    "Profile of {U}", "{U} upvoted your answer", "Subscribe to {U}", "Merged by {U}", "Maintainer: {U}", "Forked from {U}")
MIXED = _bank((),
    "{P} (@{U}) commented on your photo", "{P} aka {U} posted a reply", "User {U} ({P}) updated the profile",
    "Hi {F}, your username {U} is ready.", "{U} ({P}) joined the team", "Profile: {P} / @{U}", "{P} logged in as {U}",
    "From: {P} (@{U})", "Welcome {F}, your handle is @{U}", "Owner {P}, login {U}", "{P} <@{U}>",
    "Account {U} belongs to {P}", "Contact {P} or ping @{U}", "{U} ({P}) — admin")
FILLER = ["Please review the attached {FILE} before {DATE}.", "Your order #{NUM} has shipped.",
          "The {PROD} is now available in stores.", "{ORG} announced quarterly results.", "Visit {CITY} this summer!",
          "See you at {TIME}.", "Server {HOST} restarted at {TIME}.", "Thanks for choosing {ORG}!", "Error code {NUM}: timeout",
          "Reference {HEX}", "Total: {NUM} items", "Download {FILE} to continue.", "Your session {UUID} has expired.",
          "Open {FILE} and follow the steps.", "Flights to {CITY} are delayed.", "Build {SLUG} passed all checks.",
          "Please do not reply to this message.", "Lorem ipsum dolor sit amet.", "Office hours: 9-17.", "ETA {TIME}."]
LOG_TPLS = _bank((),
    "{DATE} INFO auth: user={U} ip={IP} result=ok", "[{DATE} {TIME}] \"{U}\" authenticated",
    "sshd[{NUM}]: Failed password for invalid user {U} from {IP} port {NUM} ssh2",
    "{IP} - {U} [{DATE}] \"GET /index.html HTTP/1.1\" 200 {NUM}",
    "{\"event\":\"login\",\"user\":\"{U}\",\"ip\":\"{IP}\"}".replace("{\"", "{\"").replace("\"}", "\"}"),
    "level=info msg=\"signed in\" username={U}", "audit: actor={U} action=update target={HEX}",
    "Jul 9 {TIME} host sudo: {U} : command not allowed", "{DATE} WARN [{HOST}] user {U} exceeded rate limit",
    "pam_unix(sshd:session): session opened for user {U}", "{TIME} DEBUG uid={NUMID} login={U}",
    "<{NUM}>1 {DATE} {HOST} app - - user={U} op=read", "event=logout user_id={NUMID} username={U}")
URL_TPLS = _bank((),
    "/users/{U}", "/users/{U}/profile", "/u/{U}", "/u/{U}/posts", "/@{U}", "/profile/{U}?tab=2",
    "/api/v{NUM}/accounts/{U}/settings", "/members/{U}/", "https://{HOST}/~{U}/", "/api/users/{U}/followers",
    "/{U}/repos", "/user/{U}/edit", "/accounts/{U}/security", "/people/{U}")
URL_NEG = ["/products/{SLUG}", "/files/{FILE}", "/category/{WORD}", "/city/{CITY}", "/static/{FILE}", "/docs/{SLUG}",
           "/search?q={WORD}&page=2", "/download/{FILE}", "/api/v1/orders/{NUMID}", "/blog/{SLUG}", "/company/{ORG}"]
HEADER_TPLS = [  # (header name, template, label kind)
    ("from", "{P} <{EMAIL}>", None), ("from", "\"{P}\" <{EMAIL}>", None), ("to", "{P} <{EMAIL}>", None),
    ("reply-to", "{P} <{EMAIL}>", None), ("cc", "{P} <{EMAIL}>, {P2} <{EMAIL}>", None), ("sender", "{P}", None),
    ("x-forwarded-user", "{U}", None), ("remote-user", "{U}", None), ("x-user", "{U}", None),
    ("x-requested-by", "{U}", None), ("referer", "https://{HOST}/users/{U}", None), ("referer", "https://{HOST}/@{U}/posts", None),
    ("cookie", "sid={HEX}; user={U}; lang=en", None), ("set-cookie", "username={U}; Path=/; HttpOnly", None),
    ("x-author", "{P}", None), ("x-owner", "{P}", None)]
HEADER_NEG = [("user-agent", "{UA}"), ("host", "{HOST}"), ("origin", "https://{HOST}"), ("x-request-id", "{UUID}"),
              ("referer", "https://{HOST}/products/{SLUG}"), ("x-company", "{ORG}"), ("server", "{WORD}/{NUM}"),
              ("x-trace", "{HEX}"), ("content-type", "application/json"), ("accept-language", "en-US,en;q=0.9"),
              ("x-forwarded-for", "{IP}"), ("x-app", "{PROD}")]
MARKUP = _bank((),
    "<input type=\"text\" name=\"username\" value=\"{U}\">", "<span class=\"author\">{P}</span>",
    "<a href=\"/users/{U}\">{U}</a>", "<td>{P}</td>", "<meta name=\"author\" content=\"{P}\">",
    "<div data-user=\"{U}\">Hello</div>", "<li class=\"member\">{P}</li>", "<h2>Profile: {P}</h2>",
    "<p>Posted by <b>{U}</b></p>", "<label>Name</label><input value=\"{P}\">",
    "[{P}](/people/{NUM})", "**{P}** wrote", "`{U}` logged in", "<user id=\"{NUM}\" login=\"{U}\"/>")
JSONTXT = [
    ('{"user":"%s","id":%s}', "U"), ('{"name":"%s","age":%s}', "P"), ('{"login":"%s","score":%s}', "U"),
    ('{"author":"%s","rev":%s}', "P"), ('{"owner":{"name":"%s"},"n":%s}', "P"), ('["%s",%s]', "P"),
    ('{"data":{"username":"%s"},"code":%s}', "U"), ('{"from":"%s","seq":%s}', "P")]
NEG_ONLY_TEXT = ["user_id={NUMID}", "session_id={UUID}", "Logged in session {HEX}", "token={TOKEN}", "User {NUMID} created",
                 "Account {NUMID} locked", "uid={NUMID} gid={NUMID}", "Request {UUID} from {IP}", "Failed password from {IP} port {NUM} ssh2",
                 "Order {HEX} confirmed", "Contact: {EMAIL}", "Reply to {EMAIL}", "Invalid user from {IP}","Welcome to {CITY}!", "Hello world", "Hi there, how can we help?", "Dear customer, your request is received.",
                 "Hello team, standup moved to {TIME}.", "Signed and sealed", "Congratulations on the launch of {PROD}!",
                 "Thank you for contacting {ORG} support.", "Greetings from {CITY}!", "Hey everyone, {HOST} is down.",
                 "Good morning, everyone", "Dear Sir or Madam,", "Hello {ORG},", "Hi all, see attached {FILE}", "Account locked",
                 "Logged in successfully", "User not found", "Invalid password", "Contact support", "Signed in via SSO"]
UA_LIST = LEX["user_agent"]


def _partition_templates(bank, split: str, salt: str):
    return [(t, n) for t, n in bank if bucket(t, "cue" + salt) in (split, "common")]


OWN_BIAS = 0.6  # val/calib draw 60% of their cue templates from split-exclusive frames (train: uniform over its share)


def _pick_template(rng: random.Random, bank, split: str, salt: str):
    avail = _partition_templates(bank, split, salt)
    if split != "train":
        own = [x for x in avail if bucket(x[0], "cue" + salt) == split]
        if own and rng.random() < OWN_BIAS:
            return rng.choice(own)
    return rng.choice(avail)


# ------------------------------------------------------------------ example builders
KIND_WEIGHTS = {"field_person": .10, "field_user": .08, "field_display": .02, "field_first_last": .06, "field_neg": .12,
                "field_neutral": .05, "text_person": .13, "text_user": .09, "text_mixed": .03, "text_neg": .05,
                "narrative": .05, "kv": .08, "log": .04, "url": .04, "header": .04, "markup": .02}
TEXT_KEYS = ["message", "comment", "text", "body", "notes", "description", "bio", "content", "log", "msg", "summary",
             "subject", "q", "query", "payload", "raw", "data", "value", "note", "title", "reason", "feedback", "reply"]
LOG_KEYS = ["log", "line", "message", "msg", "entry", "event", "audit", "syslog", "text", "raw"]
URL_KEYS = ["path", "uri", "redirect_uri", "link", "href", "next", "return_to", "url", "target", "callback", "continue"]
NEG_VALUE_KINDS = ["ORG", "CITY", "PROD", "FILE", "JOB", "WORD", "PLACE", "HOST", "SLUG", "HEX", "UUID", "NUMID", "EMAIL", "TOKEN"]


def _loc(rng: random.Random, kinds: Sequence[str] = TEXT_KEYS) -> str:
    if rng.random() < .12 and kinds is TEXT_KEYS:
        return "body.text"
    return _root_and_path(rng, (0, 0, 1, 1, 2)) + rng.choice(kinds)


def _noise(rng: random.Random, pieces: list) -> list:
    out = []
    if rng.random() < .06:   # frame literal in lower case (entities untouched)
        pieces = [(s.lower() if lab is None else s, lab) for s, lab in pieces]
    if pieces and pieces[-1][1] is None and pieces[-1][0][-1:] in ".!?:,;" and rng.random() < .12:
        pieces = pieces[:-1] + [(pieces[-1][0][:-1], None)]
    if rng.random() < .08:
        pieces = [(rng.choice(["Re: ", "FYI: ", ">> ", "[note] ", "- ", "* ", "1. ", "# ", "// ", "TODO: "]), None)] + list(pieces)
    for s, lab in pieces:
        if lab is None and rng.random() < .12 and " " in s:
            s = s.replace(" ", rng.choice(["  ", "\t", " ", " "]), 1) if rng.random() < .8 else s.replace(" ", "  ")
        out.append((s, lab))
    if rng.random() < .05:
        out = [('"', None)] + out + [('"', None)]
    elif rng.random() < .04:
        out = [("(", None)] + out + [(")", None)]
    return out


def _finish(rng: random.Random, pieces: list, tags: set) -> tuple[str, list]:
    pieces = _noise(rng, pieces)
    text, spans = assemble(pieces)
    if len(text) > 8 and rng.random() < .04:  # fragmented / truncated field text
        cut = rng.randint(3, len(text) - 1)
        text = text[:cut]
        spans = [(s, min(e, cut), l) for s, e, l in spans if s < cut]
        tags.add("truncated")
    if rng.random() < .01 and len(text) > 4:  # decode-replacement char in a non-entity position
        free = [i for i in range(len(text)) if not any(s <= i < e for s, e, _ in spans) and not text[i].isalnum()]
        if free:
            i = rng.choice(free); text = text[:i] + "�" + text[i + 1:]; tags.add("replacement_char")
    return text, spans


def _frame(ctx: Ctx, bank, split: str, salt: str, p_neg: float = .30):
    rng = ctx.rng
    tpl, neg = _pick_template(rng, bank, split, salt)
    pieces, any_neg = render_template(tpl, ctx, neg, p_neg)
    if any_neg: ctx.tags.add("hard_negative")
    if bucket(tpl, "cue" + salt) == split: ctx.tags.add("exclusive_template")
    return tpl, pieces


def _filler(ctx: Ctx):
    return render_template(ctx.rng.choice(FILLER), ctx, (), 0)[0]


def build_example(rng: random.Random, split: str) -> tuple[str, str, list, list, set]:
    ctx = Ctx(rng, split)
    kind = rng.choices(list(KIND_WEIGHTS), list(KIND_WEIGHTS.values()))[0]
    tags = ctx.tags
    loc, tid, pieces = "", kind, []
    if kind == "field_person":
        loc, tid = make_key(rng, split, "person"); r = rng.random()
        if r < .13:
            pieces = [(ctx.style(ctx.neg(rng.choice(["ORG", "CITY", "JOB", "PROD", "TEAM", "FILE"]))), None)]; tags.add("hard_negative")
        else:
            v = rng.choices(["{P}", "{F}", "{L}", "{P} ({JOB})", "{P} - {JOB}", "{P} <{EMAIL}>", "{P}, {ORG}", "Dr. {P}", "{P} Jr.", "Mr. {P}"],
                            [62, 10, 4, 4, 3, 5, 3, 3, 2, 4])[0]
            pieces, _ = render_template(v, ctx)
    elif kind == "field_user":
        loc, tid = make_key(rng, split, "user")
        if rng.random() < .12:
            pieces = [(ctx.neg(rng.choice(USER_NEG)), None)]; tags.add("hard_negative")
        else:
            pieces, _ = render_template(rng.choices(["{U}", "@{U}", "{U} ({P})", "{U}@"], [84, 8, 4, 4])[0] if False else rng.choices(["{U}", "@{U}", "{U} ({P})"], [88, 8, 4])[0], ctx)
    elif kind == "field_display":
        loc = _loc(rng, ["display_name", "displayName", "nickname", "screen_name", "name", "profile_name", "alias_name", "visible_name"])
        pieces, _ = render_template(rng.choice(["{P}", "{U}"]), ctx); tid = "display"
    elif kind == "field_first_last":
        which = rng.choice(["first", "last"]); loc, tid = make_key(rng, split, which)
        pieces, _ = render_template("{F}" if which == "first" else "{L}", ctx)
    elif kind == "field_neg":
        loc, tid = make_key(rng, split, "neg"); k = loc.lower()
        if "user_agent" in k: pieces = [(rng.choice(UA_LIST), None)]
        elif "user_id" in k or k.endswith("_id") or "session" in k or "request" in k: pieces = [(ctx.neg(rng.choice(["HEX", "UUID", "NUMID", "TOKEN"])), None)]
        elif "email" in k: pieces = [(ctx.neg("EMAIL"), None)]
        else: pieces = [(ctx.style(ctx.neg(rng.choice(NEG_VALUE_KINDS))), None)]
        tags.add("hard_negative")
    elif kind == "field_neutral":
        loc, tid = make_key(rng, split, "neutral")
        if rng.random() < .5:
            pieces, _ = render_template("{P}", ctx)
        else:
            pieces = [(ctx.style(ctx.neg(rng.choice(["ORG", "CITY", "PROD", "JOB", "FILE", "WORD", "PLACE"]))), None)]; tags.add("hard_negative")
    elif kind in ("text_person", "text_user", "text_mixed", "text_neg", "narrative"):
        loc = _loc(rng)
        if kind == "text_person":
            bank, salt = (PERSON_WEAK, "pw") if rng.random() < .55 else (PERSON_STRONG, "ps")
        elif kind == "text_user": bank, salt = (USER_EXPLICIT, "ue") if rng.random() < .7 else (USER_WEAK, "uw")
        elif kind == "text_mixed": bank, salt = MIXED, "mx"
        else: bank, salt = None, ""
        if kind == "text_neg":
            tid = rng.choice(NEG_ONLY_TEXT); pieces, _ = render_template(tid, ctx); tags.add("hard_negative")
        elif kind == "narrative":
            parts = []
            for b, s in rng.sample([(PERSON_WEAK, "pw"), (PERSON_STRONG, "ps"), (USER_EXPLICIT, "ue"), (USER_WEAK, "uw"), (MIXED, "mx")], rng.choice((2, 2, 3))):
                t, pc = _frame(ctx, b, split, s); parts.append(pc); tid = "narr"
                if rng.random() < .5: parts.append(_filler(ctx))
            for i, pc in enumerate(parts):
                if i: pieces.append((rng.choice([" ", "\n", "  ", ". "]), None))
                pieces += pc
        else:
            tid, pieces = _frame(ctx, bank, split, salt)
            if rng.random() < .35:
                f = _filler(ctx)
                pieces = (f + [(rng.choice([" ", "\n"]), None)] + pieces) if rng.random() < .5 else (pieces + [(rng.choice([" ", "\n"]), None)] + f)
    elif kind == "kv":
        tid = "kv"; target = rng.choices(["person", "user", "first", "last", "neg"], [28, 28, 4, 4, 36])[0]
        sep, eq = rng.choice([("&", "="), ("; ", "="), ("\n", ": "), (" | ", ": "), (" ", "="), (",", "="), ("&", "="), ("\n", "=")])
        keys = [rng.choice(["id", "ref", "ts", "page", "lang", "sort", "theme", "v", "company", "city", "file", "plan", "role"]) for _ in range(rng.randint(1, 4))]
        vals = {"id": "NUMID", "ref": "HEX", "ts": "NUM", "page": "NUM", "lang": None, "sort": None, "theme": None, "v": "NUM", "company": "ORG",
                "city": "CITY", "file": "FILE", "plan": None, "role": None}
        fixed_vals = {"lang": "en", "sort": "asc", "theme": "dark", "plan": "pro", "role": "member"}
        tkey = make_key(rng, split, {"first": "first", "last": "last"}.get(target, target))[0].split(".")[-1]
        pairs = []
        for k in keys:
            v = vals[k]; pairs.append([(k, None), (eq, None), (fixed_vals[k] if v is None else ctx.fixed(v), None)])
        if target == "neg":
            tv = [(ctx.style(ctx.neg(rng.choice(["ORG", "CITY", "PROD", "FILE", "JOB", "PLACE", "HEX", "TOKEN", "EMAIL"]))), None)]; tags.add("hard_negative")
        elif target == "user": tv, _ = render_template("{U}", ctx)
        elif target == "first": tv, _ = render_template("{F}", ctx)
        elif target == "last": tv, _ = render_template("{L}", ctx)
        else:
            tv, _ = render_template("{P}", ctx)
            if sep == "&" and rng.random() < .6:
                s, lab = tv[0]; enc = "+" if rng.random() < .55 else "%20"; tv = [(s.replace(" ", enc), lab)]
        pairs.insert(rng.randint(0, len(pairs)), [(tkey, None), (eq, None)] + tv)
        for i, pr in enumerate(pairs):
            if i: pieces.append((sep, None))
            pieces += pr
        loc = rng.choice(["header.cookie", "header.set-cookie", "header.referer", "body.text", "body.text"]) if rng.random() < .45 else _loc(rng, ["query_string", "raw", "payload", "cookie", "log", "text", "data", "params", "details"])
    elif kind == "log":
        loc = _loc(rng, LOG_KEYS); tid, pieces = _frame(ctx, LOG_TPLS, split, "lg")
    elif kind == "url":
        loc = _loc(rng, URL_KEYS)
        if rng.random() < .28:
            tid = rng.choice(URL_NEG); pieces, _ = render_template(tid, ctx); tags.add("hard_negative")
        else:
            tid, pieces = _frame(ctx, URL_TPLS, split, "ur", .0)
        if rng.random() < .3: pieces = [("https://" + ctx.neg("HOST"), None)] + pieces
    elif kind == "header":
        if rng.random() < .3:
            name, t = rng.choice(HEADER_NEG); tid = "hdr:" + name; loc = "header." + name
            pieces, _ = render_template(t.replace("{UA}", "{HOST}"), ctx)
            if name == "user-agent": pieces = [(rng.choice(UA_LIST), None)]
            tags.add("hard_negative")
        else:
            name, t, _x = rng.choice(HEADER_TPLS); tid = "hdr:" + name; loc = "header." + name
            pieces, _ = render_template(t, ctx)
    else:  # markup / embedded json
        loc = _loc(rng)
        if rng.random() < .5:
            tid, pieces = _frame(ctx, MARKUP, split, "mk", .25)
        else:
            fmt, which = rng.choice(JSONTXT); tid = "json:" + fmt
            ent = ctx.style(ctx.handle("U") if which == "U" else ctx.person("P"))
            b = fmt.split("%s")
            pieces = [(b[0], None), (ent, "USERNAME" if which == "U" else "PERSON_NAME"), (b[1], None), (str(rng.randint(1, 999)), None), (b[2], None)]
    text, spans = _finish(rng, pieces, tags)
    ents = [text[s:e] for s, e, _ in spans]
    if any(not x.isascii() for x in ents): tags.add("unicode")
    if len(spans) >= 2: tags.add("multi_entity")
    if not spans and "hard_negative" not in tags and kind.startswith(("field", "text", "kv", "url")): tags.add("no_entity")
    return kind, str(tid), [loc, text], spans, tags


def generate_split(split: str, n: int, seed: int) -> list[Example2]:
    out, seen, i, bad = [], set(), 0, 0
    while len(out) < n:
        rng = random.Random(f"{seed}|{split}|{i}"); i += 1
        kind, tid, (loc, text), spans, tags = build_example(rng, split)
        if not text.strip() or (loc, text) in seen:
            continue
        try:
            spans_to_tags(tokenize(text), spans)
        except ValueError:
            bad += 1
            continue
        seen.add((loc, text))
        out.append(Example2(f"{split}2-{len(out):06d}", split, kind, tid, loc, text, tuple(sorted(spans)), tuple(sorted(tags))))
    if bad > 0.02 * i:
        raise RuntimeError(f"too many unalignable examples ({bad}/{i}) in split {split}")
    return out


def generate_dataset(seed: int = 20261014, sizes: dict | None = None) -> dict[str, list[Example2]]:
    sizes = sizes or DEFAULT_SIZES
    return {s: generate_split(s, sizes[s], seed) for s in SPLITS}


# ------------------------------------------------------------------ IO / audit
def dumps_split(exs: Iterable[Example2]) -> str:
    return "".join(json.dumps(e.to_json(), ensure_ascii=False, sort_keys=True) + "\n" for e in exs)


def read_split(path) -> list[Example2]:
    import gzip
    op = gzip.open if str(path).endswith(".gz") else open
    with op(path, "rt", encoding="utf-8") as f:
        return [Example2.from_json(json.loads(l)) for l in f if l.strip()]


def leakage_report(ds: dict[str, list[Example2]]) -> dict:
    sp = list(ds)
    pairs = [(a, b) for i, a in enumerate(sp) for b in sp[i + 1:]]
    ent = lambda exs: {e.text[s:t].lower() for e in exs for s, t, _ in e.spans}
    toks = lambda exs: {x.text.lower() for e in exs for s, t, _ in e.spans for x in tokenize(e.text[s:t])}
    rep = {"exact_text_duplicates_with_entities": 0, "exact_text_duplicates": 0, "entity_string_overlap": 0, "entity_token_overlap": 0, "shared_templates_excluding_common": 0,
           "shared_negative_lexicon_items": 0}
    for a, b in pairs:
        rep["exact_text_duplicates"] += len({(e.location, e.text) for e in ds[a]} & {(e.location, e.text) for e in ds[b]})
        rep["exact_text_duplicates_with_entities"] += len({(e.location, e.text) for e in ds[a] if e.spans} & {(e.location, e.text) for e in ds[b] if e.spans})
        rep["entity_string_overlap"] += len(ent(ds[a]) & ent(ds[b]))
        rep["entity_token_overlap"] += len(toks(ds[a]) & toks(ds[b]))
        ta = {e.template for e in ds[a]}; tb = {e.template for e in ds[b]}
        rep["shared_templates_excluding_common"] += len({t for t in ta & tb if t in CUE_SALT and bucket(t, "cue" + CUE_SALT[t]) != "common"})
    for cat in POOL:
        for a, b in pairs:
            rep["shared_negative_lexicon_items"] += len({w.lower() for w in POOL[cat][a]} & {w.lower() for w in POOL[cat][b]})
    return rep


CUE_SALT: dict[str, str] = {}
for _bank_, _salt in ((PERSON_WEAK, "pw"), (PERSON_STRONG, "ps"), (USER_EXPLICIT, "ue"), (USER_WEAK, "uw"), (MIXED, "mx"),
                      (LOG_TPLS, "lg"), (URL_TPLS, "ur"), (MARKUP, "mk")):
    for _t, _n in _bank_:
        CUE_SALT[_t] = _salt


def common_cue_share(ds: dict) -> dict:
    """Fraction of each split's cue-template examples whose template is 'common' (appears in every split by design)."""
    out = {}
    for sp, exs in ds.items():
        cues = [e for e in exs if e.template in CUE_SALT]
        out[sp] = round(sum(1 for e in cues if bucket(e.template, "cue" + CUE_SALT[e.template]) == "common") / max(len(cues), 1), 3)
    return out
