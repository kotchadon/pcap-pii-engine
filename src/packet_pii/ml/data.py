"""Synthetic, leakage-controlled dataset of HTTP-field-like text with PERSON_NAME / USERNAME spans.

Everything is fake (hand-written name lists + procedurally generated pseudo-words);
no external data. Pure standard library, fully deterministic for a given seed.

Leakage controls
----------------
* Every lexical pool (first names, last names, handle words, cities, companies,
  products, file stems, ...) is partitioned across splits by a stable hash of the
  word, so identities AND negative vocabulary never repeat across splits.
  (Otherwise "unseen word" would itself be a cue for PERSON_NAME.)
* Every template *family* belongs to exactly one split; free-text / key-value / URL
  frames are never shared across splits. Field-value examples (``kind`` starting
  with ``field_``) share a few very common key paths (e.g. ``username``) across
  splits by design; each split also has exclusive key names.
* ``leakage_report`` checks exact duplicates, template/skeleton overlap and
  lexical-pool overlap, and the tests assert it is clean.
"""
from __future__ import annotations

import hashlib
import json
import random
import re
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Sequence

from .spans import spans_to_tags, tokenize

SPLITS = ("train", "val", "calib", "test")
SPLIT_WEIGHTS = (70, 10, 10, 10)
DEFAULT_SIZES = {"train": 9000, "val": 1500, "calib": 1500, "test": 2500}


@dataclass(frozen=True)
class Example:
    id: str
    split: str
    family: str
    kind: str
    template: str
    skeleton: str
    location: str
    text: str
    spans: tuple  # ((start, end, label), ...)

    def to_json(self) -> dict:
        d = dict(self.__dict__)
        d["spans"] = [list(s) for s in self.spans]
        return d

    @staticmethod
    def from_json(d: dict) -> "Example":
        d = dict(d)
        d["spans"] = tuple(tuple(s) for s in d["spans"])
        return Example(**d)


# ----------------------------------------------------------------- lexical pools
FIRST_REAL = ("Maria Anna Peter James Sofia Liam Emma Noah Olivia Lucas Mia Ethan Ava Daniel Chloé Zoë José Søren "
              "Łukasz Renée Anaïs Björn Jürgen Müge Ángel Inés Thérèse François Håkon Václav Dmitri Ivan Anya "
              "Priya Rahul Aisha Omar Fatima Hassan Wei Mei Hiro Yuki Sakura Min-jun Ji-woo Kofi Amara Thabo "
              "Niamh Siobhan Ciarán Giulia Matteo Chiara Luca Elena Pavel Katarina Milan Ingrid Lars Astrid "
              "Иван Анна Мария Дмитрий Αλέξανδρος Ελένη 李 王 田中 محمد").split()
LAST_REAL = ("Smith Johnson Garcia Müller Schneider Rossi Dubois Kowalski Nowak Novák Ivanov Petrov Silva Santos "
             "Fernández González López Martínez Sørensen Lindqvist Andersson O'Brien McAllister D'Angelo "
             "Nguyen Tran Kim Park Chen Wang Tanaka Suzuki Sato Patel Sharma Khan Ahmed Hussain Okafor Mensah "
             "Dlamini Haddad Mansour Çelik Yılmaz Öztürk Papadopoulos Popescu Horvat Jovanović Kovács Szabó "
             "Eriksen Hansen Johansen Bergström Virtanen Korhonen Иванов Петров Смирнов Παπαδόπουλος 李 王 田中").split()
CITY_REAL = ("Springfield Riverside Lakewood Oakland Fairview Georgetown Madison Clinton Franklin Salem Dayton "
             "Paris Berlin Madrid Rome Vienna Lisbon Dublin Oslo Kyoto Osaka Lagos Nairobi Cairo Lima Quito Perth "
             "Zürich Málaga Kraków Göteborg Curitiba").split()
HANDLE_REAL = ("dark pixel wolf ninja coder cat fox star blue shadow dragon gamer storm cyber turbo happy lazy "
               "mighty tiny silent rapid cosmic frozen golden iron red green night sun moon panda tiger eagle "
               "ghost rocket pirate wizard robot hacker pilot rider").split()
WORD_REAL = ("apple table river window garden market summer winter engine bridge candle forest planet silver "
             "ticket basket orange pillow mirror anchor ladder button carpet jacket kitchen lemon harbor island "
             "journal kettle lantern meadow napkin oyster parcel quarry ribbon saddle thimble umbrella valley").split()
FILE_EXT = ("pdf", "docx", "png", "csv", "zip", "log", "txt", "jpg", "xlsx", "json", "tar.gz")
COMPANY_SUFFIX = ("Labs", "Systems", "Industries", "Group", "Holdings", "GmbH", "Ltd", "Inc", "Dynamics",
                  "Logistics", "Partners", "Corp", "Foods", "Motors")
PRODUCT_TAIL = ("Pro", "Max", "Mini", "Lite", "Air", "Plus", "X200", "3000", "Ultra", "S5", "One", "Go")
CITY_SUFFIX = ("ville", "burg", "ton", "field", "port", "dale", "mouth", "ford", "haven", "stad")
NAME_SUFFIX = ("son", "berg", "ski", "ova", "ez", "ini", "man", "ford", "sen", "ić", "ov", "dottir")

_ONS = ["m", "d", "k", "l", "r", "s", "t", "v", "n", "br", "ch", "gr", "sh", "z", "al", "em", "ol", "ar",
        "fl", "pr", "st", "tr", "j", "h", "b", "g", "p", "c", "f", "w"]
_VOW = ["a", "e", "i", "o", "u", "ia", "ou", "ey", "ae", "io"]
_COD = ["", "", "n", "r", "l", "s", "m", "k", "th", "nd", "x", "t"]


def _pseudo(rng: random.Random, syl: int, cod: Sequence[str] = _COD) -> str:
    w = ""
    for _ in range(syl):
        w += rng.choice(_ONS) + rng.choice(_VOW)
    return w + rng.choice(cod)


def _bucket(word: str, salt: str) -> str:
    h = int(hashlib.sha256((salt + "|" + word.lower()).encode("utf-8")).hexdigest()[:8], 16) % 100
    acc = 0
    for s, w in zip(SPLITS, SPLIT_WEIGHTS):
        acc += w
        if h < acc:
            return s
    return SPLITS[-1]


def _build_pools() -> dict[str, dict[str, list[str]]]:
    """Fixed-seed pools -> {category: {split: [words]}} (hash-partitioned, no word in two splits)."""
    rng = random.Random(20240601)
    cats: dict[str, list[str]] = {}
    firsts = list(FIRST_REAL) + [_pseudo(rng, rng.choice((2, 2, 3))).capitalize() for _ in range(1100)]
    lasts = list(LAST_REAL) + [(_pseudo(rng, 2) + rng.choice(NAME_SUFFIX)).capitalize() for _ in range(1100)]
    cats["first"], cats["last"] = firsts, lasts
    cats["city"] = list(CITY_REAL) + [(_pseudo(rng, 2) + rng.choice(CITY_SUFFIX)).capitalize() for _ in range(450)]
    cats["company"] = [_pseudo(rng, 2).capitalize() + " " + rng.choice(COMPANY_SUFFIX) for _ in range(500)]
    cats["product"] = [_pseudo(rng, 2).capitalize() + " " + rng.choice(PRODUCT_TAIL) for _ in range(500)]
    cats["handleword"] = list(HANDLE_REAL) + [_pseudo(rng, rng.choice((1, 2))) for _ in range(500)]
    cats["word"] = list(WORD_REAL) + [_pseudo(rng, 2) + rng.choice(("ing", "er", "ment", "ly", "")) for _ in range(500)]
    cats["stem"] = [rng.choice(("report", "invoice", "backup", "photo", "scan", "notes", "export", "draft")) + "_" +
                    _pseudo(rng, 1) + str(rng.randint(1, 99)) for _ in range(500)]
    out: dict[str, dict[str, list[str]]] = {}
    for cat, words in cats.items():
        seen = set()
        out[cat] = {s: [] for s in SPLITS}
        for w in words:
            if w.lower() in seen:
                continue
            seen.add(w.lower())
            out[cat][_bucket(w, cat)].append(w)
    return out


POOLS = _build_pools()

# ----------------------------------------------------------------- key pools (location names)
KEYS = {
    "person": {"common": ["name", "full_name", "customer_name", "author", "owner_name"],
               "train": ["contact_name", "recipient", "patient_name", "student", "employee_name", "fullName"],
               "val": ["client", "sender_name", "passenger", "attendee"],
               "calib": ["buyer", "signee", "participant"],
               "test": ["cardholder", "applicant", "guest_name", "billing_name", "displayName"]},
    "first": {"common": ["first_name", "firstname"], "train": ["given_name", "fname"], "val": ["forename"],
              "calib": ["first"], "test": ["givenName"]},
    "last": {"common": ["last_name", "lastname"], "train": ["surname", "lname"], "val": ["family_name"],
             "calib": ["last"], "test": ["familyName"]},
    "user": {"common": ["username", "user_name", "login"], "train": ["uname", "account_name", "screen_name"],
             "val": ["nick", "gamertag"], "calib": ["alias", "userHandle"], "test": ["handle", "display_handle"]},
    "neg": {"common": ["name", "title", "label", "description", "category", "version", "product_name", "company",
                       "organization", "city", "file_name", "filename", "hostname", "module", "user_agent",
                       "user_id", "session_id", "request_id", "build_id"],
            "train": ["item_name", "app_name", "project_name"], "val": ["store_name", "brand"],
            "calib": ["team_name", "theme"], "test": ["service_name", "device_name", "team", "channel_name"]},
}
PREFIXES = ["", "json_body.", "json_body.user.", "json_body.profile.", "json_body.data[0].", "form.", "query.",
            "json_body.customer.", "json_body.account.", "body.", "json_body.payload.user."]
TEXT_LOCS = ["json_body.message", "json_body.comment", "form.comment", "json_body.bio", "query.q", "json_body.text",
             "json_body.notes", "form.message", "json_body.description", "body.text", "json_body.items[0].note"]
KV_LOCS = ["header.cookie", "query_string", "body.raw", "json_body.log", "form.payload", "header.referer"]
URL_LOCS = ["url.path", "header.referer", "json_body.link", "json_body.redirect_uri"]

# ----------------------------------------------------------------- templates (family -> split-exclusive)
FIELD_VALUES = {
    "person": {"train": ["{P}", "{P}", "{L}, {F}"], "val": ["{P}", "{PM}"], "calib": ["{P}", "{L}, {F}"],
               "test": ["{P}", "{PM}", "{L}, {F}"]},
}
T = {  # kind -> split -> list of templates
    "text_person": {
        "train": ["Hi {F}, your order has shipped.", "Dear {P},\nThank you for your purchase.",
                  "My name is {P} and I need help with my account.", "Please contact {P} for more details.",
                  "Message from {P}: see you at 5pm", "Thanks, {F}!", "Order placed by {P} on 2024-03-02",
                  "{P} created the repository", "Regards,\n{P}", "I'm {F}, nice to meet you.",
                  "Meeting with {P} tomorrow at noon", "Assigned to {P}",
                  "Dear Ms. {L}, we have received your request.", "{F} and {F2} are attending.",
                  "Invoice for {P}, due next week"],
        "val": ["Hello {F}! Your ticket is open.", "Sincerely,\n{P}", "This is {P} calling about the invoice.",
                "Booking for {P}, 2 guests", "cc: {P}", "Ticket reassigned from {P} to {P2}",
                "Dear Mr. {L}, welcome aboard.", "Prepared by {P}"],
        "calib": ["Best wishes, {F}", "Reply to {P} before Friday.", "Welcome back, {F}!", "Signed by {P}",
                  "Hello Dr. {L}, results are attached.", "Contact: {P}"],
        "test": ["Good morning {P}, your appointment is confirmed.", "Hey {F}, are you coming tonight?",
                 "Reservation under the name {P}", "Written by {P}", "From: {P} (sales)",
                 "Hello Mr. {L}, thanks for visiting.", "I spoke with {F} yesterday about the refund.",
                 "Patient: {P}, age 42", "Congratulations {F} on the new job!", "Shipping to {PM}, 12 High Street"],
    },
    "text_user": {
        "train": ["Logged in as {U}", "@{U} mentioned you in a comment", "login attempt for user {U} failed",
                  "Follow {U} on the platform", "username: {U}", "player {U} joined the lobby", "Posted by u/{U}",
                  "User {U} changed their password"],
        "val": ["Account {U} was locked after 5 attempts", "session opened for user {U}",
                "@{U} replied to your post", "Banned user {U} for spam"],
        "calib": ["Added {U} to the group", "{U} has joined the chat", "DM from @{U}"],
        "test": ["Signed in as @{U}", "Invalid password for {U}", "Hello @{U}!", "Reported user: {U}",
                 "Thanks @{U} for the fix", "{U} pushed 3 commits to main"],
    },
    "text_mixed": {
        "train": ["{P} (@{U}) commented on your photo", "User {U} ({P}) updated the profile"],
        "val": ["{P} aka {U} posted a reply", "Welcome {F}, your handle is @{U}"],
        "calib": ["{U} ({P}) joined the team"],
        "test": ["Profile: {P} / @{U}", "Hi {F}, your username {U} is ready.", "{P} logged in as {U}"],
    },
    "kv": {
        "train": ["user={U}; theme=dark; lang=en", "Name: {P}\nCity: {CITY}\nPlan: pro",
                  "INFO action=login user={U} status=ok", "name={P|plus}&source=web", "Company: {COMPANY}\nCity: {CITY}"],
        "val": ["name={F}&page=2&sort=asc", "Username: {U}\nRole: member", "level=warn msg=\"login failed\" user={U}",
                "product={PRODUCT}&page=2"],
        "calib": ["Full name: {P}\nStatus: active", "uid={U} gid=users", "Name: {COMPANY}\nStatus: active"],
        "test": ["User: {U} | Plan: free | Region: eu", "first={F}&last={L}&source=web",
                 "Name - {P}\nDepartment - {WORD}", "Contact: {P}; Office: {CITY}", "login={U}&remember=1",
                 "Customer: {P}, Company: {COMPANY}", "Name - {PRODUCT}\nDepartment - {WORD}",
                 "Server: {HOST} | Region: eu"],
    },
    "url": {
        "train": ["/users/{U}/profile", "/api/v1/products/{SLUG}/details", "/static/{FILE}"],
        "val": ["/u/{U}", "/files/{FILE}/download"],
        "calib": ["/profile/{U}/posts", "/docs/{SLUG}"],
        "test": ["/api/v2/accounts/{U}/settings", "/@{U}", "/search?q={WORD}&page=2", "/download/{FILE}"],
    },
    "text_neg": {
        "train": ["Your order #{NUM} has shipped.", "The {PRODUCT} is now available in stores.",
                  "{COMPANY} announced quarterly results.", "Download {FILE} to continue.",
                  "Visit {CITY} this summer!", "Server {HOST} restarted at 03:00", "Hi there, how can we help?",
                  "Dear customer, your request is received.", "Thanks for choosing {COMPANY}!",
                  "Error in module {SLUG}: null pointer", "Hello team, standup moved to 10am."],
        "val": ["Hello everyone, the {PRODUCT} launch is Friday.", "Welcome to {CITY}!",
                "Open {FILE} and follow the steps.", "{COMPANY} is hiring engineers.",
                "Build {SLUG} passed all checks.", "Hi all, see attached {FILE}"],
        "calib": ["Hi folks, release {SLUG} is out.", "Flights to {CITY} are delayed.", "Review {PRODUCT} before buying."],
        "test": ["Greetings from {CITY}!", "Hey there, welcome to {COMPANY}.", "{PRODUCT} now supports dark mode.",
                 "Cannot open {FILE}: permission denied", "Hi everyone, {HOST} is down.",
                 "Thank you for contacting {COMPANY} support.", "Dear user, your session expired."],
    },
}
KIND_WEIGHTS = {"field_person": 0.10, "field_first": 0.04, "field_last": 0.04, "field_user": 0.12,
                "field_neg": 0.14, "text_person": 0.16, "text_user": 0.10, "text_mixed": 0.04, "kv": 0.10,
                "url": 0.04, "text_neg": 0.12}
KIND_LOCS = {"text_person": TEXT_LOCS, "text_user": TEXT_LOCS, "text_mixed": TEXT_LOCS, "text_neg": TEXT_LOCS,
             "kv": KV_LOCS, "url": URL_LOCS}

_PH = re.compile(r"\{(\w+)(?:\|(\w+))?\}")
_ENTITY = {"P": "PERSON_NAME", "P2": "PERSON_NAME", "PM": "PERSON_NAME", "F": "PERSON_NAME", "F2": "PERSON_NAME",
           "L": "PERSON_NAME", "U": "USERNAME"}


class _Ctx:
    def __init__(self, rng: random.Random, split: str):
        self.rng, self.split = rng, split
        pick = lambda cat: rng.choice(POOLS[cat][split])
        self.pick = pick
        self.ids = []
        for _ in range(2):
            self.ids.append((pick("first"), pick("last")))
        self.case = rng.choices(["as", "lower", "upper", "title"], [80, 8, 6, 6])[0]

    def handle(self, ident) -> str:
        r, (f, l) = self.rng, ident
        w = lambda: self.pick("handleword")
        dig = lambda: str(r.randint(1, 99)) if r.random() < .7 else str(r.randint(1970, 2012))
        pat = r.randint(0, 8)
        if pat == 0: h = (f[0] + l).lower()
        elif pat == 1: h = f"{f}.{l}".lower()
        elif pat == 2: h = f"{f.lower()}_{dig()}"
        elif pat == 3: h = w().capitalize() + w().capitalize() + dig()
        elif pat == 4: h = f"{w()}_{w()}"
        elif pat == 5: h = f"xX{w().capitalize()}Xx"
        elif pat == 6: h = f"{f.lower()}{l[:3].lower()}{dig()}"
        elif pat == 7: h = f"{w()}-{w()}{dig()}"
        else: h = f"{f.lower()}{dig()}"
        return h

    def neg(self, name: str) -> str:
        r, p = self.rng, self.pick
        if name == "CITY": return p("city")
        if name == "COMPANY": return p("company")
        if name == "PRODUCT": return p("product")
        if name == "WORD": return p("word")
        if name == "FILE": return p("stem") + "." + r.choice(FILE_EXT)
        if name == "SLUG": return f"{p('word')}_{r.choice(('v2', 'prod', 'beta', '2024', 'x'))}"
        if name == "NUM": return str(r.randint(1000, 999999))
        if name == "HOST": return f"{r.choice(('srv', 'db', 'web', 'node'))}-{p('word')[:4]}{r.randint(1, 99)}"
        if name == "ID": return "".join(r.choice("0123456789abcdef") for _ in range(r.choice((8, 12, 32))))
        if name == "UA": return f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/{r.randint(90, 130)}.0.{r.randint(1000, 6999)}.{r.randint(1, 199)}"
        raise KeyError(name)

    def casefn(self, s: str) -> str:
        return {"as": s, "lower": s.lower(), "upper": s.upper(), "title": s.title()}[self.case]


def render(tpl: str, ctx: _Ctx) -> tuple[str, list[tuple[int, int, str]], str]:
    out, spans, pos, last = [], [], 0, 0
    skel = []
    for m in _PH.finditer(tpl):
        lit = tpl[last:m.start()]
        out.append(lit); pos += len(lit); skel.append(lit.lower())
        name, mod = m.group(1), m.group(2)
        if name in _ENTITY:
            (f1, l1), (f2, l2) = ctx.ids
            ident = ctx.ids[1] if name.endswith("2") else ctx.ids[0]
            if name in ("P", "P2"): val = f"{ident[0]} {ident[1]}"
            elif name == "PM": val = f"{ident[0]} {ctx.rng.choice('ABCDEFGHJKLMNPRSTW')}. {ident[1]}"
            elif name in ("F", "F2"): val = ident[0]
            elif name == "L": val = ident[1]
            else: val = ctx.handle(ctx.ids[0])
            val = ctx.casefn(val)
            if name == "L" and "," in tpl: pass
            if mod == "plus": val = val.replace(" ", "+")
            spans.append((pos, pos + len(val), _ENTITY[name]))
            skel.append("<" + _ENTITY[name][0] + ">")
        else:
            val = ctx.casefn(ctx.neg(name))
            skel.append("<" + name.lower() + ">")
        out.append(val); pos += len(val); last = m.end()
    tail = tpl[last:]
    out.append(tail); skel.append(tail.lower())
    return "".join(out), spans, "".join(skel)


def _merge_comma_names(tpl: str, text: str, spans):
    """For '{L}, {F}' the gold entity is the whole 'Last, First' string (one person)."""
    if tpl == "{L}, {F}" and len(spans) == 2:
        return [(spans[0][0], spans[1][1], "PERSON_NAME")]
    return spans


def _digits0(s: str) -> str:
    return re.sub(r"\d", "0", s)


def _make_example(rng: random.Random, split: str, kind: str, fam_idx: int, n: int) -> Example:
    ctx = _Ctx(rng, split)
    if kind.startswith("field_"):
        sub = kind[6:]
        keys = KEYS[sub]["common"] + KEYS[sub][split]
        key = rng.choice(keys)
        loc = rng.choice(PREFIXES) + key
        if sub == "person":
            tpl = rng.choice(FIELD_VALUES["person"][split])
        elif sub == "first": tpl = "{F}"
        elif sub == "last": tpl = "{L}"
        elif sub == "user": tpl = "{U}"
        else:  # negatives: value type follows the key
            k = key.lower()
            if "file" in k: tpl = "{FILE}"
            elif "user_agent" in k: tpl = "{UA}"
            elif k.endswith("_id"): tpl = rng.choice(["{ID}", "{NUM}"])
            elif "company" in k or "organization" in k or "store" in k or "brand" in k or k in ("team", "team_name"):
                tpl = "{COMPANY}"
            elif "city" in k: tpl = "{CITY}"
            elif "host" in k or "service" in k or "device" in k: tpl = "{HOST}"
            elif "product" in k or "item" in k or "app" in k: tpl = "{PRODUCT}"
            elif k in ("module", "version", "theme", "category", "label", "channel_name", "project_name") or "project" in k:
                tpl = rng.choice(["{SLUG}", "{WORD}"])
            elif k == "description":
                tpl = rng.choice(T["text_neg"][split])
            else:  # name / title
                tpl = rng.choice(["{FILE}", "{PRODUCT}", "{COMPANY}", "{CITY}", "{WORD}"])
        fam = f"{kind}:{split}"
    else:
        tpls = T[kind][split]
        fam_idx = rng.randrange(len(tpls))
        tpl = tpls[fam_idx]
        loc = rng.choice(KIND_LOCS[kind])
        fam = f"{kind}:{split}:{fam_idx}"
    text, spans, skel = render(tpl, ctx)
    spans = _merge_comma_names(tpl, text, spans)
    for s, e, _ in spans:
        assert 0 <= s < e <= len(text)
    return Example(f"{split}-{n:05d}", split, fam, kind, tpl, skel, loc, text, tuple(spans))


def generate_split(split: str, n: int, seed: int) -> tuple[list[Example], int]:
    """Return (``n`` unique examples, number of exact duplicates removed)."""
    rng = random.Random(f"{seed}|{split}")
    kinds = list(KIND_WEIGHTS)
    weights = [KIND_WEIGHTS[k] for k in kinds]
    seen, out, dups = set(), [], 0
    attempts = 0
    while len(out) < n and attempts < n * 30:
        attempts += 1
        kind = rng.choices(kinds, weights)[0]
        ex = _make_example(rng, split, kind, 0, len(out))
        key = (ex.location, ex.text)
        if key in seen:
            dups += 1
            continue
        seen.add(key)
        out.append(ex)
    if len(out) < n:
        raise RuntimeError(f"could not generate {n} unique examples for split {split}")
    for ex in out:  # strict alignment check: every gold span must align to token boundaries
        spans_to_tags(tokenize(ex.text), ex.spans)
    return out, dups


def generate_dataset(seed: int = 1234, sizes: dict[str, int] | None = None) -> dict[str, list[Example]]:
    sizes = sizes or DEFAULT_SIZES
    return {s: generate_split(s, sizes[s], seed)[0] for s in SPLITS}


# ----------------------------------------------------------------- IO, manifest, leakage
def dumps_split(examples: Iterable[Example]) -> str:
    return "".join(json.dumps(e.to_json(), ensure_ascii=False, sort_keys=True) + "\n" for e in examples)


def write_dataset(ds: dict[str, list[Example]], out_dir) -> dict:
    import os
    os.makedirs(out_dir, exist_ok=True)
    manifest = {"splits": {}}
    for s, exs in ds.items():
        blob = dumps_split(exs)
        with open(os.path.join(out_dir, f"{s}.jsonl"), "w", encoding="utf-8") as f:
            f.write(blob)
        lab = Counter(l for e in exs for _, _, l in e.spans)
        manifest["splits"][s] = {
            "examples": len(exs), "entities": dict(lab), "no_entity_examples": sum(1 for e in exs if not e.spans),
            "by_kind": dict(Counter(e.kind for e in exs)), "sha256": hashlib.sha256(blob.encode("utf-8")).hexdigest()}
    return manifest


def read_split(path) -> list[Example]:
    with open(path, encoding="utf-8") as f:
        return [Example.from_json(json.loads(line)) for line in f if line.strip()]


def leakage_report(ds: dict[str, list[Example]]) -> dict:
    """Cross-split overlap statistics. All ``*_overlap`` counts for non-field kinds must be zero."""
    rep: dict = {"exact_duplicates": 0, "template_overlap": 0, "skeleton_overlap": 0,
                 "family_overlap": 0, "lexical_overlap": 0, "field_skeleton_overlap_expected": 0}
    pairs = [(a, b) for i, a in enumerate(SPLITS) for b in SPLITS[i + 1:]]
    nonfield = lambda e: not e.kind.startswith("field_")
    for a, b in pairs:
        A, B = ds[a], ds[b]
        rep["exact_duplicates"] += len({(e.location, e.text) for e in A} & {(e.location, e.text) for e in B})
        rep["template_overlap"] += len({e.template for e in A if nonfield(e)} & {e.template for e in B if nonfield(e)})
        rep["skeleton_overlap"] += len({_digits0(e.skeleton) for e in A if nonfield(e)} &
                                       {_digits0(e.skeleton) for e in B if nonfield(e)})
        rep["family_overlap"] += len({e.family for e in A} & {e.family for e in B})
        rep["field_skeleton_overlap_expected"] += len({(e.location, _digits0(e.skeleton)) for e in A if not nonfield(e)} &
                                                      {(e.location, _digits0(e.skeleton)) for e in B if not nonfield(e)})
    for cat in POOLS:
        for a, b in pairs:
            rep["lexical_overlap"] += len({w.lower() for w in POOLS[cat][a]} & {w.lower() for w in POOLS[cat][b]})
    return rep


def entity_value_overlap(ds: dict[str, list[Example]]) -> dict[str, int]:
    """Number of gold entity strings (lowercased) of each eval split that also occur as entities in train."""
    vals = lambda exs: {e.text[s:t].lower() for e in exs for s, t, _ in e.spans}
    tr = vals(ds["train"])
    return {s: len(vals(ds[s]) & tr) for s in SPLITS if s != "train"}
