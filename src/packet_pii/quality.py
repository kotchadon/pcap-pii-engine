"""Automated, local, per-capture *model quality assessment* by context-matched synthetic probes.

What this is: a privacy-safe structural summary of a scanned capture (field-location categories, allowlisted name classes,
nesting depth, shape/length buckets, HTTP method/encoding classes) drives a deterministic generator that builds fictional,
labelled probe fields. The real V2 detector is run on that frozen suite and scored by exact span.

What this is NOT: the accuracy of the scanned capture. That capture is unlabelled and a model cannot grade itself. The headline
number is therefore always named "Context-matched synthetic probe F1" and carries the disclosure in ``DISCLOSURE``.

Invariants
  * no raw capture value, field name, URL, IP or credential is stored: the summary holds enums and counters only, and probe
    field names are built from an allowlist of generic words;
  * gold labels and span boundaries are constructed before any detector runs, from fixed fictional pools, using a hash of
    (seed, stratum, case) - never from detector output, rules, confidence or ensemble agreement;
  * the suite is frozen (hash recorded, re-verified after inference) and never edited based on results;
  * inference is bounded (probes, characters, batch size, model time) and never rescans the capture.
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace

from .detect import detect_fields
from .groundtruth import EvaluationCollector, _wilson, prf
from .hybrid import _excluded
from .ml_runner import MLBatchRunner, MLWorkBudget

GENERATOR_VERSION = 'probe-gen/1'
TEMPLATE_VERSION = 'probe-templates/1'
RESULT_SCHEMA = 'trace-context-probe-assessment/1'
SUMMARY_SCHEMA = 'trace-context-summary/1'
DEFAULT_SEED = 20250602
METRIC_NAME = 'Context-matched synthetic probe F1'
DISCLOSURE = ("These metrics are measured on automatically generated, labelled synthetic probes matched to aspects of this "
              "capture's structure. They are not precision, recall or F1 measured on the original uploaded traffic.")
LIMITATIONS = (
    'The scanned capture itself is unlabelled; no accuracy of the original traffic is measured or estimated here.',
    'Probe values are fictional and template-generated; real traffic is both easier and harder in ways this does not capture.',
    'The V2 model sees only a field location and its text, so HTTP method, direction and encoding only change which contexts are sampled, not the model input.',
    'Probes within a context share templates and name pools, so they are strongly dependent; intervals use a cluster bootstrap over contexts and still understate uncertainty.',
    'Exact-span scoring: a boundary near-miss is one false positive and one false negative and gets no true-positive credit.',
    'Rule/model disagreement and stability are diagnostics, not accuracy; agreement between detectors is not proof of correctness.',
)

# ----------------------------------------------------------------------------------------------- budget
@dataclass(frozen=True)
class AssessmentBudget:
    """Independent, validated limits for the post-scan assessment (separate from the capture's ML budget)."""
    max_probes: int = 480
    max_characters: int = 60_000
    max_seconds: float = 20.0
    batch_fields: int = 128
    max_strata: int = 24
    stability_probes: int = 90
    max_output_bytes: int = 200_000
    bootstrap_rounds: int = 400

    def __post_init__(self):
        for key in ('max_probes', 'max_characters', 'batch_fields', 'max_strata', 'max_output_bytes', 'bootstrap_rounds'):
            if type(getattr(self, key)) is not int or getattr(self, key) <= 0:
                raise ValueError(f'{key} must be a positive integer')
        if type(self.stability_probes) is not int or self.stability_probes < 0:
            raise ValueError('stability_probes must be a non-negative integer')
        if type(self.max_seconds) not in (int, float) or not 0 < self.max_seconds <= 120:
            raise ValueError('max_seconds must be in (0, 120]')
        if self.max_probes > 5000 or self.max_characters > 1_000_000 or self.batch_fields > 1000 or self.max_strata > 200:
            raise ValueError('assessment budget exceeds its absolute ceiling')
        if self.stability_probes > 500 or self.bootstrap_rounds > 2000:
            raise ValueError('assessment budget exceeds its absolute ceiling')

    def public(self) -> dict:
        return dict(self.__dict__)


class AssessmentCancelled(Exception):
    """Raised from the checkpoint callback to stop the assessment between detector calls."""


# ----------------------------------------------------------------------------------------------- safe vocabulary
def _tokens(name: str) -> list:
    spaced = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', name)
    return [t.lower() for t in re.split(r'[^A-Za-z0-9]+', spaced) if t]


# class -> allowlisted generic words. Only these words can ever appear in a probe field name.
NAME_CLASSES = (
    ('username_like', ('username', 'user', 'login', 'handle', 'nick', 'nickname', 'alias', 'account', 'screen', 'gamertag')),
    ('person_like', ('name', 'fullname', 'firstname', 'lastname', 'surname', 'given', 'family', 'display', 'recipient', 'passenger',
                     'customer', 'contact', 'person', 'speaker', 'reviewer', 'client')),
    ('actor_like', ('author', 'owner', 'assignee', 'reporter', 'committer', 'approver', 'actor', 'creator', 'sender', 'cc', 'by',
                    'member', 'player', 'participant')),
    ('organisation_like', ('company', 'vendor', 'org', 'organisation', 'organization', 'employer', 'brand', 'team', 'carrier',
                           'sponsor', 'business')),
    ('place_like', ('city', 'country', 'street', 'address', 'suburb', 'region', 'place', 'venue', 'location', 'landmark',
                    'postcode', 'zip', 'state')),
    ('product_like', ('product', 'item', 'collection', 'model', 'catalog', 'sku', 'category')),
    ('time_like', ('date', 'time', 'timestamp', 'created', 'updated', 'expires', 'modified', 'at')),
    ('free_text', ('message', 'text', 'comment', 'description', 'note', 'notes', 'body', 'summary', 'subject', 'content', 'log',
                   'details', 'bio')),
    ('label_like', ('title', 'label', 'caption', 'heading', 'status', 'role', 'type', 'level', 'mode')),
    ('identifier_like', ('id', 'uuid', 'guid', 'ref', 'key', 'code', 'hash', 'number', 'serial', 'version', 'build', 'branch',
                         'artifact', 'file', 'path', 'url')),
)
OTHER_LEAF = 'value'
PREFIX_CHAIN = ('data', 'attributes')
CATEGORIES = ('json', 'form', 'query', 'text', 'header', 'other')
SHAPES = ('single_token', 'two_tokens', 'few_tokens', 'sentence_like')
LENGTH_BUCKETS = (8, 16, 32, 64, 128)


def classify_location(location: str) -> tuple:
    """(category, name_class, safe_leaf, depth_bucket); nothing from ``location`` is returned except allowlisted words."""
    if location.startswith('header.'):
        category, path = 'header', location[7:]
    elif location.startswith('query_parameter.'):
        category, path = 'query', location[16:]
    elif location.startswith('form.'):
        category, path = 'form', location[5:]
    elif location == 'body.text':
        return 'text', 'free_text', 'text', 1
    elif location.startswith('json_body'):
        category, path = 'json', location[9:].lstrip('.')
    else:
        category, path = 'other', location
    segments = [s for s in re.split(r'\.', path) if s] or ['']
    leaf = re.sub(r'\[\d*\]', '', segments[-1])
    depth = min(len(segments), 3) if category == 'json' else 1
    tokens = _tokens(leaf)
    for a, b in zip(tokens, tokens[1:]):                      # compound usernames such as user_name / screen_name
        if b == 'name' and a in ('user', 'screen', 'login', 'account'):
            return category, 'username_like', a, depth
    for token in reversed(tokens):
        for cls, words in NAME_CLASSES:
            if token in words:
                return category, cls, token, depth
    return category, 'other', OTHER_LEAF, depth


def classify_http(info: dict | None, direction: str) -> tuple:
    info = info or {}
    if direction == 'response':
        method = 'none'
    else:
        verb = str(info.get('method') or '').upper()
        method = {'GET': 'GET', 'POST': 'POST', 'PUT': 'PUT_PATCH', 'PATCH': 'PUT_PATCH', 'DELETE': 'DELETE'}.get(verb, 'OTHER')
    ctype = str(info.get('content_type') or '').lower()
    kind = ('json' if 'json' in ctype else 'form' if 'x-www-form-urlencoded' in ctype else 'multipart' if 'multipart' in ctype
            else 'text' if ctype.startswith('text/') else 'other' if ctype else 'none')
    extras = ''
    if str(info.get('content_encoding') or '').lower() in ('gzip', 'deflate'):
        extras += '+compressed'
    if 'chunked' in str(info.get('transfer_encoding') or '').lower():
        extras += '+chunked'
    return method, kind + extras


def _shape(text: str) -> str:
    words = len(text.split())
    return SHAPES[0] if words <= 1 else SHAPES[1] if words == 2 else SHAPES[2] if words <= 5 else SHAPES[3]


def _length_bucket(n: int) -> str:
    for edge in LENGTH_BUCKETS:
        if n <= edge:
            return f'<={edge}'
    return f'>{LENGTH_BUCKETS[-1]}'


# ----------------------------------------------------------------------------------------------- sampling
class ContextSampler:
    """Bounded structural tally fed by the engine's field observer. Order-independent and independent of any prediction."""

    def __init__(self):
        self.strata: dict = {}
        self.messages = self.fields_total = self.fields_eligible = self.fields_excluded = self.fields_empty = 0

    def observe_message(self, info: dict) -> None:
        self.messages += 1
        direction = info.get('message_type', 'request')
        method, encoding = classify_http(info.get('http'), direction)
        for location, text in info['fields']:
            self.fields_total += 1
            if not text:
                self.fields_empty += 1
                continue
            if _excluded(location):
                self.fields_excluded += 1
                continue
            category, name_class, leaf, depth = classify_location(location)
            self.fields_eligible += 1
            entry = self.strata.setdefault((category, name_class, depth, direction, method, encoding), {
                'count': 0, 'leaf': Counter(), 'shape': Counter(), 'length': Counter(), 'non_ascii': 0, 'digit': 0, 'separator': 0})
            entry['count'] += 1
            entry['leaf'][leaf] += 1
            entry['shape'][_shape(text)] += 1
            entry['length'][_length_bucket(len(text))] += 1
            entry['non_ascii'] += not text.isascii()
            entry['digit'] += any(c.isdigit() for c in text)
            entry['separator'] += any(c in '_.-@' for c in text)

    def summary(self) -> dict:
        rows = []
        for key in sorted(self.strata):
            e = self.strata[key]
            rows.append({'category': key[0], 'name_class': key[1], 'depth': key[2], 'direction': key[3], 'method': key[4],
                         'encoding': key[5], 'count': e['count'], 'leaf': dict(sorted(e['leaf'].items())),
                         'shape': dict(sorted(e['shape'].items())), 'length': dict(sorted(e['length'].items())),
                         'non_ascii': e['non_ascii'], 'digit': e['digit'], 'separator': e['separator']})
        doc = {'schema_version': SUMMARY_SCHEMA, 'messages': self.messages, 'fields_total': self.fields_total,
               'fields_eligible': self.fields_eligible, 'fields_excluded_by_policy': self.fields_excluded,
               'fields_empty': self.fields_empty, 'strata': rows}
        doc['summary_hash'] = _hash(doc)
        return doc


def _hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest()


def select_strata(summary: dict, max_strata: int) -> list:
    """Defined rule: round-robin over location categories (alphabetical); within a category by descending count, then key."""
    by_category = defaultdict(list)
    for row in summary['strata']:
        by_category[row['category']].append(row)
    order = {c: sorted(rows, key=lambda r: (-r['count'], r['name_class'], r['depth'], r['direction'], r['method'], r['encoding']))
             for c, rows in by_category.items()}
    chosen, level = [], 0
    while len(chosen) < max_strata and any(len(rows) > level for rows in order.values()):
        for category in sorted(order):
            if len(order[category]) > level and len(chosen) < max_strata:
                chosen.append(order[category][level])
        level += 1
    return chosen


# ----------------------------------------------------------------------------------------------- fictional pools
FIRST = ('Amarachi', 'Bartholomew', 'Calliope', 'Desmond', 'Elowen', 'Fenwick', 'Giselle', 'Hadrian', 'Idony', 'Jorund', 'Kalani',
         'Lucian', 'Mireille', 'Nevan', 'Oriel', 'Perpetua', 'Quillon', 'Rosamund', 'Siegbert', 'Tabitha', 'Uriel', 'Vesna',
         'Wilhelmina', 'Yarrow', 'Anselm', 'Brigid', 'Cormac', 'Dalia', 'Evander', 'Fiora', 'Gunnar', 'Hestia')
LAST = ('Aldershot', 'Brannigan', 'Dunmore', 'Eriksdottir', 'Fairweather', 'Grunwald', 'Halvorsen', 'Ibekwe', 'Jarrowby',
        'Kovalenko', 'Mwangi', 'Northcott', 'Oyelowo', 'Pemberton', 'Quillfeather', 'Rasmussen', 'Strathmore', 'Thackeray',
        'Umarov', 'Valdivia', 'Whitcombe', 'Yamazaki', 'Ashgrove', 'Bellweather', 'Corrigan', 'Dellacroix', 'Eastwick', 'Fenholt')
HYPHEN_LAST = ('Castellanos-Wright', 'Lindgren-Shaw', 'Okafor-Brennan', 'Thorsen-Vale', 'Marchetti-Owusu', 'Hartwell-Nakamura',
               'Delacroix-Mbeki', 'Ferreira-Lundqvist', 'Abernathy-Osei', 'Kristiansen-Roy', 'Valverde-Hale', 'Wexford-Adeyemi')
UNICODE_NAMES = ('Søren Ødegård', 'Ayşe Yıldırım', 'Zofia Wiśniewska', 'Joaquín Peñaloza', 'Nguyễn Thị Hạnh', 'Θεοδώρα Μαυρίδου',
                 'Анфиса Громова', 'Łukasz Czarnecki', 'Siobhán Ní Bhriain', 'Renée Beauchêne', 'Gülşen Aydoğan', 'Ingólfur Þórsson')
WORDS_A = ('copper', 'tundra', 'velvet', 'ember', 'saffron', 'glacier', 'willow', 'cobalt', 'maple', 'harbor', 'pebble', 'lantern',
           'juniper', 'obsidian', 'sparrow', 'thistle')
WORDS_B = ('heron', 'quill', 'fjord', 'marten', 'ridge', 'plover', 'badger', 'finch', 'otter', 'wren', 'basalt', 'meadow')
COMPANIES = ('Harborview Logistics Pty Ltd', 'Beckett & Marlowe Associates', 'Sunrise Foods Ltd', 'Kensington Oak Furniture',
             'Pacific Dawn Airways', 'Northgate Cooperative Bank', 'Blue Heron Support', 'Corrigan & Daughters Ltd')
CITIES = ('Madison', 'Austin Heights', 'Victoria Park', 'Charlotte Street', 'Washington Reserve', 'Lincoln Bay', 'Jordan Valley',
          'Fremantle')
PRODUCTS = ('Aurora Desk Lamp', 'Kensington Oak Table', 'Madison Collection Chair', 'Harper Notebook Pro', 'AirLoom Mini',
            'Stratus Travel Mug', 'Marlowe Pen Set', 'Beacon Wall Clock')
IDENTIFIERS = ('build_20250602_final', 'SKU_BLUE_42', 'feature_login_fix', 'report_final_v2.pdf', 'req_8f3a21c9',
               'nightly_build_main', 'ORD-77310', 'release-2025.06.2')
LOG_LINES = ('Invalid token supplied', 'Connection reset by peer', 'Retrying request after timeout', 'Cache miss for key',
             'Order shipped to warehouse', 'Payment gateway returned 502', 'Scheduled job finished in 41 ms', 'Upload complete')
UI_LABELS = ('Username', 'Full name', 'Password', 'Email address', 'Sign in', 'Display name', 'Account settings', 'Remember me')
DATETIMES = ('2025-06-02T10:15:00Z', 'Monday 2 June', 'April', '10:21 AM', '2024-11-03', 'June 2025', 'Tuesday', '02/06/2025')
LOOKALIKES = ('Johnson & Johnson', 'Morgan Stanley Fund', 'Harper Collins Books', 'Madison Avenue', 'Austin Powers Collection',
              'Mother Teresa Hospital', 'Victoria Falls', 'Jordan River')
SENTENCES = ('Please contact {} today', 'Reviewed by {} last week', 'Message from {} about the invoice',
             'Assigned to {} for follow-up', 'Thanks {}! Will do.', 'Spoke with {} yesterday')
MENTIONS = ('hey @{} can you review this?', 'cc @{} for visibility', 'thanks @{}!', 'login ok for {} from device Pixel',
            '[2025-06-02 10:21] session opened by {}')
SINGLE_CLASSES = ('person_like', 'actor_like', 'free_text', 'other')


def _pick(pool, seed, *parts) -> str:
    digest = hashlib.sha256('|'.join([str(seed), *map(str, parts)]).encode('utf-8')).digest()
    return pool[int.from_bytes(digest[:4], 'big') % len(pool)]


def _name(seed, tag):
    return f'{_pick(FIRST, seed, tag, "f")} {_pick(LAST, seed, tag, "l")}'


def _user(seed, tag, separators=False):
    a, b, n = _pick(WORDS_A, seed, tag, 'a'), _pick(WORDS_B, seed, tag, 'b'), int(_pick(tuple(range(10, 100)), seed, tag, 'n'))
    return f'{a}.{b}-{n}' if separators else f'{a}_{b}{n}'


# ----------------------------------------------------------------------------------------------- suite
@dataclass(frozen=True)
class ProbeItem:
    probe_id: str
    location: str
    text: str
    spans: tuple          # ((start, end, label), ...)  constructed by the generator; empty = negative
    case_id: str
    tags: tuple

    @property
    def kind(self) -> str:
        return 'positive' if self.spans else 'negative'


@dataclass(frozen=True)
class ProbeSuite:
    items: tuple
    meta: dict

    @property
    def hash(self) -> str:
        return self.meta['probe_set_hash']


def _probe_location(category, depth, leaf):
    if category == 'json':
        chain = ('.'.join(PREFIX_CHAIN[:max(0, depth - 1)]) + '.') if depth > 1 else ''
        return f'json_body.{chain}{leaf}'
    if category == 'query':
        return f'query_parameter.{leaf}'
    if category == 'form':
        return f'form.{leaf}'
    return 'body.text' if category == 'text' else f'json_body.{leaf}'


def _cases(seed, stratum_key, name_class):
    """(case_id, text, spans, tags) for one context, built from fixed pools only."""
    out = []

    def positive(case_id, text, value, label, *tags):
        at = text.index(value)
        out.append((case_id, text, ((at, at + len(value), label),), tags))
    full = _name(seed, (stratum_key, 'full'))
    positive('name_full', full, full, 'PERSON_NAME', 'bare', 'full_name')
    hy = f'{_pick(FIRST, seed, stratum_key, "hf")} {_pick(HYPHEN_LAST, seed, stratum_key, "hl")}'
    positive('name_hyphenated', hy, hy, 'PERSON_NAME', 'bare', 'hyphenated')
    uni = _pick(UNICODE_NAMES, seed, stratum_key, 'u')
    positive('name_unicode', uni, uni, 'PERSON_NAME', 'bare', 'unicode')
    if name_class in SINGLE_CLASSES:
        single = _pick(FIRST, seed, stratum_key, 's')
        positive('name_single_token', single, single, 'PERSON_NAME', 'bare', 'single_token')
    emb = _name(seed, (stratum_key, 'emb'))
    positive('name_sentence', _pick(SENTENCES, seed, stratum_key, 'ns').format(emb), emb, 'PERSON_NAME', 'embedded', 'sentence')
    u1 = _user(seed, (stratum_key, 'u1'))
    positive('user_plain', u1, u1, 'USERNAME', 'bare', 'alnum_underscore')
    u2 = _user(seed, (stratum_key, 'u2'), separators=True)
    positive('user_separators', u2, u2, 'USERNAME', 'bare', 'period_hyphen')
    u3 = _user(seed, (stratum_key, 'u3'))
    positive('user_mention', _pick(MENTIONS, seed, stratum_key, 'um').format(u3), u3, 'USERNAME', 'embedded', 'mention')
    for case_id, pool, tag in (('neg_company', COMPANIES, 'organisation'), ('neg_city', CITIES, 'place'), ('neg_product', PRODUCTS, 'product'),
                               ('neg_identifier', IDENTIFIERS, 'identifier'), ('neg_log', LOG_LINES, 'log'),
                               ('neg_ui_label', UI_LABELS, 'ui_label'), ('neg_datetime', DATETIMES, 'datetime'),
                               ('neg_lookalike', LOOKALIKES, 'name_lookalike')):
        out.append((case_id, _pick(pool, seed, stratum_key, case_id), (), (tag,)))
    return out


def generate_suite(summary: dict, budget: AssessmentBudget, seed: int = DEFAULT_SEED) -> ProbeSuite:
    """Build and freeze the probe suite. Uses only the structural summary, the seed and fixed pools."""
    if summary.get('schema_version') != SUMMARY_SCHEMA:
        raise ValueError('unsupported context summary')
    chosen = select_strata(summary, budget.max_strata)
    seen, items, characters, truncated = {}, [], 0, False
    for row in chosen:
        leaf_counts = row['leaf']
        leaf = sorted(leaf_counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if leaf_counts else OTHER_LEAF
        location = _probe_location(row['category'], row['depth'], leaf)
        stratum_key = f"{row['category']}/{row['name_class']}/{row['depth']}"
        for case_id, text, spans, tags in _cases(seed, stratum_key, row['name_class']):
            key = (location, case_id, text)
            if key in seen:
                continue                      # identical probe already generated for another stratum (model input is location + text)
            if len(items) >= budget.max_probes or characters + len(text) > budget.max_characters:
                truncated = True
                continue
            seen[key] = True
            items.append(ProbeItem(f'p{len(items):04d}', location, text, spans, case_id, tags))
            characters += len(text)
    core = [[i.probe_id, i.location, i.text, [list(s) for s in i.spans], i.case_id, list(i.tags)] for i in items]
    meta = {'generator_version': GENERATOR_VERSION, 'template_version': TEMPLATE_VERSION, 'seed': seed,
            'summary_hash': summary['summary_hash'], 'strata_selected': len(chosen), 'strata_available': len(summary['strata']),
            'probes': len(items), 'positive_probes': sum(1 for i in items if i.spans),
            'negative_probes': sum(1 for i in items if not i.spans), 'characters': characters, 'truncated_by_budget': truncated,
            'probe_set_hash': _hash(core)}
    return ProbeSuite(tuple(items), meta)


def stability_variants(items, limit: int):
    """Meaning-preserving text variants of a deterministic subset of positive probes: (variant, base item, text, spans)."""
    chosen, seen_cases = [], set()
    for item in items:                                    # first positive of each case, then fill in suite order
        if item.spans and item.case_id not in seen_cases:
            seen_cases.add(item.case_id)
            chosen.append(item)
    chosen += [i for i in items if i.spans and i not in chosen]
    out = []
    for item in chosen[:limit]:
        for name, prefix, suffix in (('trailing_period', '', '.'), ('label_prefix', 'Note: ', ''), ('quoted', '"', '"')):
            spans = tuple((a + len(prefix), b + len(prefix), l) for a, b, l in item.spans)
            out.append((name, item, prefix + item.text + suffix, spans))
    return out


# ----------------------------------------------------------------------------------------------- scoring
def _predict(detector, entries, budget, *, checkpoint=None, max_seconds=None):
    """Run (location, text) entries through the real detector via the shared bounded runner. Returns (spans, status)."""
    status = {}
    runner = MLBatchRunner(
        detector,
        MLWorkBudget(max_fields=max(1, len(entries)), max_characters=max(1, sum(len(t) for _, t in entries) + 1),
                     max_seconds=max_seconds or budget.max_seconds, batch_fields=budget.batch_fields,
                     batch_characters=max(65_536, budget.batch_fields * 512), name='assessment'),
        checkpoint=checkpoint, disposition=lambda ticket, index, s: status.__setitem__(ticket, s))
    for n, (location, text) in enumerate(entries):
        runner.add(n, [(location, text)])
    runner.flush()
    spans = {key: {(f['span_start'], f['span_end'], f['pii_type']) for f in found} for key, found in runner.take_ready()}
    return spans, status, runner


def _rule_spans(location, text) -> set:
    out = set()
    for d in detect_fields([(location, text)], 0.0, True):
        if d.pii_type in ('USERNAME', 'PERSON_NAME_CANDIDATE'):
            out.add((0, len(text), 'USERNAME' if d.pii_type == 'USERNAME' else 'PERSON_NAME'))
    return out


def _bootstrap(clusters: dict, rounds: int, seed: int):
    """Cluster bootstrap over probe contexts: [lo, hi] for precision, recall, F1 (None if too few clusters)."""
    keys = sorted(clusters)
    if len(keys) < 8:
        return None
    rng, draws = random.Random(seed), {'precision': [], 'recall': [], 'f1': []}
    for _ in range(rounds):
        tp = fp = fn = 0
        for key in (keys[rng.randrange(len(keys))] for _ in keys):
            c = clusters[key]
            tp, fp, fn = tp + c[0], fp + c[1], fn + c[2]
        m = prf(tp, fp, fn)
        for name in draws:
            if m[name] is not None:
                draws[name].append(m[name])
    def interval(values):
        if len(values) < rounds * 0.9:
            return None
        values.sort()
        return [round(values[int(0.025 * len(values))], 4), round(values[min(len(values) - 1, int(0.975 * len(values)))], 4)]
    return {name: interval(v) for name, v in draws.items()}


def assess_summary(detector, summary: dict, budget: AssessmentBudget | None = None, *, seed: int = DEFAULT_SEED,
                   checkpoint=None) -> dict:
    """Generate, freeze, run and score a probe suite for a context summary. Never touches the capture."""
    budget = budget or AssessmentBudget()
    started = time.monotonic()
    base = {'schema_version': RESULT_SCHEMA, 'metric_name': METRIC_NAME, 'disclosure': DISCLOSURE, 'limitations': list(LIMITATIONS),
            'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'model_version': getattr(detector, 'model_version', None), 'budget': budget.public()}
    if not summary.get('strata'):
        return {**base, 'status': 'unavailable', 'reason': 'The scan exposed no model-eligible field contexts to build probes from.'}
    suite = generate_suite(summary, budget, seed)
    frozen = suite.hash
    if not suite.items:
        return {**base, 'status': 'unavailable', 'reason': 'No probes could be generated within the budget.', 'suite': suite.meta}
    by_id = {i.probe_id: i for i in suite.items}
    entries = [(i.location, i.text) for i in suite.items]
    predicted, statuses, runner = _predict(detector, entries, budget, checkpoint=checkpoint)
    if _hash([[i.probe_id, i.location, i.text, [list(s) for s in i.spans], i.case_id, list(i.tags)] for i in suite.items]) != frozen:
        raise RuntimeError('probe suite changed during evaluation')          # frozen-suite guard
    counts = {'PERSON_NAME': Counter(), 'USERNAME': Counter()}
    clusters, tag_stats, fp_types, fn_types, unscored = defaultdict(lambda: [0, 0, 0]), defaultdict(Counter), Counter(), Counter(), Counter()
    negatives, scored_pos, scored_neg, disagreement = Counter(), 0, 0, Counter()
    base_predictions = {}
    for index, item in enumerate(suite.items):
        status = statuses.get(index, 'not_observed')
        if status != 'evaluated':
            unscored[status] += 1
            continue
        spans, gold = predicted.get(index, set()), set(item.spans)
        base_predictions[item.probe_id] = spans
        field = SimpleNamespace(spans=item.spans)
        cluster = clusters[item.location]
        for s in spans & gold:
            counts[s[2]]['tp'] += 1; cluster[0] += 1
            for t in item.tags:
                tag_stats[t]['exact'] += 1
        for s in spans - gold:
            counts[s[2]]['fp'] += 1; cluster[1] += 1
            kind = EvaluationCollector._classify_fp(s, field)
            fp_types[kind] += 1
            tag_stats[item.tags[0] if not item.spans else item.tags[-1]]['extra_prediction'] += 1
        for s in gold - spans:
            counts[s[2]]['fn'] += 1; cluster[2] += 1
            kind = EvaluationCollector._classify_fn(s, {p: 1 for p in spans}, 'evaluated', 'model_only')
            fn_types[kind] += 1
            for t in item.tags:
                tag_stats[t]['near_miss' if kind == 'boundary_mismatch' else 'missed'] += 1
        if item.spans:
            scored_pos += 1
            for t in item.tags:
                tag_stats[t]['probes'] += 1
        else:
            scored_neg += 1
            negatives['with_false_positive'] += bool(spans)
        rules = {(a, b, l) for a, b, l in _rule_spans(item.location, item.text)}
        category = ('both_agree' if spans and spans == rules else 'v2_only' if spans and not rules else
                    'rules_only' if rules and not spans else 'conflicting' if spans and rules else 'neither')
        disagreement[f'{item.kind}:{category}'] += 1
    total = Counter()
    for c in counts.values():
        total.update(c)
    micro = prf(total['tp'], total['fp'], total['fn'])
    scored = scored_pos + scored_neg
    unscored_total = sum(unscored.values())
    status = 'complete' if scored == len(suite.items) and not suite.meta['truncated_by_budget'] else 'partial'
    if scored == 0:
        return {**base, 'status': 'failed', 'reason': 'No probe could be evaluated by the model.', 'suite': suite.meta,
                'unscored_probes': dict(unscored)}
    ci = _bootstrap(clusters, budget.bootstrap_rounds, seed)
    # stability under meaning-preserving variants (bounded, separate counters)
    stability = None
    stability_runner = None
    stability_characters = 0
    if budget.stability_probes:
        variants = [v for v in stability_variants(suite.items, budget.stability_probes) if v[1].probe_id in base_predictions]
        if variants and runner.seconds < budget.max_seconds:
            stability_characters = sum(len(text) for _, _, text, _ in variants)
            remaining_model_seconds = budget.max_seconds - runner.seconds
            v_pred, v_status, stability_runner = _predict(
                detector, [(b.location, text) for _, b, text, _ in variants], budget,
                checkpoint=checkpoint, max_seconds=remaining_model_seconds)
            groups = defaultdict(Counter)
            for n, (name, b, text, spans) in enumerate(variants):
                if v_status.get(n) != 'evaluated':
                    groups[name]['unscored'] += 1
                    continue
                shift = spans[0][0] - b.spans[0][0]
                shifted = {(x - shift, y - shift, l) for x, y, l in v_pred.get(n, set())}
                groups[name]['probes'] += 1
                groups[name]['identical_to_base'] += shifted == base_predictions[b.probe_id]
                groups[name]['exact_on_variant'] += v_pred.get(n, set()) == set(spans)
                groups[name]['exact_on_base'] += base_predictions[b.probe_id] == set(b.spans)
            stability = {name: {**dict(c), 'identical_rate': round(c['identical_to_base'] / c['probes'], 4) if c['probes'] else None}
                         for name, c in sorted(groups.items())}
        elif variants:
            stability = {'status': 'unavailable', 'reason': 'model_time_budget_exhausted'}
    # capture-context applicability
    selected_mass = sum(r['count'] for r in select_strata(summary, budget.max_strata))
    eligible = summary['fields_eligible']
    coverage = round(selected_mass / eligible, 4) if eligible else None
    excluded_share = round(summary['fields_excluded_by_policy'] / summary['fields_total'], 4) if summary['fields_total'] else None
    limited = [reason for ok, reason in (
        (coverage is not None and coverage >= 0.6, 'sampled contexts cover less than 60% of eligible fields'),
        (suite.meta['strata_selected'] >= 3, 'fewer than 3 distinct contexts were sampled'),
        (excluded_share is None or excluded_share <= 0.5, 'more than half of all fields are excluded by model input policy'),
        (scored == len(suite.items), 'some probes were not evaluated')) if not ok]
    result = {
        **base, 'status': status,
        'headline': {'name': METRIC_NAME, 'value': micro['f1'], 'precision': micro['precision'], 'recall': micro['recall'],
                     'ci95_cluster_bootstrap': ci},
        'suite': suite.meta, 'summary_hash': summary['summary_hash'],
        'probes': {'generated': len(suite.items), 'evaluated': scored, 'unscored': unscored_total,
                   'unscored_reasons': dict(unscored), 'positive_evaluated': scored_pos, 'negative_evaluated': scored_neg,
                   'excluded_by_policy': unscored.get('excluded_by_policy', 0),
                   'skipped': sum(v for k, v in unscored.items() if k.startswith('skipped:'))},
        'micro': micro, 'per_label': {l: {**prf(c['tp'], c['fp'], c['fn']), 'support': c['tp'] + c['fn']} for l, c in counts.items()},
        'boundary': {'near_miss_false_negatives': fn_types.get('boundary_mismatch', 0),
                     'near_miss_false_positives': fp_types.get('boundary_mismatch', 0),
                     'by_tag': {t: {k: int(v) for k, v in c.items()} for t, c in sorted(tag_stats.items()) if c.get('probes')},
                     'note': 'Near-misses are shown separately and receive no true-positive credit.'},
        'negatives': {'evaluated': scored_neg, 'with_false_positive': negatives['with_false_positive'],
                      'false_positive_rate': round(negatives['with_false_positive'] / scored_neg, 4) if scored_neg else None,
                      'false_positive_rate_ci95': _wilson(negatives['with_false_positive'], scored_neg)},
        'errors': {'false_positive': dict(sorted(fp_types.items())), 'false_negative': dict(sorted(fn_types.items()))},
        'stability': stability if stability is not None else {'status': 'unavailable'},
        'independent_detector': {'available': True, 'detector': 'deterministic rules (detect.py): key/pattern based, mechanistically '
                                 'distinct from the BiLSTM', 'counts': dict(sorted(disagreement.items())),
                                 'note': 'Counts of agreement and disagreement on probes only; neither detector is treated as ground truth.'},
        'applicability': {'status': 'ok' if not limited else 'limited', 'reasons': limited, 'coverage_of_eligible_fields': coverage,
                          'strata_selected': suite.meta['strata_selected'], 'strata_available': suite.meta['strata_available'],
                          'eligible_fields': eligible, 'excluded_by_policy_share': excluded_share},
        'workload': {'elapsed_seconds': round(time.monotonic() - started, 3),
                     'model_seconds': round(runner.seconds + (stability_runner.seconds if stability_runner else 0), 3),
                     'batches': runner.batches + (stability_runner.batches if stability_runner else 0),
                     'probe_characters': suite.meta['characters'],
                     'stability_model_seconds': round(stability_runner.seconds, 3) if stability_runner else 0.0,
                     'stability_batches': stability_runner.batches if stability_runner else 0,
                     'stability_probe_characters': stability_characters},
    }
    result['reproducibility'] = {'model_version': base['model_version'], 'generator_version': GENERATOR_VERSION,
                                 'template_version': TEMPLATE_VERSION, 'seed': seed, 'probe_set_hash': frozen,
                                 'context_summary_hash': summary['summary_hash']}
    if len(json.dumps(result)) > budget.max_output_bytes:
        raise ValueError('assessment output exceeds its size budget')
    return result


def unavailable(reason: str, model_version=None) -> dict:
    return {'schema_version': RESULT_SCHEMA, 'metric_name': METRIC_NAME, 'status': 'unavailable', 'reason': reason,
            'disclosure': DISCLOSURE, 'model_version': model_version}
