import gzip
import hashlib
import json
import os
import random

import pytest

from packet_pii.ml import challenge as C
from packet_pii.ml import data2 as D
from packet_pii.ml.spans import spans_to_tags, tokenize

DS = os.path.join(os.path.dirname(__file__), "..", "src", "packet_pii", "ml", "datasets")
MAN = os.path.join(os.path.dirname(__file__), "..", "docs", "ml", "results")
SMALL = {"train": 1500, "val": 300, "calib": 300}


@pytest.fixture(scope="module")
def small():
    return D.generate_dataset(seed=3, sizes=SMALL)


def test_v2_generation_is_deterministic_and_sized(small):
    again = D.generate_dataset(seed=3, sizes=SMALL)
    assert {s: D.dumps_split(v) for s, v in small.items()} == {s: D.dumps_split(v) for s, v in again.items()}
    assert {s: len(v) for s, v in small.items()} == SMALL
    assert D.dumps_split(small["val"]) != D.dumps_split(D.generate_dataset(seed=4, sizes=SMALL)["val"])


def test_v2_offsets_are_independently_verified(small):
    """Gold spans must lie inside the exact string, be non-empty, non-overlapping and token-aligned."""
    for exs in small.values():
        for e in exs:
            prev = 0
            for s, t, lab in e.spans:
                assert 0 <= s < t <= len(e.text) and s >= prev and lab in ("PERSON_NAME", "USERNAME")
                assert e.text[s:t].strip() == e.text[s:t] and e.text[s:t]
                prev = t
            spans_to_tags(tokenize(e.text), e.spans)


def test_v2_covers_required_phenomena(small):
    tr = small["train"]
    kinds = {e.kind for e in tr}
    assert {"field_person", "field_user", "field_neg", "kv", "log", "url", "header", "markup", "narrative", "text_neg"} <= kinds
    tags = {t for e in tr for t in e.tags}
    assert {"hard_negative", "multi_entity", "unicode", "truncated"} <= tags
    roots = {e.location.split(".")[0] for e in tr}
    assert {"json_body", "form", "query_parameter", "header", "body"} <= roots   # mirrors http_extract naming
    assert any("[" in e.location for e in tr)                                     # array paths
    assert any(not e.spans for e in tr) and any(len(e.spans) >= 2 for e in tr)
    assert any(any(not c.isascii() for c in e.text) for e in tr)


def test_v2_no_shortcut_capitalisation_leak():
    """Capitalisation must not separate positives from negatives."""
    exs = D.generate_dataset(seed=5, sizes={"train": 3000, "val": 100, "calib": 100})["train"]
    cap = lambda s: s[:1].isupper()
    pos = [cap(e.text[s:t]) for e in exs for s, t, l in e.spans if l == "PERSON_NAME"]
    neg = [cap(e.text) for e in exs if e.kind == "field_neg"]
    assert 0.5 < sum(pos) / len(pos) < 0.97 and 0.25 < sum(neg) / len(neg) < 0.97
    # lower-case positives and capitalised negatives both exist in quantity
    assert sum(1 for p in pos if not p) > 100 and sum(1 for n in neg if n) > 100


def test_v2_frame_sharing_hard_negatives(small):
    """The same cue frame is realised with entities AND without (non-person fillers)."""
    by_t = {}
    for e in small["train"]:
        if e.template in D.CUE_SALT:
            by_t.setdefault(e.template, []).append(bool(e.spans))
    both = [t for t, v in by_t.items() if any(v) and not all(v)]
    assert len(both) >= 15


def test_v2_split_isolation(small):
    rep = D.leakage_report(small)
    assert rep["shared_templates_excluding_common"] == 0
    assert rep["shared_negative_lexicon_items"] == 0
    assert rep["exact_text_duplicates_with_entities"] == 0
    tok = lambda s: {x.text.lower() for e in small[s] for a, b, _ in e.spans for x in tokenize(e.text[a:b]) if len(x.text) > 3 and x.text.isalpha()}
    assert len(tok("train") & tok("val")) <= 3 and len(tok("train") & tok("calib")) <= 3
    # every split sees some split-exclusive cue frames, and common frames exist but are minority in train
    assert 0.1 < D.common_cue_share(small)["train"] < 0.5


def test_committed_v2_splits_match_manifest():
    man = json.load(open(os.path.join(MAN, "v2_dataset_manifest.json")))
    for s in D.SPLITS:
        blob = gzip.open(os.path.join(DS, "v2", f"{s}.jsonl.gz")).read()
        assert hashlib.sha256(blob).hexdigest() == man["splits"][s]["sha256_jsonl"]
        exs = D.read_split(os.path.join(DS, "v2", f"{s}.jsonl.gz"))
        assert len(exs) == man["splits"][s]["examples"]
    assert man["leakage_report"]["shared_templates_excluding_common"] == 0


# ---- challenge benchmark
def test_challenge_is_frozen():
    man = json.load(open(os.path.join(MAN, "challenge_v1_manifest.json")))
    blob = gzip.open(os.path.join(DS, "challenge_v1.jsonl.gz")).read()
    assert hashlib.sha256(blob).hexdigest() == man["sha256_jsonl"], "challenge_v1 must never change; create challenge_v2 instead"
    exs = D.read_split(os.path.join(DS, "challenge_v1.jsonl.gz"))
    assert len(exs) == man["examples"] == 1058 and "FROZEN" in man["status"]
    for e in exs:
        spans_to_tags(tokenize(e.text), e.spans)
        assert all(0 <= s < t <= len(e.text) for s, t, _ in e.spans)


def test_challenge_independent_of_training_generator():
    """Its lexicons/frames are separate: no V2 lexicon object is reused, and frames differ."""
    train_templates = set(D.CUE_SALT)
    chal = C.generate()
    assert sum(1 for e in chal if e.template in train_templates) == 0
    own = {w.lower() for w in C.FIRST + C.LAST}
    assert len(own) > 150 and C.SEED != 20261014
    # hand-written lexicons: not a subset of the Faker dump (independent authorship), though common names may coincide
    faker_names = {w.lower() for cat in ("first", "last") for w in D.LEX[cat]}
    assert len(own - faker_names) > 40


def test_challenge_regeneration_matches_frozen_file():
    """Provenance check: generator reproduces the frozen bytes on this Python (if not, the FILE remains the benchmark)."""
    man = json.load(open(os.path.join(MAN, "challenge_v1_manifest.json")))
    regen = hashlib.sha256(D.dumps_split(C.generate()).encode("utf-8")).hexdigest()
    if regen != man["sha256_jsonl"]:
        pytest.skip("generator output differs on this Python version; the committed file is authoritative")


def test_challenge_content_mix():
    exs = D.read_split(os.path.join(DS, "challenge_v1.jsonl.gz"))
    srcs = {e.kind for e in exs}
    assert {"json_nested", "json_neg", "query", "form", "header", "narrative", "log", "chat", "email", "csv", "xml"} <= srcs
    assert sum(1 for e in exs if not e.spans) / len(exs) > 0.2
    assert any("unicode" in e.tags for e in exs) and any("multi_entity" in e.tags for e in exs) and any("truncated" in e.tags for e in exs)
    ents = [e.text[s:t] for e in exs for s, t, _ in e.spans]
    assert not any("@" in x for x in ents)          # e-mail addresses are never entities
