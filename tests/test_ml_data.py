import json

import pytest

from packet_pii.ml import data as D
from packet_pii.ml.baseline import existing_key_rules, majority, strong_rules
from packet_pii.ml.encoding import (IGNORE, PAD, UNK, build_vocab, chunk_ranges, encode_example,
                                    location_tokens, shape_id)
from packet_pii.ml.metrics import entity_metrics
from packet_pii.ml.spans import (TAGS, AlignmentError, spans_to_tags, tags_to_spans, tokenize, viterbi_decode)


@pytest.fixture(scope="module")
def ds():
    return D.generate_dataset(seed=7, sizes={"train": 600, "val": 150, "calib": 150, "test": 200})


def test_tokenizer_offsets_unicode_and_punctuation():
    text = "Hi O'Brien, cool.cat 😀 Zoë éa  日本"
    toks = tokenize(text)
    assert all(text[t.start:t.end] == t.text for t in toks)
    assert [t.text for t in toks][:8] == ["Hi", "O", "'", "Brien", ",", "cool", ".", "cat"]
    assert "éa" in [t.text for t in toks]  # combining mark stays inside the token
    assert tokenize("") == [] and tokenize("   \n\t") == []
    assert tokenize(text) == tokenize(text)


def test_bio_alignment_roundtrip_unicode():
    text = "😀 Zoë Müller wrote @cool.cat_99"
    toks = tokenize(text)
    s1 = text.index("Zoë"); e1 = s1 + len("Zoë Müller")
    s2 = text.index("cool"); e2 = len(text)
    spans = [(s1, e1, "PERSON_NAME"), (s2, e2, "USERNAME")]
    tags = spans_to_tags(toks, spans)
    assert [TAGS[t] for t in tags if t] == ["B-PERSON_NAME", "I-PERSON_NAME", "B-USERNAME", "I-USERNAME",
                                            "I-USERNAME", "I-USERNAME"][:sum(1 for t in tags if t)]
    back = tags_to_spans(toks, tags)
    assert [(a, b, l) for a, b, l, _ in back] == spans
    assert text[back[0][0]:back[0][1]] == "Zoë Müller"


@pytest.mark.parametrize("spans", [[(1, 3, "PERSON_NAME")], [(0, 2, "NOPE")], [(0, 2, "USERNAME"), (0, 2, "USERNAME")],
                                   [(5, 2, "USERNAME")]])
def test_misaligned_or_overlapping_gold_raises_never_dropped(spans):
    with pytest.raises(AlignmentError):
        spans_to_tags(tokenize("Maria Gonzalez"), spans)


def test_viterbi_enforces_bio_constraints():
    import math
    n = len(TAGS)
    def row(best, p=0.9):
        r = [math.log((1 - p) / (n - 1))] * n
        r[best] = math.log(p)
        return r
    # raw argmax would be O, I-PERSON_NAME, I-USERNAME (illegal); decoded path must be legal
    path = viterbi_decode([row(0), row(2), row(4)])
    names = [TAGS[i] for i in path]
    assert not names[0].startswith("I-")
    for a, b in zip(names, names[1:]):
        if b.startswith("I-"):
            assert a != "O" and a[2:] == b[2:]
    assert viterbi_decode([]) == []


def test_tags_to_spans_tolerates_stray_I_and_scores():
    toks = tokenize("a b c d")
    tags = [0, 2, 2, 0]  # I I without B
    sp = tags_to_spans(toks, tags, [0.1, 0.8, 0.6, 0.1])
    assert len(sp) == 1 and sp[0][:3] == (2, 5, "PERSON_NAME") and abs(sp[0][3] - 0.7) < 1e-9


def test_location_tokens_and_shapes():
    assert location_tokens("json_body.user[0].fullName") == ["json", "body", "user", "<num>", "full", "name"]
    assert len(location_tokens(".".join("abcdefghijklmnopqrst"))) == 12
    assert [shape_id(t) for t in ("abc", "Abc", "ABC", "aBc", "123", "a1", "a_b", "-", "日本")] == [0, 1, 2, 3, 4, 5, 6, 7, 8]


def test_vocab_train_only_unknowns_and_padding_conventions():
    v = build_vocab([("user.name", "Alice Smith lives here"), ("user.name", "Alice Smith lives there")], 2, 1)
    assert v.words[PAD] == 0 and v.words[UNK] == 1
    assert "alice" in v.words and "there" not in v.words
    enc = encode_example(v, "user.name", "Zed Alice", [(4, 9, "PERSON_NAME")])
    assert enc.word_ids[enc.n_ctx] == v.words[UNK]          # unseen -> trained <unk> id, never random
    assert enc.tags == [0, 1] and enc.n_ctx == 3 and len(enc) == 5
    assert IGNORE == -100


def test_chunk_ranges_cover_everything():
    assert chunk_ranges(0, 5) == [] and chunk_ranges(5, 5) == [(0, 5)] and chunk_ranges(11, 5) == [(0, 5), (5, 10), (10, 11)]
    with pytest.raises(ValueError):
        chunk_ranges(3, 0)


def test_dataset_deterministic_aligned_and_sized(ds):
    again = D.generate_dataset(seed=7, sizes={"train": 600, "val": 150, "calib": 150, "test": 200})
    assert D.dumps_split(ds["test"]) == D.dumps_split(again["test"])
    assert {k: len(v) for k, v in ds.items()} == {"train": 600, "val": 150, "calib": 150, "test": 200}
    for exs in ds.values():
        assert len({(e.location, e.text) for e in exs}) == len(exs)
        for e in exs:
            spans_to_tags(tokenize(e.text), e.spans)  # every gold span aligns
    # covers every context type incl. hard negatives, unicode, both labels
    kinds = {e.kind for e in ds["train"]}
    assert {"field_neg", "text_neg", "kv", "url", "text_mixed"} <= kinds
    assert any(not e.spans for e in ds["test"]) and any(not c.isascii() for e in ds["train"] for c in e.text)
    assert {l for e in ds["train"] for *_, l in e.spans} == {"PERSON_NAME", "USERNAME"}


def test_no_leakage_between_splits(ds):
    rep = D.leakage_report(ds)
    for k in ("exact_duplicates", "template_overlap", "skeleton_overlap", "family_overlap", "lexical_overlap"):
        assert rep[k] == 0, (k, rep)
    assert all(v == 0 for v in D.entity_value_overlap(ds).values())  # no entity string shared with train


def test_dataset_io_roundtrip(tmp_path, ds):
    man = D.write_dataset(ds, tmp_path)
    back = D.read_split(tmp_path / "val.jsonl")
    assert back == ds["val"] and man["splits"]["val"]["examples"] == 150
    json.dumps(man)


def test_metrics_exact_match_semantics():
    gold = {1: [(0, 5, "USERNAME")], 2: [(0, 3, "PERSON_NAME")], 3: []}
    pred = {1: [(0, 5, "USERNAME")], 2: [(0, 4, "PERSON_NAME")], 3: [(1, 2, "USERNAME")]}
    m = entity_metrics(gold, pred)
    assert m["micro"]["tp"] == 1 and m["micro"]["fp"] == 2 and m["micro"]["fn"] == 1
    assert m["per_class"]["USERNAME"]["support"] == 1 and m["per_class"]["PERSON_NAME"]["f1"] == 0.0
    assert entity_metrics({}, {})["micro"]["f1"] == 0.0


def test_baselines_basic_behaviour():
    assert majority("a", "Maria") == []
    assert existing_key_rules("json_body.full_name", "Maria G") == [(0, 7, "PERSON_NAME")]
    assert existing_key_rules("json_body.title", "Maria") == []
    assert strong_rules("json_body.name", "Acme Labs") == []
    assert strong_rules("json_body.name", "Maria Garcia") == [(0, 12, "PERSON_NAME")]
    assert strong_rules("body.text", "Logged in as bob_1")[0][2] == "USERNAME"
    assert strong_rules("x", "") == []
