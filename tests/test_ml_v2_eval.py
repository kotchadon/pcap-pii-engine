import pytest

from packet_pii.ml import FieldInput
from packet_pii.ml.data2 import Example2
from packet_pii.ml.evaluation import (TrainContext, bootstrap_ci, hybrid_rules_first, hybrid_union, no_entity_false_positive_rate,
                                      paired_bootstrap_diff, per_example_counts, prf, recall_on, reliability_bins)
from packet_pii.ml.input_policy import QUALITY_FLAGS, run_with_policy, screen_field
from packet_pii.ml.schema import EntityLabel, EntitySpan, ScoreType


def ex(i, loc, text, spans=(), tags=()):
    return Example2(i, "t", "k", "tpl", loc, text, tuple(spans), tuple(tags))


def test_prf_and_per_example_counts_handle_unknown_ids():
    c = per_example_counts({1: [(0, 3, "USERNAME")]}, {1: [(0, 3, "USERNAME")], 2: [(0, 1, "USERNAME")]})
    assert c == {1: (1, 0, 0), 2: (0, 1, 0)} and prf(1, 1, 0)["precision"] == 0.5 and prf(0, 0, 0)["f1"] == 0.0


def test_bootstrap_is_deterministic_and_brackets_point_estimate():
    counts = {i: ((1, 0, 0) if i % 4 else (0, 1, 1)) for i in range(200)}
    a, b = bootstrap_ci(counts, 200, seed=1), bootstrap_ci(counts, 200, seed=1)
    assert a == b
    point = prf(*[sum(v[j] for v in counts.values()) for j in range(3)])["f1"]
    lo, hi = a["f1"]
    assert lo <= point <= hi and hi - lo < 0.2
    d = paired_bootstrap_diff(counts, {i: (0, 1, 1) for i in counts}, 100)
    assert d["ci95"][0] > 0 and d["p_a_not_better"] == 0.0


def test_hybrid_rules_first_never_overrides_rules_and_filters_by_score():
    rules = [(0, 5, "USERNAME")]
    ml = [(0, 5, "PERSON_NAME", .99), (10, 15, "PERSON_NAME", .8), (12, 16, "PERSON_NAME", .95), (20, 25, "USERNAME", .2)]
    out = hybrid_rules_first(rules, ml, .5)
    assert (0, 5, "USERNAME") in out and (0, 5, "PERSON_NAME") not in out        # label conflict: rules win
    assert (12, 16, "PERSON_NAME") in out and (10, 15, "PERSON_NAME") not in out  # overlapping ML spans: highest score only
    assert (20, 25, "USERNAME") not in out                                         # below tau
    assert hybrid_rules_first([], [], .5) == []


def test_hybrid_veto_drops_unconfirmed_ambiguous_rule_span():
    rules = [(0, 8, "PERSON_NAME")]
    assert hybrid_rules_first(rules, [], .5, veto_ids=rules, tau_veto=.2) == []
    assert hybrid_rules_first(rules, [(0, 8, "PERSON_NAME", .9)], .5, veto_ids=rules, tau_veto=.2) == rules
    assert hybrid_rules_first(rules, [], .5) == rules                              # no veto configured


def test_hybrid_union_is_a_superset_of_rules():
    assert set(hybrid_union([(0, 1, "USERNAME")], [(3, 4, "USERNAME", .9)], .5)) == {(0, 1, "USERNAME"), (3, 4, "USERNAME")}


def test_context_slices_unseen_key_and_context():
    train = [ex("a", "json_body.user.name", "Hi Maria", [(3, 8, "PERSON_NAME")]), ex("b", "form.login", "bob_1", [(0, 5, "USERNAME")])]
    ctx = TrainContext.build(train)
    seen = ex("c", "json_body.user.name", "Hi Zed", [(3, 6, "PERSON_NAME")])
    unseen = ex("d", "json_body.gamertag", "Greetings Zed", [(10, 13, "PERSON_NAME")])
    assert not ctx.unseen_key(seen) and ctx.unseen_key(unseen)
    assert not ctx.unseen_context(seen, seen.spans[0]) and ctx.unseen_context(unseen, unseen.spans[0])
    value_only = ex("e", "form.login", "alice", [(0, 5, "USERNAME")])
    assert not ctx.unseen_context(value_only, value_only.spans[0])
    pred = {"c": [(3, 6, "PERSON_NAME")], "d": []}
    assert recall_on([seen, unseen], pred, lambda e, sp: ctx.unseen_context(e, sp)) == {"n": 1, "recall": 0.0}


def test_no_entity_fp_rate():
    exs = [ex("a", "x", "Hello team", tags=("hard_negative",)), ex("b", "x", "Hi", tags=()), ex("c", "x", "Maria", [(0, 5, "PERSON_NAME")])]
    r = no_entity_false_positive_rate(exs, {"a": [(6, 10, "PERSON_NAME")]})
    assert r == {"n": 2, "with_false_positive": 1, "rate": 0.5}
    assert no_entity_false_positive_rate(exs, {}, "hard_negative")["with_false_positive"] == 0


def test_reliability_bins_ece():
    ece, rows = reliability_bins([(0.9, 1)] * 9 + [(0.9, 0)] + [(0.1, 0)] * 10)
    assert ece == pytest.approx(0.05, abs=1e-9) and len(rows) == 2
    assert reliability_bins([]) == (None, [])


# ---- upstream input policy
class FakeDetector:
    model_version = "fake"

    def __init__(self):
        self.seen = []

    def predict_fields(self, fields):
        self.seen += [f.field_index for f in fields]
        return [EntitySpan(f.field_index, EntityLabel.PERSON_NAME, 0, 1, "fake", 0.5, ScoreType.UNCALIBRATED_MODEL_SCORE)
                for f in fields if f.text]


def test_policy_skips_secret_empty_short_and_replacement_fields_without_calling_model():
    d = FakeDetector()
    fields = [FieldInput(0, "json_body.password", "hunter2 Maria"), FieldInput(1, "header.cookie", "user=bob"), FieldInput(2, "json_body.name", ""),
              FieldInput(3, "json_body.name", "x"), FieldInput(4, "json_body.name", "���� a"), FieldInput(5, "json_body.name", "Maria Garcia")]
    r = run_with_policy(d, fields)
    assert d.seen == [5] and [s.field_index for s in r.spans] == [5]
    assert r.skipped == {0: ("secret_bearing_key",), 1: ("secret_bearing_key",), 2: ("empty_text",), 3: ("too_short",), 4: ("mostly_replacement_chars",)}
    assert "hunter2" not in repr(r) and "Maria" not in repr(r.skipped)


def test_policy_propagates_upstream_quality_flags_as_partial_evidence():
    d = FakeDetector()
    fields = [FieldInput(0, "json_body.name", "Maria Gar", {"truncated": "true"}), FieldInput(1, "json_body.name", "Maria Garcia"),
              FieldInput(2, "body.text", "Hi Mari�a there", {"stream_gap": "1", "capture_incomplete": "yes"})]
    r = run_with_policy(d, fields)
    assert r.partial_evidence == frozenset({0, 2}) and {s.field_index for s in r.spans} == {0, 1, 2}
    assert r.screens[2].quality_flags == ("capture_incomplete", "decode_replaced", "stream_gap")
    assert set(QUALITY_FLAGS) >= {"truncated", "stream_gap"}


def test_policy_empty_input_and_duplicate_indices():
    assert run_with_policy(FakeDetector(), []).spans == []
    from packet_pii.ml import MlValidationError
    with pytest.raises(MlValidationError):
        run_with_policy(FakeDetector(), [FieldInput(0, "a", "bb"), FieldInput(0, "b", "cc")])
    assert screen_field(FieldInput(0, "x", "ok text")).eligible


def test_v2_torch_free_modules_import_without_pytorch():
    import os
    import subprocess
    import sys
    import textwrap
    src = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
    code = f"SRC = {src!r}\n" + textwrap.dedent("""
        import sys
        sys.path.insert(0, SRC)
        sys.modules['torch'] = None
        from packet_pii.ml import data2, challenge, evaluation, input_policy, FieldInput
        from packet_pii.ml.input_policy import screen_field
        assert len(data2.generate_split('val', 20, 1)) == 20 and len(challenge.generate()) > 1000
        assert screen_field(FieldInput(0, 'json_body.password', 'x y')).skip_reasons == ('secret_bearing_key',)
        try:
            import packet_pii.ml.infer
        except ImportError as e:
            assert 'PyTorch is required' in str(e)
        else:
            raise SystemExit('infer must need torch')
        print('ok')
    """)
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "ok", r.stderr
