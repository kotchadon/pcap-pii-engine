"""Model-behaviour probes on synthetic extracted fields representing upstream defects (U2/U4/U9/U13 in
docs/ml/UPSTREAM_INPUT_ASSUMPTIONS.md). These are NOT tests of TCP reassembly."""
import logging
import os

import pytest

torch = pytest.importorskip("torch")

from packet_pii.ml import FieldInput, MlValidationError, ValidationLimits, run_detector
from packet_pii.ml import data2 as D
from packet_pii.ml.bilstm import ModelConfig, save_checkpoint, train_model
from packet_pii.ml.encoding import build_vocab
from packet_pii.ml.infer import BiLSTMDetector
from packet_pii.ml.input_policy import run_with_policy

SECRET = "Zq9SECRETvalue"
ARTIFACT = os.path.join(os.path.dirname(__file__), "..", "src", "packet_pii", "ml", "artifacts", "bilstm_v2")


@pytest.fixture(scope="module")
def det(tmp_path_factory):
    ds = D.generate_dataset(seed=21, sizes={"train": 700, "val": 120, "calib": 60})
    v = build_vocab([(e.location, e.text) for e in ds["train"]])
    cfg = ModelConfig(len(v.words), len(v.chars), hidden=32, word_dim=24, char_filters=16, key_broadcast=True).validate()
    m, rec = train_model(ds["train"], ds["val"], v, cfg, epochs=8, patience=9, log=lambda s: None)
    d = tmp_path_factory.mktemp("probe") / "ck"
    save_checkpoint(str(d), m, v, version_prefix="bilstm-v2x", training=rec, extra={"min_score": 0.0})
    return BiLSTMDetector(str(d))


DEFECTS = {
    "truncated_mid_entity": "Dear Maria Gar",
    "duplicated_value": "Maria GarciaMaria Garcia",
    "fused_across_gap": "ThankyouMariaGarcia",
    "replacement_chars": "Dear Mar��a Garcia,",
    "only_replacement": "���",
    "single_char": "M",
    "empty": "",
    "whitespace_only": "   \n\t ",
    "control_chars": "Dear\x00Maria\x07Garcia",
    "emoji_and_rtl": "Hi ‮Maria‬ \U0001F600 יעל",
    "very_long_token": "a" * 5000,
    "many_short_tokens": "x " * 6000,
}


@pytest.mark.parametrize("name", sorted(DEFECTS))
def test_defective_fields_never_crash_and_offsets_stay_valid(det, name):
    text = DEFECTS[name]
    out = run_detector(det, [FieldInput(0, "json_body.message", text)])
    for s in out:
        assert 0 <= s.start < s.end <= len(text) and 0.0 <= s.score <= 1.0
    assert out == run_detector(det, [FieldInput(0, "json_body.message", text)])   # deterministic


def test_policy_flags_replacement_chars_and_truncation_but_still_returns_valid_spans(det):
    fields = [FieldInput(0, "json_body.message", DEFECTS["replacement_chars"]),
              FieldInput(1, "json_body.message", DEFECTS["truncated_mid_entity"], {"truncated": "true", "stream_gap": "true"}),
              FieldInput(2, "json_body.message", DEFECTS["only_replacement"]), FieldInput(3, "json_body.password", "Dear Maria Garcia")]
    r = run_with_policy(det, fields)
    assert r.skipped == {2: ("mostly_replacement_chars",), 3: ("secret_bearing_key",)}
    assert {s.field_index for s in r.spans} <= {0, 1} and r.partial_evidence <= {0, 1}
    assert r.screens[0].quality_flags == ("decode_replaced",) and r.screens[1].quality_flags == ("stream_gap", "truncated")


def test_oversized_and_long_fields(det):
    long_text = "Hello Maria Garcia, please call Bob tomorrow. " * 800     # ~36k chars, windowed
    out = run_detector(det, [FieldInput(0, "body.text", long_text)])
    assert all(s.end <= len(long_text) for s in out)
    with pytest.raises(MlValidationError):
        run_detector(det, [FieldInput(0, "body.text", "x" * 70000)])
    with pytest.raises(MlValidationError):
        run_detector(det, [FieldInput(0, "body.text", "x" * 50)], ValidationLimits(max_field_chars=10))


def test_no_raw_values_in_logs_stdout_or_policy_objects(det, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    f = FieldInput(0, "json_body.token", f"user {SECRET}")
    g = FieldInput(1, "json_body.comment", f"login as {SECRET}")
    r = run_with_policy(det, [f, g])
    cap = capsys.readouterr()
    assert SECRET not in caplog.text and SECRET not in cap.out + cap.err and SECRET not in repr(r)


@pytest.mark.skipif(not os.path.isdir(ARTIFACT), reason="V2 artifact not present")
def test_committed_v2_artifact_contract_and_examples():
    d = BiLSTMDetector(ARTIFACT)
    assert d.model_version.startswith("bilstm-v2-") and 0 <= d.min_score <= 1
    f = [FieldInput(0, "json_body.shipping.recipient", "Priyanka Venkataraman"), FieldInput(1, "json_body.audit.actor", "night_owl_77"),
         FieldInput(2, "json_body.invoice.billed_to", "Johnson & Johnson")]
    out = run_detector(d, f)
    assert any(s.field_index == 0 and s.label.value == "PERSON_NAME" and (s.start, s.end) == (0, 21) for s in out)
    assert any(s.field_index == 1 and s.label.value == "USERNAME" and (s.start, s.end) == (0, 12) for s in out)
    assert not any(s.field_index == 2 for s in out)
    assert out == run_detector(BiLSTMDetector(ARTIFACT), f)
