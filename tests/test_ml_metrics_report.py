import json
import os
import subprocess
import sys

import pytest

from packet_pii.ml import data as D
from packet_pii.ml.metrics import entity_metrics, error_samples

ROOT = os.path.join(os.path.dirname(__file__), "..")
ARTIFACT = os.path.join(ROOT, "src", "packet_pii", "ml", "artifacts", "bilstm_v1")
EVAL = os.path.join(ROOT, "scripts", "ml", "evaluate.py")


# ---- metrics: ids missing from gold
def test_prediction_for_id_missing_from_gold_is_false_positive():
    gold = {1: [(0, 5, "USERNAME")]}
    pred = {1: [(0, 5, "USERNAME")], 99: [(2, 6, "PERSON_NAME"), (7, 9, "USERNAME")]}
    m = entity_metrics(gold, pred)
    assert (m["micro"]["tp"], m["micro"]["fp"], m["micro"]["fn"]) == (1, 2, 0)
    assert m["per_class"]["PERSON_NAME"]["fp"] == 1 and m["per_class"]["USERNAME"]["fp"] == 1
    assert m["micro"]["precision"] == pytest.approx(1 / 3)
    assert (99, 2, 6, "PERSON_NAME") in m["errors"]["false_positives"]


def test_only_unknown_ids_predicted_gives_zero_precision_not_ignored():
    m = entity_metrics({1: [(0, 3, "USERNAME")]}, {2: [(0, 3, "USERNAME")]})
    assert (m["micro"]["tp"], m["micro"]["fp"], m["micro"]["fn"]) == (0, 1, 1)
    assert m["micro"]["f1"] == 0.0


def test_missing_pred_ids_still_false_negatives_and_empty_cases():
    m = entity_metrics({1: [(0, 3, "USERNAME")], 2: []}, {})
    assert (m["micro"]["tp"], m["micro"]["fp"], m["micro"]["fn"]) == (0, 0, 1)
    assert entity_metrics({}, {5: [(0, 1, "USERNAME")]})["micro"]["fp"] == 1
    assert entity_metrics({}, {})["micro"]["fp"] == 0


def test_metrics_unchanged_when_ids_match():
    gold = {1: [(0, 5, "USERNAME")], 2: [(0, 3, "PERSON_NAME")], 3: []}
    pred = {1: [(0, 5, "USERNAME")], 2: [(0, 4, "PERSON_NAME")], 3: [(1, 2, "USERNAME")]}
    m = entity_metrics(gold, pred)
    assert (m["micro"]["tp"], m["micro"]["fp"], m["micro"]["fn"]) == (1, 2, 1)


# ---- error samples
SECRET_TEXT = "Contact Zq9-SECRET-Person now"


class _Ex:
    kind, location, text = "text_person", "json_body.password", SECRET_TEXT


def test_error_samples_default_has_no_raw_text():
    rows = error_samples([("a", 8, 25, "PERSON_NAME")], {"a": _Ex()})
    blob = json.dumps(rows)
    assert "SECRET" not in blob and "password" not in blob
    assert rows == [{"id": "a", "kind": "text_person", "label": "PERSON_NAME", "start": 8, "end": 25,
                     "span_length": 17, "text_length": len(SECRET_TEXT)}]
    assert error_samples([("zzz", 0, 1, "USERNAME")], {})[0]["kind"] is None  # unknown id does not crash
    assert len(error_samples([("a", 0, 1, "USERNAME")] * 40, {"a": _Ex()}, limit=5)) == 5


def test_error_samples_opt_in_includes_text():
    row = error_samples([("a", 8, 25, "PERSON_NAME")], {"a": _Ex()}, include_text=True)[0]
    assert row["text"] == SECRET_TEXT and row["span"] == "Zq9-SECRET-Person" and row["location"] == "json_body.password"


# ---- evaluate.py end to end (existing checkpoint, no retraining)
def _run(tmp_path, *args):
    out = tmp_path / "r.json"
    r = subprocess.run([sys.executable, EVAL, "--checkpoint", ARTIFACT, "--out", str(out), *args],
                       capture_output=True, text=True)
    return r, out


@pytest.fixture(scope="module")
def have_stack():
    pytest.importorskip("torch")
    if not os.path.isdir(ARTIFACT):
        pytest.skip("trained artifact not present")


def test_evaluate_default_exports_no_raw_text(tmp_path, have_stack):
    r, out = _run(tmp_path, "--splits", "calib")
    assert r.returncode == 0, r.stderr[-500:]
    blob = out.read_text(encoding="utf-8")
    res = json.loads(blob)
    assert res["error_samples_include_text"] is False
    errs = res["splits"]["calib"]["errors"]
    assert errs["sample_false_positives"] and errs["sample_false_negatives"]
    for row in errs["sample_false_positives"] + errs["sample_false_negatives"]:
        assert not {"text", "span", "location"} & set(row)
    for ex in D.generate_dataset(res["data_seed"])["calib"][:300]:
        for s, e, _ in ex.spans:
            if e - s >= 8:
                assert ex.text[s:e] not in blob  # no raw PII span strings anywhere in the report


def test_evaluate_include_text_is_explicit_opt_in(tmp_path, have_stack):
    r, out = _run(tmp_path, "--splits", "calib", "--include-text")
    assert r.returncode == 0
    res = json.loads(out.read_text(encoding="utf-8"))
    assert res["error_samples_include_text"] is True
    assert all({"text", "span", "location"} <= set(x) for x in res["splits"]["calib"]["errors"]["sample_false_negatives"])


def test_evaluate_refuses_frozen_test_without_final(tmp_path, have_stack):
    r, out = _run(tmp_path, "--splits", "test")
    assert r.returncode != 0 and not out.exists()
