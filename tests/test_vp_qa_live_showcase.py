"""Task A - independent verification of the live V2 BiLSTM + rules behaviour on the 12-conversation showcase.

Real engine, real V2 ensemble checkpoint, no mock detector. Structural invariants are asserted unconditionally; the exact
model outputs are *characterisation* tests pinned to checkpoint ``bilstm-v2-d1f9e9fb9a2b`` (they are skipped, not weakened,
if the checkpoint changes). Observed misses and false positives are asserted as observed - they are never suppressed.
These are observations on ONE hand-authored fixture (9 intended person/username fields); they are not an accuracy estimate.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import threading
from collections import Counter
from contextlib import contextmanager
from http.client import HTTPConnection

import pytest

from packet_pii import hybrid
from packet_pii.dashboard import DashboardServer
from packet_pii.engine import analyze
from packet_pii.http_extract import extract_fields, parse_http_stream
from packet_pii.detect import SECRET_KEYS
from test_vp_qa_support import (ROOT, V2_VERSION, is_v2_checkpoint, ml_findings, rule_findings, showcase_module, showcase_pcap, v2_detector)

RAW_FICTIONAL = ("Priyanka Venkataraman", "night_owl_77", "violet_dev22", "robot_test_44", "Alex Example", "Fatima Khan",
                 "fictional-demo-password", "fictional-demo-token-123", "4111 1111 1111 1111", "0412345678", "Johnson & Johnson")


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    det = v2_detector()
    path = showcase_pcap(tmp_path_factory.mktemp("showcase"))
    return {"det": det, "path": path, "rules": analyze(path), "hybrid": analyze(path, ml_detector=det)}


# ---------------------------------------------------------------- network layer (identical in both modes)
@pytest.mark.parametrize("mode", ["rules", "hybrid"])
def test_measured_network_counts(run, mode):
    s = run[mode]["summary"]
    assert (s["packets_captured"], s["non_tcp_or_unsupported_packets"], s["flows_processed"], s["http_flows"]) == (95, 0, 12, 12)
    assert (s["http_messages"], s["http_transactions"], s["unpaired_requests"], s["unpaired_responses"]) == (24, 12, 0, 0)
    assert (s["stream_gaps"], s["capture_truncated_records"], s["capture_malformed_records"], s["analysis_incomplete"]) == (0, 0, 0, False)
    assert len(run[mode]["flows"]) == 12 and all(f["http_messages"] == 2 for f in run[mode]["flows"])


def test_mode_metadata_is_honest(run):
    r, h = run["rules"]["metadata"], run["hybrid"]["metadata"]
    assert r["detection_method"] == "rules_only" and r.get("ml_model_version") is None and r["confidence_type"] == "heuristic_not_calibrated"
    assert h["detection_method"] == "rules_plus_bilstm" and h["ml_model_version"] == run["det"].model_version
    assert h["confidence_type"] == "separate_rule_heuristic_and_uncalibrated_model_scores"
    lim = " ".join(run["hybrid"]["limitations"])
    assert "uncalibrated" in lim and "no real-traffic precision/recall" in lim and "not proof of exfiltration" in lim


# ---------------------------------------------------------------- rules findings
def test_rules_findings_are_identical_in_rules_only_and_hybrid(run):
    """ML is additive: it must never add, drop or alter a rule finding."""
    assert rule_findings(run["rules"]) == rule_findings(run["hybrid"])
    assert all(f["detector"] == "rule" for f in run["rules"]["findings"]) and ml_findings(run["rules"]) == []


def test_rule_finding_breakdown(run):
    assert Counter(f["pii_type"] for f in rule_findings(run["hybrid"])) == Counter(
        {"EMAIL": 10, "CREDENTIAL_OR_TOKEN": 2, "USERNAME": 2, "PERSON_NAME_CANDIDATE": 2, "PHONE": 2, "CREDIT_CARD": 1})
    assert run["rules"]["summary"]["rules_findings"] == run["hybrid"]["summary"]["rules_findings"] == 19


# ---------------------------------------------------------------- ML accounting: evaluated / skipped / excluded
def test_ml_field_accounting_matches_independent_recount(run, tmp_path):
    """Recount extracted fields straight from the fixture bytes and apply the documented exclusion rules independently."""
    mod = showcase_module()
    cat = Counter()
    for i, scenario in enumerate(mod.SCENARIOS):
        for blob in mod._messages(i, scenario):
            for message in parse_http_stream(blob):
                for location, text in extract_fields(message):
                    if location.startswith("header."):
                        cat["excluded_header"] += 1
                    elif SECRET_KEYS.search(location):
                        cat["excluded_secret_key"] += 1
                    elif hybrid._RESERVED_FIELD.search(location):
                        cat["excluded_reserved_contact_or_numeric_key"] += 1
                    elif text:
                        cat["evaluated"] += 1
    assert cat == Counter({"excluded_header": 85, "excluded_reserved_contact_or_numeric_key": 13, "excluded_secret_key": 1, "evaluated": 48})
    s = run["hybrid"]["summary"]
    assert (s["ml_fields_evaluated"], s["ml_fields_excluded_by_policy"], s["ml_fields_skipped"]) == (48, 99, 0)
    assert s["ml_fields_excluded_by_policy"] == 85 + 13 + 1
    r = run["rules"]["summary"]
    assert (r["ml_fields_evaluated"], r["ml_fields_excluded_by_policy"], r["ml_findings"]) == (0, 0, 0)


def test_summary_counts_are_internally_consistent(run):
    s = run["hybrid"]["summary"]
    assert s["potential_leaks"] == len(run["hybrid"]["findings"]) == s["rules_findings"] + s["ml_findings"]
    assert Counter(f["detector"] for f in run["hybrid"]["findings"]) == Counter({"rule": 19, "bilstm": 12})


# ---------------------------------------------------------------- characterisation of the real V2 outputs
EXPECTED_ML = {  # (flow, location, label, start, end) - observed with bilstm-v2-d1f9e9fb9a2b
    ("flow_0001", "json_body.audit.actor", "USERNAME", 0, 12), ("flow_0001", "json_body.shipping.recipient", "PERSON_NAME", 0, 21),
    ("flow_0002", "json_body.username", "USERNAME", 0, 12), ("flow_0005", "form.full_name", "PERSON_NAME", 0, 11),
    ("flow_0006", "json_body.audit.actor", "USERNAME", 0, 12), ("flow_0007", "json_body.shipping.recipient", "PERSON_NAME", 0, 21),
    ("flow_0011", "json_body.username", "USERNAME", 0, 13), ("flow_0012", "json_body.user", "USERNAME", 0, 12)}
OBSERVED_FALSE_POSITIVE_CANDIDATES = {  # fields the fixture author intended as NOT person/username
    ("flow_0004", "json_body.order.currency", "PERSON_NAME", 0, 3),     # "AUD"
    ("flow_0009", "json_body.note", "PERSON_NAME", 17, 29), ("flow_0009", "json_body.note", "USERNAME", 53, 64),  # words in a free-text note
    ("flow_0010", "json_body.geo.place", "PERSON_NAME", 0, 7)}          # "Madison" (city)


def _ml_keys(report):
    return {(f["flow_id"], f["location"], f["pii_type"], f["span_start"], f["span_end"]) for f in ml_findings(report)}


def test_characterisation_v2_findings_on_showcase(run):
    if not is_v2_checkpoint(run["det"]):
        pytest.skip("characterisation is pinned to " + V2_VERSION)
    assert _ml_keys(run["hybrid"]) == EXPECTED_ML | OBSERVED_FALSE_POSITIVE_CANDIDATES
    assert run["hybrid"]["summary"]["ml_findings"] == 12 and run["det"].min_score == 0.35


def test_known_model_miss_is_reported_not_hidden(run):
    """V2 does not flag json_body.full_name='Alex Example' (flow_0003); only the deterministic rule does."""
    if not is_v2_checkpoint(run["det"]):
        pytest.skip("pinned to " + V2_VERSION)
    ml_here = [f for f in ml_findings(run["hybrid"]) if f["flow_id"] == "flow_0003"]
    rule_here = [f for f in rule_findings(run["hybrid"]) if f["flow_id"] == "flow_0003" and f["location"] == "json_body.full_name"]
    assert ml_here == []
    assert [f["pii_type"] for f in rule_here] == ["PERSON_NAME_CANDIDATE"]


def test_hard_negative_company_not_flagged_but_city_and_currency_are(run):
    if not is_v2_checkpoint(run["det"]):
        pytest.skip("pinned to " + V2_VERSION)
    flagged = {(f["flow_id"], f["location"]) for f in ml_findings(run["hybrid"])}
    assert ("flow_0009", "json_body.invoice.billed_to") not in flagged       # "Johnson & Johnson": correct, no finding
    assert ("flow_0010", "json_body.geo.place") in flagged                   # "Madison": known false-positive candidate
    assert ("flow_0004", "json_body.order.currency") in flagged              # "AUD": unexpected false-positive candidate
    # their scores are the lowest of the report - low raw score is a hint, never a guarantee
    by_loc = {(f["flow_id"], f["location"], f["pii_type"]): f["confidence"] for f in ml_findings(run["hybrid"])}
    assert by_loc[("flow_0010", "json_body.geo.place", "PERSON_NAME")] < 0.6
    assert by_loc[("flow_0004", "json_body.order.currency", "PERSON_NAME")] < 0.8


def test_fixture_intended_field_tally_is_not_an_accuracy_metric(run):
    """8 of 9 intended person/username fields were hit and 4 false-positive candidates appeared. Documented, but n=9 on a
    hand-authored fixture that reuses the V2 demo strings: it must never be quoted as precision/recall/F1."""
    if not is_v2_checkpoint(run["det"]):
        pytest.skip("pinned to " + V2_VERSION)
    keys = _ml_keys(run["hybrid"])
    assert len(EXPECTED_ML & keys) == 8 and len(OBSERVED_FALSE_POSITIVE_CANDIDATES & keys) == 4


def test_showcase_strings_are_absent_from_v2_training_data():
    """Contamination check (training vs fixture): the demo person/handle strings never occur as training/validation/calibration entities."""
    from packet_pii.ml import data2
    banned = {"priyanka venkataraman", "night_owl_77", "violet_dev22", "robot_test_44", "alex example"}
    for split in ("train", "val", "calib"):
        examples = data2.read_split(ROOT / "src" / "packet_pii" / "ml" / "datasets" / "v2" / f"{split}.jsonl.gz")
        entities = {e.text[a:b].lower() for e in examples for a, b, _ in e.spans}
        assert not (entities & banned), split
        assert not any(b in e.text.lower() for e in examples for b in banned), split


# ---------------------------------------------------------------- provenance, masking, leakage
RULE_KEYS = {"pii_type", "location", "confidence", "value", "detector", "flow_id", "http_message_id", "http_request_id", "http_message_type",
             "timestamp", "source_ip", "source_port", "destination_ip", "destination_port", "http_start_line", "evidence"}
ML_EXTRA = {"confidence_type", "model_version", "span_start", "span_end", "field_index"}


def _assert_finding_provenance(report, model_version):
    fields = {row["field_id"]: row for row in report["field_evidence"]}
    assert report["findings"]
    for f in report["findings"]:
        if f["detector"] == "bilstm":
            assert set(f) == RULE_KEYS | ML_EXTRA
            assert f["confidence_type"] == "uncalibrated_model_score" and f["model_version"] == model_version
            assert 0 <= f["span_start"] < f["span_end"] and 0.0 <= f["confidence"] <= 1.0
        else:
            assert f["detector"] == "rule" and set(f) == RULE_KEYS            # no model fields on rule findings
            assert "confidence_type" not in f and "span_start" not in f
        evidence = f['evidence']
        assert evidence['http_message_id'] == f['http_message_id']
        assert evidence['raw_detection_span'] == 'unavailable'
        assert evidence['field_ids']
        assert all(fields[key]['http_message_id'] == f['http_message_id'] for key in evidence['field_ids'])
        if f['detector'] == 'bilstm':
            assert evidence['decoded_text_span'] == {'start': f['span_start'], 'end': f['span_end']}
            assert evidence['field_ids'] == [f"{f['http_message_id']}_field_{f['field_index']}"]
        else:
            assert evidence['scope'] == 'candidate_fields' and 'decoded_text_span' not in evidence
        assert f["flow_id"].startswith("flow_") and f["http_message_id"].startswith(f["flow_id"])
        assert f["source_ip"].startswith(("192.0.2.", "198.51.100.")) and f["destination_ip"].startswith(("192.0.2.", "198.51.100."))
        assert f["http_message_type"] in ("request", "response") and f["http_request_id"]


def test_provenance_fields_and_detector_separation(run):
    _assert_finding_provenance(run['hybrid'], run['det'].model_version)


def test_rules_provenance_contract_without_optional_model(tmp_path):
    _assert_finding_provenance(analyze(showcase_pcap(tmp_path)), None)


def test_ml_and_rule_confidence_are_never_merged(run):
    """Rule heuristics and raw model scores stay separate per finding; a single finding never carries both."""
    for f in run["hybrid"]["findings"]:
        assert isinstance(f["confidence"], float)
    ml = {f["detector"] for f in run["hybrid"]["findings"] if "confidence_type" in f}
    assert ml == {"bilstm"}


@pytest.mark.parametrize("mode", ["rules", "hybrid"])
def test_no_raw_fictional_values_in_default_report(run, mode):
    blob = json.dumps(run[mode], ensure_ascii=False)
    for raw in RAW_FICTIONAL:
        assert raw not in blob, raw
    assert all(("***" in f["value"] or set(f["value"]) == {"*"}) for f in run[mode]["findings"])    # masked
    assert all("fingerprint" not in f for f in run[mode]["findings"])


def test_overlapping_signals_are_reported_as_distinct_locations(run):
    """F-08 fixed: rule + ML can flag the SAME field. `potential_leaks` still counts findings (compatibility) but the summary
    now also reports the distinct exposed locations and which detectors agree."""
    by_loc: dict[tuple, set] = {}
    for f in run["hybrid"]["findings"]:
        by_loc.setdefault((f["flow_id"], f["http_message_id"], f["location"]), set()).add(f["detector"])
    both = sorted(k[2] for k, d in by_loc.items() if d == {"rule", "bilstm"})
    assert both == ["form.full_name", "json_body.username", "json_body.username"]
    s = run["hybrid"]["summary"]
    assert s["potential_leaks"] == 31 and len(by_loc) == 27
    assert (s["distinct_exposed_locations"], s["locations_flagged_by_both"]) == (27, 3)
    assert s["locations_flagged_by_rules"] + s["locations_flagged_by_model"] - s["locations_flagged_by_both"] == 27
    rules = run["rules"]["summary"]
    assert rules["distinct_exposed_locations"] == rules["locations_flagged_by_rules"] and rules["locations_flagged_by_model"] == 0


def test_include_values_offsets_are_consistent_with_masked_lengths(run):
    """With raw values enabled (synthetic only), the ML value equals the field slice and its length equals the span length."""
    det = run["det"]
    full = analyze(run["path"], include_values=True, ml_detector=det)
    for f in ml_findings(full):
        assert len(f["value"]) == f["span_end"] - f["span_start"]
    assert {f["value"] for f in ml_findings(full)} >= {"Priyanka Venkataraman", "night_owl_77", "violet_dev22", "robot_test_44", "Fatima Khan"}


# ---------------------------------------------------------------- runtime
def test_measured_inference_runtime_is_bounded_and_separate(run):
    r, h = run["rules"]["summary"]["processing_time_seconds"], run["hybrid"]["summary"]["processing_time_seconds"]
    assert r < 1.0                      # measured ~0.005 s
    assert 0 < h < 60.0 and h > r       # measured ~2.9 s for 48 fields (3-member ensemble, CPU); model load (~4 s) is outside analyze()


# ---------------------------------------------------------------- rules-only independence from PyTorch
def test_rules_only_analysis_runs_with_pytorch_blocked(tmp_path):
    path = showcase_pcap(tmp_path)
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(ROOT / 'src')!r})
        sys.modules['torch'] = None
        from packet_pii.engine import analyze
        r = analyze({str(path)!r})
        assert r['summary']['http_messages'] == 24 and r['summary']['rules_findings'] == 19 and r['summary']['ml_findings'] == 0
        assert r['metadata']['detection_method'] == 'rules_only'
        print('ok')
    """)
    out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.strip() == "ok", out.stderr


# ---------------------------------------------------------------- the live dashboard API with the REAL model
@contextmanager
def _server(detector):
    s = DashboardServer(("127.0.0.1", 0), ml_detector=detector)
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    try:
        yield s
    finally:
        s.shutdown(); s.server_close(); t.join(timeout=5)


def _call(s, method, url, token=None, mode=None):
    c = HTTPConnection("127.0.0.1", s.server_port, timeout=60)
    headers = {k: v for k, v in (("X-Dashboard-Token", token), ("X-Detection-Mode", mode)) if v}
    c.request(method, url, headers=headers)
    r = c.getresponse()
    out = r.status, json.loads(r.read())
    c.close()
    return out


def test_dashboard_api_matches_direct_engine_with_real_model(run):
    with _server(run["det"]) as s:
        _, session = _call(s, "GET", "/api/session")
        assert session["model_enabled"] is True and session["model_version"] == run["det"].model_version
        _, rules = _call(s, "POST", "/api/showcase", session["token"], "rules")
        _, hyb = _call(s, "POST", "/api/showcase", session["token"], "hybrid")
    assert rules["scan_mode"] == "rules" and rules["model_enabled"] is False and rules["model_available"] is True
    assert hyb["scan_mode"] == "hybrid" and hyb["model_enabled"] is True
    for api, direct in ((rules, run["rules"]), (hyb, run["hybrid"])):
        ks = ("packets_captured", "flows_processed", "http_messages", "rules_findings", "ml_findings", "ml_fields_evaluated", "ml_fields_excluded_by_policy", "potential_leaks")
        assert {k: api["report"]["summary"][k] for k in ks} == {k: direct["summary"][k] for k in ks}
        # The local client dashboard intentionally shows original noncredential
        # values. Only their presentation changes; detection and provenance must match.
        scrub = lambda findings: [{k:v for k,v in x.items() if k != "value"} for x in findings]
        assert scrub(api["report"]["findings"]) == scrub(direct["findings"])
        assert api["report"]["metadata"]["finding_value_policy"] == "noncredential_original"
    blob = json.dumps(hyb, ensure_ascii=False)
    assert "night_owl_77" in blob  # Original username visible in the local client.
    assert "fictional-demo-password" not in blob
    assert "fictional-demo-token-123" not in blob
