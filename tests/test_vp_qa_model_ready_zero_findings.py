"""Why "model ready / AI invoked" can coexist with ZERO contextual findings (real V2 ensemble, synthetic captures).

Model-ready = checkpoint loaded; AI-invoked = analyze(..., ml_detector=...) ran; fields evaluated = eligible text fields actually
passed to the model; ML findings = spans returned. Each of the four can differ. These tests construct one capture per cause.
"""
from __future__ import annotations

import pytest

from packet_pii.engine import analyze
from test_vp_qa_support import (build_pcap, conversation, ml_findings, ok_response, one_request_pcap, post_json, rule_findings, v2_detector)


@pytest.fixture(scope="module")
def det():
    return v2_detector()


def _summ(report):
    s = report["summary"]
    return {k: s[k] for k in ("http_messages", "rules_findings", "ml_findings", "ml_fields_evaluated", "ml_fields_excluded_by_policy", "ml_fields_skipped")}


def test_cause1_everything_sensitive_is_excluded_by_policy(tmp_path, det):
    """Credentials / contact data / headers are routed to rules only: model ready, invoked, 0 fields evaluated, rules still fire."""
    req = post_json({"password": "qa-fictional-pass-1", "api_key": "qa-fictional-key-2", "email": "qa@example.test"},
                    extra_headers=b"Authorization: Bearer qa-fictional-token-3\r\n")
    resp = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
    r = analyze(one_request_pcap(tmp_path, req, resp), ml_detector=det)
    s = _summ(r)
    assert s["ml_fields_evaluated"] == 0 and s["ml_findings"] == 0 and s["ml_fields_excluded_by_policy"] >= 4 and s["rules_findings"] >= 3
    assert r["metadata"]["detection_method"] == "rules_plus_bilstm" and r["metadata"]["ml_model_version"] == det.model_version   # "model ready" is still reported


def test_cause2_eligible_benign_fields_yield_no_contextual_finding(tmp_path, det):
    """The model ran on real text fields and simply found nothing: ml_fields_evaluated > 0, ml_findings == 0."""
    req = post_json({"status": "ok", "count": 3, "title": "Quarterly roadmap review", "region": "eu-west", "tags": ["alpha", "beta"]})
    r = analyze(one_request_pcap(tmp_path, req), ml_detector=det)
    s = _summ(r)
    assert s["ml_fields_evaluated"] >= 6 and s["ml_findings"] == 0 and s["rules_findings"] == 0


def test_cause3_no_http_means_nothing_to_evaluate(tmp_path, det):
    """Binary / TLS-like TCP payload: no HTTP message, nothing evaluated - the capture is NOT shown to be privacy-clean."""
    tls = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + bytes(range(180))
    r = analyze(one_request_pcap(tmp_path, tls, b""), ml_detector=det)
    s = _summ(r)
    assert s["http_messages"] == 0 and s["ml_fields_evaluated"] == 0 and s["ml_findings"] == 0
    assert "Encrypted HTTPS payloads cannot be inspected without decryption" in r["limitations"]


def test_cause4_pii_in_http_headers_is_a_blind_spot_for_the_model(tmp_path, det):
    """Header fields are excluded from ML by policy (hybrid._excluded): the same fictional person in the JSON body is found, in a header it is not."""
    body = post_json({"recipient": "Henrik Larsson"})
    hdr = post_json({"ok": 1}, extra_headers=b"X-Customer-Name: Henrik Larsson\r\nX-Forwarded-User: mint_panda_81\r\n")
    r_body = analyze(one_request_pcap(tmp_path, body, name="body.pcap"), ml_detector=det)
    r_hdr = analyze(one_request_pcap(tmp_path, hdr, name="hdr.pcap"), ml_detector=det)
    assert any(f["location"] == "json_body.recipient" and f["pii_type"] == "PERSON_NAME" for f in ml_findings(r_body))
    assert ml_findings(r_hdr) == [] and rule_findings(r_hdr) == [] and r_hdr["summary"]["ml_fields_excluded_by_policy"] >= 4


def test_cause5_model_miss_on_an_eligible_field(tmp_path, det):
    """A genuine false negative: eligible field, model ran, no span, while the deterministic key rule did fire."""
    if det.model_version != "bilstm-v2-d1f9e9fb9a2b":
        pytest.skip("pinned to the V2 checkpoint")
    r = analyze(one_request_pcap(tmp_path, post_json({"full_name": "Alex Example"})), ml_detector=det)
    assert [f["pii_type"] for f in rule_findings(r)] == ["PERSON_NAME_CANDIDATE"] and ml_findings(r) == []
    assert r["summary"]["ml_fields_evaluated"] >= 1


def test_accounting_counts_each_extracted_field_exactly_once(tmp_path, det):
    """Request: a, c.d (evaluated), b="" (empty: counted nowhere), email (reserved key) + 4 request headers; response: ok=true + 3 headers."""
    req = post_json({"a": "x", "b": "", "email": "e@example.test", "c": {"d": "y"}})
    p = one_request_pcap(tmp_path, req)
    hyb, rul = analyze(p, ml_detector=det), analyze(p)
    s = hyb["summary"]
    assert (s["ml_fields_evaluated"], s["ml_fields_excluded_by_policy"], s["ml_fields_skipped"], s["ml_findings"]) == (3, 8, 0, 0)
    assert rul["summary"]["ml_fields_evaluated"] == rul["summary"]["ml_fields_excluded_by_policy"] == rul["summary"]["ml_fields_skipped"] == 0
    assert rul["metadata"]["detection_method"] == "rules_only"
