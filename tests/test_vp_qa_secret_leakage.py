"""Task B - credentials and tokens: none may reach the contextual model, appear in a default report, or be logged.

A recording *spy detector* (implements ContextualPIIDetector, returns no spans) captures exactly what the engine hands to a
model, so the exclusion policy is verified without relying on any model's behaviour. Fictional secrets only.
"""
from __future__ import annotations

import io
import json
import logging
from contextlib import redirect_stderr, redirect_stdout

import pytest

from packet_pii.engine import analyze
from test_vp_qa_support import one_request_pcap, post_json, v2_detector

SECRETS = ("qa-fictional-password-01", "qa-fictional-token-02", "qa-fictional-apikey-03", "qa-fictional-cookie-04",
           "qa-fictional-bearer-05", "qa-fictional-session-06", "qa-fictional-refresh-07")
BODY = {"password": SECRETS[0], "access_token": SECRETS[1], "api_key": SECRETS[2], "session_id": SECRETS[5], "refresh_token": SECRETS[6],
        "profile": {"recipient": "Henrik Larsson", "note": "plain text"}}
HEADERS = (f"Cookie: sid={SECRETS[3]}; theme=dark\r\nAuthorization: Bearer {SECRETS[4]}\r\n").encode()


class SpyDetector:
    model_version = "qa-spy"

    def __init__(self):
        self.seen: list[tuple[str, str]] = []

    def predict_fields(self, fields):
        self.seen += [(f.location, f.text) for f in fields]
        return []


def _capture(tmp_path):
    return one_request_pcap(tmp_path, post_json(BODY, extra_headers=HEADERS))


def test_no_credential_field_or_header_is_ever_given_to_the_model(tmp_path):
    spy = SpyDetector()
    r = analyze(_capture(tmp_path), ml_detector=spy)
    assert spy.seen, "spy must have received the eligible fields"
    blob = " ".join(loc + " " + text for loc, text in spy.seen)
    for secret in SECRETS:
        assert secret not in blob
    assert not any(loc.startswith("header.") for loc, _ in spy.seen)
    assert {loc for loc, _ in spy.seen} >= {"json_body.profile.recipient", "json_body.profile.note"}
    assert r["summary"]["ml_fields_excluded_by_policy"] >= 8                              # 5 secret body keys + headers


def test_default_report_contains_no_raw_secret_in_either_mode(tmp_path):
    det = v2_detector()
    p = _capture(tmp_path)
    for report in (analyze(p), analyze(p, ml_detector=det)):
        blob = json.dumps(report, ensure_ascii=False)
        for secret in SECRETS + ("Henrik Larsson",):
            assert secret not in blob, secret
        creds = [f for f in report["findings"] if f["pii_type"] == "CREDENTIAL_OR_TOKEN"]
        assert len(creds) >= 5 and all("***" in f["value"] or set(f["value"]) == {"*"} for f in creds)
        assert all(not f["location"].lower().endswith(tuple(SECRETS)) for f in report["findings"])


def test_no_secret_in_logs_stdout_stderr_or_exception_text(tmp_path, caplog):
    det = v2_detector()
    p = _capture(tmp_path)
    caplog.set_level(logging.DEBUG)
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        analyze(p, ml_detector=det)
    text = caplog.text + out.getvalue() + err.getvalue()
    for secret in SECRETS + ("Henrik Larsson",):
        assert secret not in text


def test_include_values_is_the_only_switch_that_reveals_values(tmp_path):
    """Control experiment: values appear only when explicitly requested (synthetic data), proving the default masking is real."""
    p = _capture(tmp_path)
    assert SECRETS[0] not in json.dumps(analyze(p))
    assert SECRETS[0] in json.dumps(analyze(p, include_values=True))


def _query_form_capture(tmp_path):
    body = f"password={SECRETS[0]}&nick=mint_panda_81"
    req = (b"POST /login?token=" + SECRETS[1].encode() + b"&user=night_owl_77 HTTP/1.1\r\nHost: a\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body.encode())
    return one_request_pcap(tmp_path, req)


def test_recognised_secret_keys_are_excluded_and_masked_in_query_and_form(tmp_path):
    spy = SpyDetector()
    r = analyze(_query_form_capture(tmp_path), ml_detector=spy)
    seen = " ".join(l + " " + t for l, t in spy.seen)
    assert SECRETS[0] not in seen                                                    # form.password: excluded from the model
    assert "query_parameter.user" in seen and "form.nick" in seen                    # non-secret identity fields are still evaluated
    assert SECRETS[0] not in json.dumps(r)
    assert any(f["pii_type"] == "CREDENTIAL_OR_TOKEN" and f["location"] == "form.password" for f in r["findings"])


def test_bare_token_parameter_is_not_recognised_as_a_credential_current_behaviour(tmp_path):
    """OBSERVED GAP F-06: SECRET_KEYS has no bare `token`/`jwt`/`sid`/`passphrase`/`private_key`/`id_token`/`otp`/`pin`.
    `?token=<value>` is neither reported as CREDENTIAL_OR_TOKEN nor excluded from the contextual model's input (local only:
    the default report still does not echo it)."""
    spy = SpyDetector()
    r = analyze(_query_form_capture(tmp_path), ml_detector=spy)
    assert ("query_parameter.token", SECRETS[1]) in spy.seen
    assert not any(f["location"] == "query_parameter.token" for f in r["findings"])
    assert SECRETS[1] not in json.dumps(r)                                          # still masked/absent in the default report


@pytest.mark.xfail(strict=True, reason="QA finding F-06: a bare `token` parameter should be treated as a credential (rules) and excluded from ML")
def test_bare_token_parameter_should_be_a_credential(tmp_path):
    spy = SpyDetector()
    analyze(_query_form_capture(tmp_path), ml_detector=spy)
    assert all(text != SECRETS[1] for _, text in spy.seen)
