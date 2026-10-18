"""Task B - bounded adversarial correctness checks on the live engine (rules-only vs hybrid) with the real V2 ensemble.

All data is fictional. Outcomes of the research model are *characterised as observed* (pinned to checkpoint
bilstm-v2-d1f9e9fb9a2b, skipped otherwise); they are neither forced to be positive nor hidden when wrong.
``xfail(strict=True)`` marks behaviour a reviewer would expect but which is currently NOT delivered - if another engineer fixes
it the strict xfail turns red and the document must be updated.
"""
from __future__ import annotations

import gzip
import json

import pytest

from packet_pii.engine import analyze
from packet_pii.ml import MlValidationError
from test_vp_qa_support import (V2_VERSION, ml_findings, ok_response, one_request_pcap, post_json, rule_findings, v2_detector)


@pytest.fixture(scope="module")
def det():
    return v2_detector()


def _pinned(det):
    if det.model_version != V2_VERSION:
        pytest.skip("characterisation pinned to " + V2_VERSION)


def _both(tmp_path, request, det, name="a.pcap", include_values=False, **kw):
    p = one_request_pcap(tmp_path, request, name=name, **kw)
    return analyze(p, include_values=include_values), analyze(p, include_values=include_values, ml_detector=det)


def _flagged(report):
    return {f["location"].removeprefix("json_body."): f["pii_type"] for f in ml_findings(report)}


# ---------------------------------------------------------------- false positives: companies, cities, products
NEGATIVES = {
    "orgs": {"company": "Wells Fargo", "employer": "Morgan Stanley", "publisher": "Harper Collins", "billed_to": "Johnson & Johnson", "vendor": "Smith & Nephew"},
    "cities": {"city": "Jackson", "location": "Lincoln", "origin": "Austin", "destination": "Madison", "venue": "Charlotte"},
    "products": {"name": "AirLoom Mini", "product_name": "Nimbus 2000", "title": "Pixel Frame 8", "device": "Kestrel Drone"},
    "misc": {"currency": "AUD", "status": "created", "country": "Australia", "unit": "kg", "note": "Please call back tomorrow", "city_code": "PER"},
}
OBSERVED_FP = {"employer": "PERSON_NAME", "publisher": "PERSON_NAME", "origin": "PERSON_NAME", "destination": "PERSON_NAME", "name": "PERSON_NAME", "currency": "PERSON_NAME"}


def test_company_and_city_false_positives_are_visible_and_labelled_experimental(tmp_path, det):
    _pinned(det)
    flagged, n_fields = {}, 0
    for i, (group, obj) in enumerate(NEGATIVES.items()):
        rules, hyb = _both(tmp_path, post_json(obj), det, name=f"neg{i}.pcap")
        assert rule_findings(hyb) == [] and rules["summary"]["potential_leaks"] == 0          # rules: no false alarm here
        flagged.update(_flagged(hyb)); n_fields += len(obj)
        for f in ml_findings(hyb):
            assert f["confidence_type"] == "uncalibrated_model_score" and f["detector"] == "bilstm"
    assert flagged == OBSERVED_FP                                                              # 6 of 20 deliberately hard negatives flagged
    assert n_fields == 20 and len(flagged) / n_fields == pytest.approx(0.30)
    # Not flagged (correct): Wells Fargo, Johnson & Johnson, Smith & Nephew, Jackson, Lincoln, Charlotte, Nimbus 2000, ...
    for key in ("company", "billed_to", "vendor", "city", "location", "venue", "product_name", "title", "device", "country", "unit", "status", "note", "city_code"):
        assert key not in flagged


# ---------------------------------------------------------------- unusual field names
def test_unusual_person_and_username_field_names_rules_miss_model_finds(tmp_path, det):
    _pinned(det)
    obj = {"attendee": "Maria Gonzalez", "gamertag": "shadow_fox_91", "acct_holder": "Henrik Larsson", "screen_name": "mint.panda"}
    rules, hyb = _both(tmp_path, post_json(obj), det)
    assert rules["summary"]["potential_leaks"] == 0                                           # keyword rules know none of these keys
    assert _flagged(hyb) == {"attendee": "PERSON_NAME", "gamertag": "USERNAME", "acct_holder": "PERSON_NAME", "screen_name": "USERNAME"}
    assert {f["detector"] for f in hyb["findings"]} == {"bilstm"} and hyb["summary"]["rules_findings"] == 0


def test_generic_or_cryptic_keys_partially_found(tmp_path, det):
    _pinned(det)
    _, hyb = _both(tmp_path, post_json({"x1": "Henrik Larsson", "v": "mint_panda_81", "data": "Ingrid Solberg", "u": "quiet.storm.4"}), det)
    assert _flagged(hyb) == {"x1": "PERSON_NAME", "data": "PERSON_NAME"}                       # `v` and `u` handles are missed


# ---------------------------------------------------------------- Unicode / non-English
UNICODE = {"recipient": "Σοφία Παπαδοπούλου", "name": "김민준", "contact": "Øystein Åsen", "x": "محمد العلي", "user": "josé_ñandú_77", "who": "Анастасия Петрова"}


def test_unicode_names_offsets_are_code_points_and_values_roundtrip(tmp_path, det):
    _pinned(det)
    req = post_json(UNICODE)
    _, hyb = _both(tmp_path, req, det, include_values=True)
    fields = {k: v for k, v in UNICODE.items()}
    got = {f["location"].removeprefix("json_body."): f for f in ml_findings(hyb)}
    assert set(got) == set(UNICODE)                                                           # all six found (pinned)
    for key, f in got.items():
        text = fields[key]
        assert f["value"] == text[f["span_start"]:f["span_end"]]                              # offsets index code points of the exact field
        assert 0 <= f["span_start"] < f["span_end"] <= len(text)
        assert f["value"] == text, key                                                       # whole value in all six cases


def test_masked_unicode_output_never_contains_the_full_value(tmp_path, det):
    _, hyb = _both(tmp_path, post_json(UNICODE), det)
    blob = json.dumps(hyb, ensure_ascii=False)
    for v in UNICODE.values():
        assert v not in blob


def test_emoji_inside_a_username_truncates_the_span_known_limitation(tmp_path, det):
    _pinned(det)
    _, hyb = _both(tmp_path, post_json({"user": "ñandú_🙂_77", "recipient": "🙂 Henrik Larsson 🙂"}), det, include_values=True)
    got = {f["location"].removeprefix("json_body."): f["value"] for f in ml_findings(hyb)}
    assert got["recipient"] == "Henrik Larsson"                                              # emoji correctly outside the span
    assert got["user"] == "ñandú_"                                                           # tokenizer splits at the emoji: partial handle


# ---------------------------------------------------------------- known model misses / weak formats
def test_known_weak_formats_multi_person_list_csv_and_chat_prefix(tmp_path, det):
    _pinned(det)
    _, a = _both(tmp_path, post_json({"panel": "Interview panel: Henrik Larsson, Ingrid Solberg, Tomas Berg."}), det, name="a.pcap", include_values=True)
    assert [f["value"] for f in ml_findings(a)] == ["Henrik Larsson"]                        # 2nd and 3rd person missed
    _, b = _both(tmp_path, post_json({"log": "[12:04] <mint_panda_81> anyone around?"}), det, name="b.pcap", include_values=True)
    vals = {(f["pii_type"], f["value"]) for f in ml_findings(b)}
    assert ("USERNAME", "mint_panda_81") in vals and ("PERSON_NAME", "anyone around") in vals   # right handle, plus a false positive
    _, c = _both(tmp_path, post_json({"data": "id,name,city\n42,Henrik Larsson,Perth"}), det, name="c.pcap")
    low = [f["confidence"] for f in ml_findings(c)]
    assert low and max(low) < 0.6                                                              # found only at a low raw score


def test_lowercase_and_uppercase_variants_are_still_found(tmp_path, det):
    _pinned(det)
    _, hyb = _both(tmp_path, post_json({"recipient": "henrik larsson", "user": "MINT_PANDA_81"}), det)
    assert _flagged(hyb) == {"recipient": "PERSON_NAME", "user": "USERNAME"}


# ---------------------------------------------------------------- malformed HTTP
def _chunked(body: bytes) -> bytes:
    return (b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n" + body)


MALFORMED = {
    "binary_garbage": b"\x00\x01\x02not http at all\xff\xfe",
    "content_length_too_big": b'POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 9999\r\n\r\n{"recipient":"Henrik Larsson"}',
    "truncated_json": post_json(b'{"recipient": "Henrik Larsson", "x": '),
    "bad_chunk_size": _chunked(b'ZZ\r\n{"recipient":"Henrik Larsson"}\r\n0\r\n\r\n'),
    "negative_chunk_size": _chunked(b'-5\r\n{"recipient":"Henrik Larsson"}\r\n0\r\n\r\n'),
    "header_without_colon": b'POST /x HTTP/1.1\r\nHost: a\r\nBadHeaderLine\r\nContent-Length: 2\r\n\r\n{}',
    "conflicting_content_length": b'POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nContent-Length: 40\r\n\r\n{"recipient":"Henrik Larsson"}',
    "nul_in_header": b'POST /x HTTP/1.1\r\nHost: a\x00b\r\nContent-Length: 2\r\n\r\n{}',
    "huge_header_line": b"POST /x HTTP/1.1\r\nHost: a\r\nX-Pad: " + b"A" * 60000 + b"\r\nContent-Length: 2\r\n\r\n{}",
    "bare_lf_line_endings": b'POST /x HTTP/1.1\nHost: a\nContent-Type: application/json\nContent-Length: 28\n\n{"recipient":"Henrik Larsson"}',
    "bom_and_invalid_utf8": post_json(b'\xef\xbb\xbf{"recipient":"Henrik Lars\xe9on"}'),
    "gzip_corrupt": b'POST /x HTTP/1.1\r\nHost: a\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n\x1f\x8b\x08garbage!!',
    "gzip_bomb_like": (lambda z: b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\nContent-Length: "
                       + str(len(z)).encode() + b"\r\n\r\n" + z)(gzip.compress(b'{"recipient":"' + b"A" * 8_000_000 + b'"}')),
    "lone_surrogate_escapes": post_json(b'{"recipient":"Henrik \\ud800 Larsson","user":"bob\\udfff77"}'),
    "deeply_nested_json": post_json(b'{"a":' * 60 + b'"Henrik Larsson"' + b"}" * 60),
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_http_never_crashes_never_leaks_and_rules_are_unchanged(tmp_path, det, name):
    rules, hyb = _both(tmp_path, MALFORMED[name], det, name=f"{name}.pcap")
    assert rule_findings(hyb) == rule_findings(rules)                                          # ML never alters rule results
    blob = json.dumps(hyb, ensure_ascii=False)
    assert "Henrik Larsson" not in blob                                                        # default report is masked
    s = hyb["summary"]
    assert s["potential_leaks"] == len(hyb["findings"]) and s["ml_findings"] == len(ml_findings(hyb))
    for f in ml_findings(hyb):
        assert 0 <= f["span_start"] < f["span_end"]


def test_garbage_input_produces_no_fabricated_findings(tmp_path, det):
    for name in ("binary_garbage", "header_without_colon", "nul_in_header", "huge_header_line", "truncated_json"):
        _, hyb = _both(tmp_path, MALFORMED[name], det, name=f"{name}2.pcap")
        assert hyb["findings"] == [], name


# ---------------------------------------------------------------- hybrid-only robustness defects found by QA
def test_overlong_json_key_is_skipped_counted_and_flagged_not_fatal(tmp_path, det):
    """F-03 fixed: a >1024-char JSON key no longer aborts hybrid analysis. The field is skipped and counted, the analysis is
    flagged incomplete (never published as fully covered), and the remaining field is still evaluated."""
    req = post_json({"k" * 2000: "Henrik Larsson", "recipient": "Ingrid Solberg"})
    p = one_request_pcap(tmp_path, req)
    assert analyze(p)["summary"]["http_messages"] == 2                                       # rules-only completes (unchanged)
    r = analyze(p, ml_detector=det)
    s = r["summary"]
    assert s["ml_fields_skipped"] == 1 and s["ml_incomplete"] is True and s["analysis_incomplete"] is True
    assert "k" * 100 not in json.dumps(r)                                                    # the oversized key is never echoed
    assert s["ml_fields_evaluated"] >= 1


def test_oversized_field_value_is_skipped_and_counted_not_truncated(tmp_path, det):
    req = post_json({"recipient": "Henrik Larsson " * 5000, "contact": "Ingrid Solberg"})     # ~75k chars > 65,536
    r = analyze(one_request_pcap(tmp_path, req), ml_detector=det)
    s = r["summary"]
    assert s["ml_fields_skipped"] == 1
    assert "ML processing limits skipped eligible fields: hybrid analysis is incomplete" in r["limitations"]
    assert s["analysis_incomplete"] is True and s["ml_incomplete"] is True
    assert [f["location"] for f in ml_findings(r)] == ["json_body.contact"]


# ---------------------------------------------------------------- rules-engine finding on 'author' (QA finding F-04)
def test_author_key_is_not_a_credential_and_reaches_the_model(tmp_path, det):
    """F-04 fixed: credential keys are matched as tokens, so `author`/`authority`/`authentic` are ordinary fields. They are
    not labelled CREDENTIAL_OR_TOKEN and are eligible for contextual inference (whether the model flags them is a
    characterisation of V2, not asserted here)."""
    rules, hyb = _both(tmp_path, post_json({"author": "Ingrid Solberg", "authority": "city council", "authentic": "yes"}), det)
    assert [f["pii_type"] for f in rule_findings(rules)] == []
    assert hyb["summary"]["ml_fields_evaluated"] == 4       # three request fields (previously excluded) + the response field


@pytest.mark.parametrize("key", ["auth", "x-auth-token", "authorization", "api_key", "apiKey", "client_secret", "passwordHash", "id_token",
                                 "session_id", "refresh_token", "jwt", "otp", "token"])
def test_genuine_credential_keys_are_still_credentials(tmp_path, det, key):
    rules, hyb = _both(tmp_path, post_json({key: "fictional-secret-value-123"}), det)
    assert [f["pii_type"] for f in rule_findings(rules)] == ["CREDENTIAL_OR_TOKEN"]
    assert "fictional-secret-value-123" not in json.dumps(hyb)


@pytest.mark.parametrize("key", ["token_type", "max_tokens", "secretary", "sidebar", "pinned", "www-authenticate"])
def test_credential_lookalike_keys_are_not_credentials(tmp_path, det, key):
    rules, _ = _both(tmp_path, post_json({key: "Bearer"}), det)
    assert [f["pii_type"] for f in rule_findings(rules)] == []


# ---------------------------------------------------------------- rules-only vs hybrid
def test_hybrid_is_a_strict_superset_of_rules_only(tmp_path, det):
    obj = {"full_name": "Fatima Khan", "email": "fk@example.test", "username": "violet_dev22", "attendee": "Maria Gonzalez", "password": "fictional-pw-9"}
    rules, hyb = _both(tmp_path, post_json(obj), det)
    assert rule_findings(hyb) == rule_findings(rules) == rules["findings"]
    assert hyb["summary"]["potential_leaks"] == rules["summary"]["potential_leaks"] + hyb["summary"]["ml_findings"]
    assert hyb["summary"]["ml_findings"] >= 1 and all(f["detector"] == "bilstm" for f in ml_findings(hyb))
    assert rules["metadata"]["detection_method"] == "rules_only" and hyb["metadata"]["detection_method"] == "rules_plus_bilstm"


# ---------------------------------------------------------------- unsupported encodings / protocols are silent, not flagged (QA finding F-09)
def _enc_request(encoding: bytes, body: bytes) -> bytes:
    return (b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nContent-Encoding: " + encoding
            + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


@pytest.mark.parametrize("encoding,body", [
    (b"br", b'{"recipient":"Henrik Larsson","email":"hl@example.test"}'),        # brotli not implemented: bytes are not decoded
    (b"zstd", b'{"recipient":"Henrik Larsson","email":"hl@example.test"}'),
    (b"gzip", b'{"recipient":"Henrik Larsson","email":"hl@example.test"}'),      # declared gzip but plain text: undecodable
])
def test_undecodable_content_encodings_yield_no_findings_but_are_counted_and_flagged(tmp_path, det, encoding, body):
    """F-09 fixed: a body that exists but cannot be decoded is still never guessed at, but is now counted by reason and the
    analysis is flagged incomplete instead of looking clean."""
    rules, hyb = _both(tmp_path, _enc_request(encoding, body), det, name=f"{encoding.decode()}.pcap")
    reason = "undecodable_body" if encoding == b"gzip" else "unsupported_content_encoding"
    for r in (rules, hyb):
        assert [f for f in r["findings"] if f["http_message_type"] == "request"] == []
        assert r["summary"]["analysis_incomplete"] is True
        assert r["summary"]["http_bodies_not_inspected"] == 1
        assert r["summary"]["http_bodies_not_inspected_by_reason"] == {reason: 1}
        assert any("present but not inspected" in lim for lim in r["limitations"])


def test_decodable_and_empty_bodies_are_not_reported_as_skipped(tmp_path, det):
    rules, _ = _both(tmp_path, _enc_request(b"identity", b'{"recipient":"Henrik Larsson"}'), det, name="id.pcap")
    empty, _ = _both(tmp_path, _enc_request(b"br", b""), det, name="empty.pcap")
    assert rules["summary"]["http_bodies_not_inspected"] == 0 and empty["summary"]["http_bodies_not_inspected"] == 0


def test_http2_prior_knowledge_preface_is_not_parsed_and_is_disclosed(tmp_path, det):
    h2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + bytes([0, 0, 18, 4, 0, 0, 0, 0, 0]) + b"\x00" * 18
    _, hyb = _both(tmp_path, h2, det, name="h2.pcap", response=b"")
    assert hyb["summary"]["http_messages"] == 0 and hyb["findings"] == []
    assert hyb["summary"]["http2_streams_not_decoded"] == 1 and hyb["summary"]["analysis_incomplete"] is True   # F-09: counted, not silent
    assert "HTTP/2 and HTTP/3 not decoded; incomplete streams are ignored" in hyb["limitations"]
