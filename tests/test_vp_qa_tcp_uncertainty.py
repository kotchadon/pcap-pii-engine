"""Task B - TCP reassembly uncertainty as seen by the report (black-box, rules-only engine; synthetic fictional PCAPs).

QA does not own or modify the reassembler. These tests record what the *report* says (counts, gap flag, analysis_incomplete)
when the capture is imperfect. Behaviour that silently loses evidence is asserted as observed and paired with a strict xfail
describing what a reviewer should expect; fixing it requires the networking owner.
"""
from __future__ import annotations

import socket
import struct

import pytest

from packet_pii.engine import analyze
from test_vp_qa_support import (build_pcap, conversation, ok_response, one_request_pcap, post_json, v2_detector, write_pcap)

REQ = post_json({"full_name": "Maria Gonzalez", "username": "night_owl_77", "email": "maria@example.test", "note": "x" * 200})
SEG = 60
N = -(-len(REQ) // SEG)           # 7 segments
GROUND = {("PERSON_NAME_CANDIDATE", 2), ("USERNAME", 1), ("EMAIL", 1)}


def _sig(report):
    return sorted((f["pii_type"], f["location"]) for f in report["findings"])


def _summary(report):
    s = report["summary"]
    return s["http_messages"], s["rules_findings"], s["stream_gaps"], s["analysis_incomplete"]


@pytest.fixture(scope="module")
def baseline(tmp_path_factory):
    return analyze(one_request_pcap(tmp_path_factory.mktemp("base"), REQ, seg=SEG))


def test_baseline_segmented_capture(baseline):
    assert _summary(baseline) == (2, 3, 0, False)
    assert _sig(baseline) == [("EMAIL", "json_body.email"), ("PERSON_NAME_CANDIDATE", "json_body.full_name"), ("USERNAME", "json_body.username")]


@pytest.mark.parametrize("label,kw", [
    ("out_of_order", dict(order=[2, 0, 1] + list(range(3, N)))),
    ("fully_reversed", dict(order=list(reversed(range(N))))),
    ("duplicates_and_retransmits", dict(dup={0, 3, N - 1})),
    ("reordered_and_duplicated", dict(order=[4, 1, 0, 2, 3, 6, 5], dup={1, 5})),
    ("identical_overlap_replay", dict(extra_segments=[(30, REQ[30:100])])),
])
def test_benign_reordering_duplication_overlap_changes_nothing(tmp_path, baseline, label, kw):
    r = analyze(one_request_pcap(tmp_path, REQ, seg=SEG, **kw))
    assert _summary(r) == _summary(baseline) and _sig(r) == _sig(baseline), label


@pytest.mark.parametrize("dropped", [0, 3])
def test_missing_head_or_middle_segment_is_flagged_incomplete_and_evidence_is_lost(tmp_path, dropped):
    r = analyze(one_request_pcap(tmp_path, REQ, seg=SEG, drop={dropped}))
    s = r["summary"]
    assert s["stream_gaps"] == 1 and s["analysis_incomplete"] is True
    assert "Capture corruption/truncation or missing TCP data: analysis is incomplete" in r["limitations"]
    assert not [f for f in r["findings"] if f["http_message_type"] == "request"]          # the damaged request yields nothing - never partial guesses


def test_missing_tail_segment_is_silent_current_behaviour(tmp_path):
    """OBSERVED DEFECT F-05: losing the LAST request segment drops the whole request with stream_gaps=0 and
    analysis_incomplete=False - the report looks clean although PII-bearing traffic vanished."""
    r = analyze(one_request_pcap(tmp_path, REQ, seg=SEG, drop={N - 1}))
    s = r["summary"]
    assert (s["http_messages"], s["rules_findings"], s["stream_gaps"], s["analysis_incomplete"]) == (1, 0, 0, False)   # only the response survives


@pytest.mark.xfail(strict=True, reason="QA finding F-05: an unterminated HTTP message at end of stream should set analysis_incomplete")
def test_missing_tail_segment_should_set_analysis_incomplete(tmp_path):
    r = analyze(one_request_pcap(tmp_path, REQ, seg=SEG, drop={N - 1}))
    assert r["summary"]["analysis_incomplete"] is True


def test_conflicting_overlapping_payload_is_flagged_and_excluded_whatever_the_arrival_order(tmp_path):
    """Upstream hardening of QA finding F-02: the conflicting region is no longer resolved by arrival order. Neither candidate
    value is reported, the flow is flagged, and both arrival orders give the same (empty) result."""
    off = REQ.index(b"Maria")
    alt = REQ[:off] + b"Marta" + REQ[off + 5:]
    a = analyze(one_request_pcap(tmp_path, REQ, extra_segments=[(off - 4, alt[off - 4:off + 20])], name="a.pcap"), include_values=True)
    first = conversation(0, alt, b"")[3]
    genuine = conversation(0, REQ, ok_response())
    b = analyze(build_pcap(tmp_path / "b.pcap", [[first] + genuine]), include_values=True)
    for r in (a, b):
        assert r["summary"]["analysis_incomplete"] is True and r["summary"]["stream_gaps"] == 1       # conflict is surfaced
        assert not [f for f in r["findings"] if f["pii_type"] == "PERSON_NAME_CANDIDATE"]          # neither candidate is guessed
    assert _sig(a) == _sig(b)


def test_sequence_number_wraparound_is_reassembled(tmp_path, baseline):
    r = analyze(one_request_pcap(tmp_path, REQ, seg=SEG, cseq=0xFFFFFFFF - 100))
    assert _summary(r) == _summary(baseline) and _sig(r) == _sig(baseline)
    assert not any("wraparound" in lim for lim in r["limitations"])      # F-11 resolved upstream: the stale generic caveat is gone


def test_reused_four_tuple_is_split_into_separate_flows_and_both_users_are_found(tmp_path):
    """Upstream hardening of QA finding F-01: a reused 4-tuple (second SYN, fresh sequence space) is split into two flows."""
    c1 = conversation(0, post_json({"username": "first_user_11"}), ok_response(), cseq=1000)
    c2 = conversation(0, post_json({"username": "second_user_22"}), ok_response(), cseq=900000, t0=1_760_000_100.0)
    r = analyze(build_pcap(tmp_path / "reuse.pcap", [c1, c2]), include_values=True)
    s = r["summary"]
    assert (s["flows_processed"], s["http_messages"], s["analysis_incomplete"]) == (2, 4, False)
    assert sorted(f["value"] for f in r["findings"] if f["pii_type"] == "USERNAME") == ["first_user_11", "second_user_22"]


def test_non_http_tcp_and_non_tcp_packets_are_counted_not_guessed(tmp_path):
    tls = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + bytes(range(180))
    base = conversation(0, tls, b"")
    udp_payload = b"POST /x HTTP/1.1\r\n\r\n"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(udp_payload), 1, 0x4000, 64, 17, 0, socket.inet_aton("192.0.2.99"), socket.inet_aton("198.51.100.99"))
    udp = b"\x02" * 6 + b"\x03" * 6 + b"\x08\x00" + ip + struct.pack("!HHHH", 5353, 5353, 8 + len(udp_payload), 0) + udp_payload
    v6 = b"\x02" * 6 + b"\x03" * 6 + b"\x86\xdd" + bytes(60)
    r = analyze(write_pcap(tmp_path / "mix.pcap", base + [(1_760_000_050.0, udp), (1_760_000_051.0, v6)]))
    s = r["summary"]
    assert s["http_messages"] == 0 and s["potential_leaks"] == 0 and s["non_tcp_or_unsupported_packets"] == 2
    assert "Encrypted HTTPS payloads cannot be inspected without decryption" in r["limitations"]


def test_ip_fragment_is_counted_unsupported_but_not_flagged_incomplete(tmp_path):
    """Observed: an IPv4 fragment is dropped as 'unsupported' (counted) and the request is lost, yet analysis_incomplete stays False."""
    frames = conversation(0, REQ, ok_response())
    fb = bytearray(frames[3][1]); fb[14 + 6] = 0x20; fb[14 + 7] = 0x00           # set the More-Fragments flag on the data packet
    frames[3] = (frames[3][0], bytes(fb))
    r = analyze(build_pcap(tmp_path / "frag.pcap", [frames]))
    s = r["summary"]
    assert s["non_tcp_or_unsupported_packets"] == 1 and s["rules_findings"] == 0 and s["analysis_incomplete"] is False
    assert any("No IP fragmentation" in lim for lim in r["limitations"])              # disclosed generically


def test_empty_and_truncated_pcap_files(tmp_path):
    empty = analyze(write_pcap(tmp_path / "e.pcap", []))
    assert empty["summary"]["packets_captured"] == 0 and empty["findings"] == []
    good = one_request_pcap(tmp_path, REQ, seg=SEG, name="g.pcap").read_bytes()
    t = tmp_path / "t.pcap"; t.write_bytes(good[:-25])                                # cut the last record
    r = analyze(t)
    assert r["summary"]["capture_truncated_records"] >= 1 and r["summary"]["analysis_incomplete"] is True


def test_hybrid_mode_does_not_launder_an_incomplete_capture(tmp_path):
    """With the real model the incomplete-analysis flag must be identical to rules-only; ML findings never clear it."""
    det = v2_detector()
    p = one_request_pcap(tmp_path, REQ, seg=SEG, drop={3})
    rules, hyb = analyze(p), analyze(p, ml_detector=det)
    for k in ("analysis_incomplete", "stream_gaps", "http_messages", "packets_captured"):
        assert rules["summary"][k] == hyb["summary"][k]
    assert hyb["summary"]["analysis_incomplete"] is True
