"""Independent byte-level oracles for observable HTTP tail loss (F-05)."""
from dataclasses import asdict
import importlib.util
import json
from pathlib import Path
import struct

import pytest

from packet_pii.engine import analyze
from packet_pii.http_extract import parse_http_stream, parse_http_stream_with_spans

GET = b'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
POST = b'POST / HTTP/1.1\r\nContent-Length: 8\r\n\r\n'
CHUNKED = b'POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n'


def inspect(raw):
    diagnostics = []
    spans = parse_http_stream_with_spans(raw, diagnostics=diagnostics)
    assert [span.message for span in spans] == parse_http_stream(raw)
    return spans, [asdict(item) for item in diagnostics]


@pytest.mark.parametrize('raw,reason', [
    (POST, 'http_incomplete_content_length_body'),
    (POST + b'abc', 'http_incomplete_content_length_body'),
    (b'GET / HTTP/1.1', 'http_incomplete_headers'),
    (b'GET / HTTP/1.', 'http_incomplete_headers'),
    (b'GET / HTTP/1.1\r\nHost: exam', 'http_incomplete_headers'),
    (b'GET / HTTP/1.1\r\nHost: example.invalid\r\n', 'http_incomplete_headers'),
    (b'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r', 'http_incomplete_headers'),
    (b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n', 'http_incomplete_headers'),
])
def test_recognizable_incomplete_framing(raw, reason):
    spans, diagnostics = inspect(raw)
    assert spans == []
    assert diagnostics == [{'reason': reason, 'start_offset': 0, 'incomplete': True}]


@pytest.mark.parametrize('tail', [
    b'', b'4', b'4\r', b'4;name=', b'4\r\nab', b'4\r\nabcd',
    b'4\r\nabcd\r', b'4\r\nabcd\r\n', b'4\r\nabcd\r\n0',
    b'4\r\nabcd\r\n0\r\n', b'0\r\n\r',
    b'0\r\nX-Trace: unfinished', b'0\r\nX-Trace: done\r\n',
])
def test_chunked_missing_data_or_terminator(tail):
    spans, diagnostics = inspect(CHUNKED + tail)
    assert spans == []
    assert diagnostics == [{'reason': 'http_incomplete_chunked_framing',
                            'start_offset': 0, 'incomplete': True}]


@pytest.mark.parametrize('raw', [
    POST + b'abcdefgh',
    CHUNKED + b'4;ext="a"\r\nabcd\r\n0\r\nX-Trace: ok\r\n\r\n',
])
def test_each_tail_cut_after_recognizable_start_line_is_incomplete(raw):
    for cut in range(len(b'POST / HTTP/1.1'), len(raw)):
        spans, diagnostics = inspect(raw[:cut])
        assert spans == [], cut
        assert len(diagnostics) == 1 and diagnostics[0]['incomplete'] is True, cut


@pytest.mark.parametrize('raw', [
    GET, POST + b'abcdefgh', CHUNKED + b'4\r\nabcd\r\n0\r\n\r\n',
    CHUNKED + b'4;ext="a"\r\nabcd\r\n0\r\nX-Trace: ok\r\n\r\n',
    b'HTTP/1.1 204 No Content\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd',
])
def test_intact_framing_has_no_diagnostics(raw):
    spans, diagnostics = inspect(raw)
    assert len(spans) == 1
    assert (spans[0].start_offset, spans[0].end_offset) == (0, len(raw))
    assert diagnostics == []


def test_pipelined_request_preserves_first_message_and_tail_offset():
    spans, diagnostics = inspect(GET + POST + b'abc')
    assert len(spans) == 1
    assert spans[0].message.start_line == 'GET / HTTP/1.1'
    assert (spans[0].start_offset, spans[0].end_offset) == (0, len(GET))
    assert diagnostics == [{'reason': 'http_incomplete_content_length_body',
                            'start_offset': len(GET), 'incomplete': True}]


@pytest.mark.parametrize('raw,reason', [
    (b'\x16\x03\x01not-http', 'http_unparseable_tail'),
    (b'GET / HTTP/1.1\r\nBad Header: x', 'http_unparseable_tail'),
    (CHUNKED + b'ZZ\r\n', 'http_invalid_chunked_framing'),
    (CHUNKED + b'4\r\nabcdX', 'http_invalid_chunked_framing'),
    (b'HTTP/1.0 200 OK\r\n\r\nclose-delimited body',
     'http_close_delimited_body_uninspected'),
])
def test_unknown_or_invalid_tail_is_not_claimed_to_be_packet_loss(raw, reason):
    _, diagnostics = inspect(raw)
    assert diagnostics == [{'reason': reason, 'start_offset': 0, 'incomplete': False}]


@pytest.mark.parametrize('raw', [
    b'HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nx',
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nab',
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n',
])
def test_response_body_framing_requires_request_method_context(raw):
    spans, diagnostics = inspect(raw)
    assert spans == []  # Existing parser omission is retained, not claimed fixed.
    assert diagnostics == [{'reason': 'http_response_body_framing_unknown',
                            'start_offset': 0, 'incomplete': False}]


def test_diagnostics_do_not_retain_sensitive_headers_paths_or_body():
    raw = (b'POST /private@example.invalid HTTP/1.1\r\n'
           b'Authorization: secret-token\r\nContent-Length: 100\r\n\r\nprivate-body')
    _, diagnostics = inspect(raw)
    assert json.dumps(diagnostics) == ('[{"reason": "http_incomplete_content_length_body", '
                                       '"start_offset": 0, "incomplete": true}]')


def capture(tmp_path, entries):
    generator = Path(__file__).resolve().parents[1] / 'examples' / 'generate_demo.py'
    spec = importlib.util.spec_from_file_location('f05_fixture', generator)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = tmp_path / 'tail.pcap'
    with target.open('wb') as stream:
        stream.write(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1))
        for i, entry in enumerate(entries):
            seq, data, flags, *reverse = entry
            endpoints = ('198.51.100.20', 80, '192.0.2.10', 50001) if reverse and reverse[0] else (
                '192.0.2.10', 50001, '198.51.100.20', 80)
            frame = module.tcp_frame(*endpoints, seq, data, flags)
            stream.write(struct.pack('<IIII', i + 1, 0, len(frame), len(frame)) + frame)
    return target


def test_missing_final_segment_without_fin_marks_report_incomplete(tmp_path):
    report = analyze(capture(tmp_path, [(100, POST + b'abc', 0x18)]))
    assert report['summary']['http_messages'] == 0
    assert report['summary']['stream_gaps'] == 0  # No invented TCP byte gap.
    assert report['summary']['http_incomplete_streams'] == 1
    assert report['summary']['analysis_incomplete'] is True
    flow = report['flows'][0]
    assert flow['flow_id'] == 'flow_0001'
    diagnostic = flow['http_diagnostics'][0]
    assert diagnostic['reason'] == 'http_incomplete_content_length_body'
    assert diagnostic['start_offset'] == 0
    assert diagnostic['source_ip'] == '192.0.2.10'


@pytest.mark.parametrize('fin', [False, True])
def test_intact_request_does_not_require_fin(tmp_path, fin):
    packets = [(100, GET, 0x18)]
    if fin:
        packets.append((100 + len(GET), b'', 0x11))
    report = analyze(capture(tmp_path, packets))
    assert report['summary']['http_messages'] == 1
    assert report['summary']['http_incomplete_streams'] == 0
    assert report['summary']['stream_gaps'] == 0
    assert report['summary']['analysis_incomplete'] is False


@pytest.mark.parametrize('fin', [False, True])
def test_close_delimited_response_is_uncertain_without_claiming_corruption(tmp_path, fin):
    raw = b'HTTP/1.0 200 OK\r\n\r\nlegitimate close-delimited body'
    packets = [(100, raw, 0x18)]
    if fin:
        packets.append((100 + len(raw), b'', 0x11))
    report = analyze(capture(tmp_path, packets))
    assert report['summary']['http_messages'] == 1
    assert report['summary']['http_incomplete_streams'] == 0
    assert report['summary']['http_uncertain_streams'] == 1
    assert report['summary']['analysis_incomplete'] is False


def test_missing_internal_tcp_segment_still_has_observed_gap(tmp_path):
    report = analyze(capture(tmp_path, [(100, POST + b'ab', 0x18),
                                        (100 + len(POST) + 6, b'gh', 0x18)]))
    assert report['summary']['stream_gaps'] == 1
    assert report['summary']['analysis_incomplete'] is True
    assert report['summary']['http_messages'] == 0


def test_retransmission_does_not_create_spurious_http_tail(tmp_path):
    report = analyze(capture(tmp_path, [(100, GET, 0x18), (100, GET, 0x18)]))
    assert report['summary']['http_messages'] == 1
    assert report['summary']['http_incomplete_streams'] == 0
    assert report['summary']['analysis_incomplete'] is False


@pytest.mark.parametrize('method', [b'HEAD', b'CONNECT', b'GET'])
@pytest.mark.parametrize('framing', [b'Content-Length: 1234', b'Transfer-Encoding: chunked'])
def test_response_without_body_does_not_prove_damage_without_parser_context(tmp_path, method, framing):
    target = b'example.invalid:443' if method == b'CONNECT' else b'/'
    request = method + b' ' + target + b' HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
    response = b'HTTP/1.1 200 OK\r\n' + framing + b'\r\n\r\n'
    report = analyze(capture(tmp_path, [
        (100, request, 0x18), (900, response, 0x18, True),
        (100 + len(request), b'', 0x11),
        (900 + len(response), b'', 0x11, True),
    ]))
    assert report['summary']['stream_gaps'] == 0
    assert report['summary']['http_incomplete_streams'] == 0
    assert report['summary']['http_uncertain_streams'] == 1
    assert report['summary']['analysis_incomplete'] is False
    assert report['flows'][0]['http_diagnostics'][0]['reason'] == 'http_response_body_framing_unknown'
