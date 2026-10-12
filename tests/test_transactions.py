"""Synthetic-only tests for message provenance and conservative HTTP pairing."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct

from packet_pii.engine import analyze, safe_http_start_line
from packet_pii.http_extract import parse_http_stream, parse_http_stream_with_spans

DEMO_PATH = Path(__file__).resolve().parents[1] / 'examples' / 'generate_demo.py'
spec = importlib.util.spec_from_file_location('safe_synthetic_capture', DEMO_PATH)
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)
CLIENT = '192.0.2.10'
SERVER = '198.51.100.20'


def write_capture(path, entries):
    """Write controlled fake-PII network packets to a PCAP."""
    with path.open('wb') as output:
        output.write(b'\xd4\xc3\xb2\xa1')
        output.write(struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1))
        for ts, src, sport, dst, dport, seq, data in entries:
            frame = demo.tcp_frame(src, sport, dst, dport, seq, data)
            second = int(ts)
            us = int(round((ts - second) * 1_000_000))
            output.write(struct.pack('<IIII', second, us, len(frame), len(frame)))
            output.write(frame)


def req(path, email):
    payload = f'{{"email":"{email}"}}'.encode()
    return (f'POST {path} HTTP/1.1\r\nHost: example.invalid\r\n'
            f'Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n').encode() + payload


def res(email, status=200):
    payload = f'{{"email":"{email}"}}'.encode()
    return (f'HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n'
            f'Content-Length: {len(payload)}\r\n\r\n').encode() + payload


def outgoing(ts, seq, payload, port=50123):
    return (ts, CLIENT, port, SERVER, 80, seq, payload)


def incoming(ts, seq, payload, port=50123):
    return (ts, SERVER, 80, CLIENT, port, seq, payload)


def email_findings(report):
    return [f for f in report['findings'] if f['pii_type'] == 'EMAIL']


def test_http_spans_track_original_byte_offsets():
    first = req('/a', 'one@example.invalid')
    second = req('/b', 'two@example.invalid')
    spans = parse_http_stream_with_spans(first + second)
    assert [(s.start_offset, s.end_offset) for s in spans] == [
        (0, len(first)), (len(first), len(first) + len(second)),
    ]
    assert [s.message for s in spans] == parse_http_stream(first + second)


def test_existing_demo_correlates_request_and_response_and_records_payload_time(tmp_path):
    cap = tmp_path / 'demo.pcap'
    demo.write_pcap(cap)
    report = analyze(cap)
    assert report['summary']['http_transactions'] == 1
    assert report['summary']['unpaired_requests'] == 0
    assert report['summary']['unpaired_responses'] == 0
    findings = report['findings']
    request = next(f for f in findings if f['location'] == 'json_body.password')
    response = next(f for f in findings if f['source_port'] == 80)
    assert request['http_request_id'] == response['http_request_id']
    assert request['http_message_id'] != response['http_message_id']
    assert request['http_message_type'] == 'request'
    assert response['http_message_type'] == 'response'
    # Request SYN timestamp=1.00 and second segment=1.10; the segment
    # containing the first byte of the request starts at 1.11.
    assert request['timestamp'] == '1970-01-01T00:00:01.110000+00:00'
    assert response['timestamp'] == '1970-01-01T00:00:01.300000+00:00'


def test_two_pipelined_requests_correlate_fifo(tmp_path):
    r1, r2 = req('/1', 'first@example.invalid'), req('/2', 'second@example.invalid')
    a1, a2 = res('reply1@example.invalid'), res('reply2@example.invalid')
    cap = tmp_path / 'pipelining.pcap'
    write_capture(cap, [
        outgoing(10, 500, r1), outgoing(11, 500 + len(r1), r2),
        incoming(12, 1500, a1), incoming(13, 1500 + len(a1), a2),
    ])
    report = analyze(cap)
    assert report['summary']['http_messages'] == 4
    assert report['summary']['http_transactions'] == 2
    items = email_findings(report)
    assert len(items) == 4
    expected = ['flow_0001_req_0001', 'flow_0001_req_0002']
    req_items = [f for f in items if f['http_message_type'] == 'request']
    res_items = [f for f in items if f['http_message_type'] == 'response']
    assert [x['http_request_id'] for x in req_items] == expected
    assert [x['http_request_id'] for x in res_items] == expected
    assert len({f['http_message_id'] for f in items}) == 4


def test_interim_response_does_not_consume_request(tmp_path):
    request = req('/start', 'first@example.invalid')
    informational = b'HTTP/1.1 100 Continue\r\n\r\n'
    completed = res('ok@example.invalid')
    cap = tmp_path / 'interim.pcap'
    write_capture(cap, [
        outgoing(1, 1000, request),
        incoming(2, 2000, informational + completed),
    ])
    report = analyze(cap)
    assert report['summary']['http_messages'] == 3
    assert report['summary']['http_transactions'] == 1
    assert report['summary']['unpaired_requests'] == 0
    assert report['summary']['unpaired_responses'] == 0
    assert {f['http_request_id'] for f in report['findings']} == {'flow_0001_req_0001'}


def test_earlier_orphan_response_not_linked_to_later_request(tmp_path):
    cap = tmp_path / 'orphan.pcap'
    write_capture(cap, [
        incoming(5, 2000, res('before@example.invalid')),
        outgoing(10, 1000, req('/after', 'after@example.invalid')),
    ])
    report = analyze(cap)
    assert report['summary']['http_transactions'] == 0
    assert report['summary']['unpaired_requests'] == 1
    assert report['summary']['unpaired_responses'] == 1
    found = email_findings(report)
    assert next(f for f in found if f['http_message_type'] == 'response')['http_request_id'] is None
    assert next(f for f in found if f['http_message_type'] == 'request')['http_request_id'] is not None


def test_only_response_is_kept_unpaired(tmp_path):
    cap = tmp_path / 'response_only.pcap'
    write_capture(cap, [incoming(4, 2000, res('orphan@example.invalid'))])
    report = analyze(cap)
    assert report['summary']['unpaired_responses'] == 1
    assert report['summary']['unpaired_requests'] == 0
    assert email_findings(report)[0]['http_request_id'] is None


def test_missing_final_response_keeps_request_unpaired(tmp_path):
    cap = tmp_path / 'request_only.pcap'
    write_capture(cap, [outgoing(4, 1000, req('/missing', 'only@example.invalid'))])
    report = analyze(cap)
    assert report['summary']['unpaired_requests'] == 1
    assert report['summary']['http_transactions'] == 0
    assert email_findings(report)[0]['http_request_id'] == 'flow_0001_req_0001'


def test_independent_connections_have_independent_request_ids(tmp_path):
    cap = tmp_path / 'two_flows.pcap'
    write_capture(cap, [
        outgoing(1, 1000, req('/one', 'one@example.invalid'), port=50123),
        incoming(2, 2000, res('one-reply@example.invalid'), port=50123),
        outgoing(3, 3000, req('/two', 'two@example.invalid'), port=50124),
        incoming(4, 4000, res('two-reply@example.invalid'), port=50124),
    ])
    report = analyze(cap)
    assert report['summary']['flows_processed'] == 2
    assert report['summary']['http_transactions'] == 2
    request_ids = {f['http_request_id'] for f in report['findings']}
    assert request_ids == {'flow_0001_req_0001', 'flow_0002_req_0001'}


def test_first_byte_timestamp_of_second_message_differs(tmp_path):
    first = req('/first', 'first@example.invalid')
    second = req('/second', 'second@example.invalid')
    cap = tmp_path / 'two_requests.pcap'
    write_capture(cap, [outgoing(2, 1000, first),
                        outgoing(5, 1000 + len(first), second)])
    report = analyze(cap)
    findings = email_findings(report)
    assert [f['timestamp'] for f in findings] == [
        '1970-01-01T00:00:02+00:00', '1970-01-01T00:00:05+00:00',
    ]


def test_start_line_redacts_response_reason_phrase():
    assert safe_http_start_line('HTTP/1.1 200 hello@example.invalid') == 'HTTP/1.1 200'
    assert 'token=' not in safe_http_start_line('GET /hello?token=my-secret HTTP/1.1')


def test_http_path_can_contain_sensitive_values_and_is_redacted_by_default(tmp_path):
    cap = tmp_path / 'path_pii.pcap'
    write_capture(cap, [outgoing(2, 1000, req('/users/other@example.invalid',
                                              'body@example.invalid'))])
    report = analyze(cap)
    assert report['findings']
    assert all('other@example.invalid' not in f['http_start_line']
               for f in report['findings'])
    assert all('[path-redacted]' in f['http_start_line']
               for f in report['findings'])
    raw_report = analyze(cap, include_values=True)
    assert any('/users/other@example.invalid' in f['http_start_line']
               for f in raw_report['findings'])
