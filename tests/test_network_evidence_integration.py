"""End-to-end evidence oracles: source bytes, privacy, stable joins and budgets."""
import hashlib
import json
import struct

import pytest

from packet_pii.engine import AnalysisLimitError, AnalysisLimits, analyze, analyze_to_report
from packet_pii.evidence import EVIDENCE_ARRAYS


def capture(path, raw):
    # Two out-of-order records plus a retransmission; real file offsets are
    # derived independently here, without the application's capture writer.
    parts = [(37, raw[37:]), (0, raw[:37]), (0, raw[:37])]
    file = bytearray(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 101))
    for offset, payload in parts:
        tcp = struct.pack('!HHIIBBHHH', 12345, 80, (0xfffffff0 + offset) & 0xffffffff,
                          0, 0x50, 0x18, 4096, 0, 0) + payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(tcp), 1, 0, 64, 6, 0,
                         b'\xc0\x00\x02\x01', b'\xc6\x33\x64\x02') + tcp
        file += struct.pack('<IIII', 1, 0, len(ip), len(ip)) + ip
    path.write_bytes(file)
    return path


def request(body, extra=b''):
    return (b'POST /private-token?key=SecretQueryValue HTTP/1.1\r\n'
            b'Authorization: Bearer SecretHeaderValue\r\nContent-Type: application/json\r\n'
            + extra + b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)


def resolve(file, report, field):
    out = bytearray()
    sources = sorted((r for r in report['stream_evidence']
                      if r['row_type'] == 'source_range' and r['stream_id'] == field['stream_id']),
                     key=lambda r: r['stream_start'])
    for span in field['stream_ranges']:
        position = span['start']
        for source in sources:
            a, b = max(position, source['stream_start']), min(span['end'], source['stream_end'])
            if a < b:
                assert a == position  # no hidden gaps or duplicate ranges
                at = source['file_start'] + a-source['stream_start']
                out += file[at:at+b-a]
                position = b
        assert position == span['end']
    return bytes(out)


def test_capture_to_finding_chain_is_exact_and_private(tmp_path):
    body = '{"email":"rémi@example.invalid","name":"SecretBodyName"}'.encode()
    path = capture(tmp_path/'evidence.pcap', request(body))
    report = analyze(path)
    file = path.read_bytes()
    assert report['capture_evidence']['capture_sha256'] == hashlib.sha256(file).hexdigest()
    assert report['capture_evidence']['capture_bytes'] == len(file)
    assert report['capture_evidence']['identity_status'] == 'verified_read'
    assert sum(report['summary']['packet_dispositions'].values()) == 3
    assert report['summary']['tcp_capture_completeness'] == 'unknown'
    fields = {f['field_id']: f for f in report['field_evidence']}
    email = next(f for f in fields.values() if f['source_category'] == 'json_body')
    assert email['granularity'] == 'exact_stream_range'
    assert resolve(file, report, email).decode(email['text_encoding']) == 'rémi@example.invalid'
    assert any(r.get('diagnostics') == ['retransmission', 'consistent_overlap'] for r in report['stream_evidence']) or any('retransmission' in r.get('diagnostics', []) for r in report['stream_evidence'])
    for finding in report['findings']:
        ev = finding['evidence']
        assert ev['http_message_id'] == finding['http_message_id']
        assert all(fields[id]['http_message_id'] == finding['http_message_id'] for id in ev['field_ids'])
        assert ev['raw_detection_span'] == 'unavailable'
    serialized = json.dumps(report, ensure_ascii=False)
    for secret in ('SecretHeaderValue', 'SecretQueryValue', 'SecretBodyName', 'private-token', 'rémi@example.invalid'):
        assert secret not in serialized
    assert 'fingerprint' not in serialized


def test_transformed_bytes_are_not_a_decoded_detection_span(tmp_path):
    import gzip
    body = b'{"email":"test@example.invalid"}'
    encoded = gzip.compress(body, mtime=0)
    path = capture(tmp_path/'compressed.pcap', request(encoded, b'Content-Encoding: gzip\r\n'))
    report = analyze(path)
    field = next(f for f in report['field_evidence'] if f['source_category'] == 'json_body')
    assert field['granularity'] == 'transformed_source_range'
    assert 'gzip' in field['transformations']
    assert resolve(path.read_bytes(), report, field) == encoded


def test_evidence_streaming_is_equivalent_and_receipt_stays_small(tmp_path):
    path = capture(tmp_path/'source.pcap', request(b'{"email":"test@example.invalid"}'))
    expected = analyze(path)
    target = tmp_path/'report.json'
    observed = []
    receipt = analyze_to_report(path, target, row_observer=lambda kind, row: observed.append((kind, row)))
    actual = json.loads(target.read_text())
    for name in EVIDENCE_ARRAYS:
        assert actual[name] == expected[name]
        assert name not in receipt
        assert [r for k, r in observed if k == name] == expected[name]
    assert actual['findings'] == expected['findings']
    assert target.stat().st_mode & 0o777 == 0o600


def test_evidence_budget_aborts_atomic_report(tmp_path):
    path = capture(tmp_path/'source.pcap', request(b'{"email":"test@example.invalid"}'))
    target = tmp_path/'report.json'
    with pytest.raises(AnalysisLimitError):
        analyze_to_report(path, target, limits=AnalysisLimits(max_report_bytes=500))
    assert not target.exists()


def test_ml_decoded_spans_remain_distinct_from_raw_byte_offsets(tmp_path):
    from packet_pii.ml import EntityLabel, EntitySpan, ScoreType
    class Detector:
        model_version = 'test-double-provenance-only'
        def predict_fields(self, fields):
            return [EntitySpan(f.field_index, EntityLabel.PERSON_NAME, 0, len(f.text),
                    self.model_version, .9, ScoreType.UNCALIBRATED_MODEL_SCORE)
                    for f in fields if f.location == 'json_body.note']
    path = capture(tmp_path/'unicode.pcap', request('{"note":"Élodie"}'.encode()))
    report = analyze(path, ml_detector=Detector())
    finding = next(f for f in report['findings'] if f['detector'] == 'bilstm')
    assert finding['evidence']['decoded_text_span'] == {'start': 0, 'end': 6}
    field = next(f for f in report['field_evidence'] if f['field_id'] == finding['evidence']['field_ids'][0])
    assert len(resolve(path.read_bytes(), report, field)) == 7
    assert finding['evidence']['raw_detection_span'] == 'unavailable'


def test_plaintext_h2_engine_uses_actual_frame_ranges(tmp_path):
    from test_http2_evidence import client, headers, frame, encoder
    enc = encoder()
    body = b'{"email":"fiction@example.invalid"}'
    raw = client(headers(enc, end=False, extra=[('content-type', 'application/json')]),
                 frame(0, 0, 1, body[:9]), frame(0, 1, 1, body[9:]))
    path = capture(tmp_path/'h2.pcap', raw)
    report = analyze(path)
    assert report['summary']['http2_connections_decoded'] == 1
    assert report['summary']['http2_messages_decoded'] == 1
    assert report['summary']['http2_streams_not_decoded'] == 0
    assert report['http_evidence'][0]['protocol'] == 'h2'
    assert report['http_evidence'][0]['contiguous'] is False
    field = next(f for f in report['field_evidence'] if f['source_category'] == 'json_body')
    assert field['granularity'] == 'transformed_source_range'
    assert resolve(path.read_bytes(), report, field) == body
    assert 'fiction@example.invalid' not in json.dumps(report)


def test_plaintext_h2_missing_dependency_is_explicit_incomplete(tmp_path, monkeypatch):
    import sys
    from packet_pii.http2_extract import PREFACE
    monkeypatch.setitem(sys.modules, 'hpack', None)
    report = analyze(capture(tmp_path/'h2.pcap', PREFACE))
    assert report['summary']['http2_connections_decoded'] == 0
    assert report['summary']['analysis_incomplete'] is True
    assert report['flows'][0]['http_diagnostics'][0]['reason'] == 'http2_hpack_unavailable'


def test_evidence_pages_require_auth_and_resolve_ids():
    from test_dashboard_jobs import server, request, finish
    with server() as s:
        auth = {'X-Dashboard-Token': s.token, 'X-Request-ID': 'evidence-contract'}
        code, body, _ = request(s, 'POST', '/api/jobs/showcase', headers=auth)
        assert code == 202
        job_id = json.loads(body)['job_id']
        finished = finish(s, job_id)
        assert finished['status'] == 'completed'
        base = '/api/jobs/' + job_id
        assert request(s, 'GET', base+'/field_evidence')[0] == 403
        code, body, _ = request(s, 'GET', base+'/field_evidence?limit=1', headers=auth)
        page = json.loads(body)
        assert code == 200 and len(page['items']) == 1 and page['total'] > 1
        field = page['items'][0]
        code, body, _ = request(s, 'GET', base+'/field_evidence?evidence_id='+field['field_id'], headers=auth)
        assert code == 200 and json.loads(body)['items'] == [field]
        code, body, _ = request(s, 'GET', base+'/stream_evidence?stream_id='+field['stream_id'], headers=auth)
        assert code == 200 and all(x['stream_id'] == field['stream_id'] for x in json.loads(body)['items'])
        assert request(s, 'GET', base+'/packet_evidence?limit=101', headers=auth)[0] == 400
        assert request(s, 'GET', base+'/packet_evidence?evidence_id='+'x'*161, headers=auth)[0] == 400


@pytest.mark.parametrize('method,target', [(b'HEAD', b'/'), (b'CONNECT', b'example.invalid:443')])
def test_earlier_orphan_response_cannot_inherit_later_request_method(tmp_path, method, target):
    from test_http_incomplete_tail import capture as tcp_capture
    orphan = b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc'
    request_bytes = method + b' ' + target + b' HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
    response = b'HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n'
    path = tcp_capture(tmp_path, [(900, orphan, 0x18, True), (100, request_bytes, 0x18),
                                  (900+len(orphan), response, 0x18, True)])
    report = analyze(path)
    assert report['summary']['http_messages'] == 3
    assert report['summary']['http_transactions'] == 1
    assert report['summary']['unpaired_responses'] == 1
    assert report['summary']['http_incomplete_streams'] == 0
    assert any(f['source_category'] == 'body' for f in report['field_evidence'])


def test_report_evidence_schema_validates_actual_serialized_objects(tmp_path):
    import importlib.util
    if importlib.util.find_spec('jsonschema') is None:
        pytest.skip('optional independent JSON Schema validator unavailable')
    import jsonschema
    from pathlib import Path
    schema=json.loads((Path(__file__).resolve().parents[1]/'schemas/report-v1.schema.json').read_text())
    report=analyze(capture(tmp_path/'schema.pcap', request(b'{"email":"test@example.invalid"}')))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(report)


def test_evidence_does_not_introduce_raw_attacker_key_disclosure(tmp_path):
    raw = request(b'{"SensitiveKeyWithoutPunctuation":"ordinary text"}')
    report = analyze(capture(tmp_path/'keys.pcap', raw))
    assert 'SensitiveKeyWithoutPunctuation' not in json.dumps(report)
    field = next(f for f in report['field_evidence'] if f['source_category'] == 'json_body')
    assert field['location'] == 'json_body'
    assert field['field_id'] and field['field_index'] >= 0
