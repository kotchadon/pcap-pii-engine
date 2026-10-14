"""Independently specified HTTP boundary and capture-corruption cases."""
import gzip
import struct
import pytest
from packet_pii.capture import CaptureDiagnostics, read_frames
from packet_pii.http_extract import parse_http_stream, parse_http_stream_with_spans, extract_fields

POST = b'POST / HTTP/1.1\r\nHost: example.test\r\n'
GET = b'GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n'

@pytest.mark.parametrize('framing', [b'Transfer-Encoding:\r\nContent-Length: 0',
    b'Transfer-Encoding:', b'Transfer-Encoding: chunked\r\nContent-Length: 0',
    b'Content-Length: -1', b'Content-Length: 1, 1'])
def test_ambiguous_or_invalid_framing_never_exposes_following_request(framing):
    assert parse_http_stream(POST + framing + b'\r\n\r\n' + GET) == []

@pytest.mark.parametrize('chunk', [b'1;\r\nx\r\n0\r\n\r\n',
    b'1;name="unterminated\r\nx\r\n0\r\n\r\n',
    b'1;name=\x00\r\nx\r\n0\r\n\r\n', b' 1\r\nx\r\n0\r\n\r\n',
    b'1\r\nx\r\n0\r\nX-Test: a\x00b\r\n\r\n',
    b'1\r\nx\r\n0\r\nContent-Length: 1\r\n\r\n'])
def test_bad_chunk_extension_or_trailer_stops_at_ambiguity(chunk):
    assert parse_http_stream(POST + b'Transfer-Encoding: chunked\r\n\r\n' + chunk + GET) == []


def test_valid_quoted_chunk_extensions_and_trailer_preserve_exact_boundaries():
    raw = POST + b'Transfer-Encoding: chunked\r\n\r\n1 ; x = "a;\\\"b"\r\nx\r\n0\r\nX-Hash: fake\r\n\r\n'
    spans = parse_http_stream_with_spans(raw + GET)
    assert [s.message.body for s in spans] == [b'x', b'']
    assert [(s.start_offset,s.end_offset) for s in spans] == [(0,len(raw)),(len(raw),len(raw)+len(GET))]


def test_switching_protocols_stops_before_http_looking_tunnel_bytes():
    upgrade = b'HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: test\r\n\r\n'
    assert len(parse_http_stream(upgrade + GET)) == 1


def test_partial_body_is_not_a_complete_message():
    assert parse_http_stream(POST + b'Content-Length: 20\r\n\r\nshort') == []


def test_persistent_gzip_json_body_extracts_original_fields():
    body = gzip.compress(b'{"email":"fixture@example.test"}', mtime=0)
    raw = (POST + b'Content-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: '
           + str(len(body)).encode() + b'\r\n\r\n' + body)
    messages = parse_http_stream(raw + GET)
    assert len(messages) == 2
    assert any('fixture@example.test' in str(field) for field in extract_fields(messages[0]))


def test_snaplen_truncation_is_diagnostic_and_next_record_survives(tmp_path):
    capture = tmp_path / 'snap.pcap'
    capture.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,101)
        + struct.pack('<IIII',1,0,3,8) + b'abc'
        + struct.pack('<IIII',2,0,3,3) + b'xyz')
    diag = CaptureDiagnostics()
    assert [f.data for f in read_frames(capture,diagnostics=diag)] == [b'abc',b'xyz']
    assert diag.truncated_records == 1 and diag.incomplete


def block(kind, body):
    size = 12 + len(body)
    return struct.pack('<II',kind,size) + body + struct.pack('<I',size)


def test_pcapng_snaplen_and_wire_length_are_enforced(tmp_path):
    shb = block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
    idb = block(1,struct.pack('<HHI',101,0,3))
    bad = block(6,struct.pack('<IIIII',0,0,1,4,4) + b'abcd')
    short = block(6,struct.pack('<IIIII',0,0,2,3,8) + b'abc\x00')
    capture = tmp_path/'snap.pcapng'; capture.write_bytes(shb+idb+bad+short)
    diag = CaptureDiagnostics()
    assert [f.data for f in read_frames(capture,diagnostics=diag)] == [b'abc']
    assert (diag.malformed_records,diag.truncated_records) == (1,1)
