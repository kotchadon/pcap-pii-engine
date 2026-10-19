"""Synthetic plaintext HTTP/2 fixtures using maintained HPACK encoder."""
import json
import sys

import pytest

from packet_pii.http_extract import extract_fields


def frame(kind, flags=0, stream_id=0, payload=b''):
    return len(payload).to_bytes(3, 'big') + bytes([kind, flags]) + stream_id.to_bytes(4, 'big') + payload


def client(*frames):
    return b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4) + b''.join(frames)


def encoder():
    return pytest.importorskip('hpack').Encoder()


def headers(enc, stream_id=1, end=True, extra=()):
    block = enc.encode([(':method', 'POST'), (':scheme', 'http'), (':path', '/'),
                        (':authority', 'example.invalid'), *extra])
    return frame(1, 4 | int(end), stream_id, block)


def parse(c, s=b''):
    from packet_pii.http2_extract import parse_http2_connection
    return parse_http2_connection(c, s)


def test_preface_missing_dependency_and_tls_never_decoded(monkeypatch):
    assert not parse(b'\x16\x03\x03ciphertext').recognized
    monkeypatch.setitem(sys.modules, 'hpack', None)
    result = parse(client())
    assert result.recognized and not result.messages
    assert result.diagnostics[0]['reason'] == 'http2_hpack_unavailable'


def test_request_response_pair_and_exact_data_packet_ranges():
    enc = encoder()
    body = b'{"email":"fiction@example.invalid"}'
    c = client(headers(enc, end=False, extra=[('content-type','application/json')]),
               frame(0, 0, 1, body[:12]), frame(0, 1, 1, body[12:]))
    s = frame(4) + frame(1, 5, 1, encoder().encode([(':status', '204')]))
    result = parse(c, s)
    assert not result.diagnostics
    assert len(result.messages) == 2
    req, resp = result.messages
    assert req.complete and resp.complete
    assert req.pairing_status == resp.pairing_status == 'paired'
    assert req.stream_id == resp.stream_id == 1
    assert b''.join(c[a:b] for a,b in req.body_stream_ranges) == body
    assert ('json_body.email', 'fiction@example.invalid') in extract_fields(req.message)
    from packet_pii.http2_extract import http2_evidence_for_fields
    metadata = http2_evidence_for_fields(req, extract_fields(req.message))
    assert all(i['granularity'] == 'transformed_source_range' for i in metadata)
    assert 'fiction@example.invalid' not in json.dumps(metadata)


def test_dynamic_table_provenance_includes_previous_header_block():
    enc = encoder()
    c = client(headers(enc, 1, extra=[('x-secret','synthetic-token')]),
               headers(enc, 3, extra=[('x-secret','synthetic-token')]))
    result = parse(c)
    assert len(result.messages) == 2
    first, second = result.messages
    assert len(second.header_source_ranges) > len(first.header_source_ranges)
    assert set(first.header_source_ranges) <= set(second.header_source_ranges)
    assert second.message.headers['x-secret'] == 'synthetic-token'


def test_continuation_padding_and_interim_responses():
    enc = encoder()
    block = enc.encode([(':method','GET'),(':scheme','http'),(':path','/')])
    c = client(frame(1, 1 | 8, 1, b'\x02' + block[:2] + b'xx'),
               frame(9, 4, 1, block[2:]))
    enc = encoder()
    s = (frame(4) + frame(1, 4, 1, enc.encode([(':status','103')]))
         + frame(1, 4, 1, enc.encode([(':status','200'),('content-type','text/plain')]))
         + frame(0, 9, 1, b'\x02abcxx'))
    result = parse(c, s)
    assert len(result.messages) == 3
    assert [r.message.start_line for r in result.messages] == ['GET / HTTP/2', 'HTTP/2 103', 'HTTP/2 200']
    assert result.messages[-1].message.body == b'abc'


@pytest.mark.parametrize('tail,reason', [
    (frame(9, 4, 1, b'\x82'), 'http2_unexpected_continuation'),
    (frame(0, 1, 1, b'abc'), 'http2_data_without_headers'),
    (frame(6, 0, 1, b'12345678'), 'http2_invalid_control_frame'),
    (frame(4, 1, 0, b'abcdef'), 'http2_invalid_settings'),
    (frame(8, 0, 0, b'\0\0\0\0'), 'http2_invalid_window_update'),
    (frame(5, 4, 1, b'abcd'), 'http2_push_unsupported'),
    (frame(4, 0, 0, b'\0\1\0\0\x20\0'), 'http2_settings_context_unsupported'),
    (b'\0\x40\x01\0\0\0\0\0\1', 'http2_frame_limit_exceeded'),
    (b'\0\0', 'http2_incomplete_frame'),
])
def test_malformed_or_unsupported_frame_has_sanitized_reason(tail, reason):
    encoder()
    result = parse(client(tail))
    assert result.diagnostics[-1]['reason'] == reason
    assert not result.messages


def test_continuation_cannot_be_interleaved():
    enc = encoder()
    block = enc.encode([(':method','GET'),(':scheme','http'),(':path','/')])
    result = parse(client(frame(1, 1, 1, block[:1]), frame(6, 0, 0, b'12345678'),
                          frame(9, 4, 1, block[1:])))
    assert not result.messages
    assert result.diagnostics[0]['reason'] == 'http2_interleaved_header_block'


@pytest.mark.parametrize('extra', [[('Connection','close')], [('connection','close')],
                                  [('content-length','9')], [('te','gzip')]])
def test_malformed_http_fields_and_content_lengths_fail_closed(extra):
    result = parse(client(headers(encoder(), extra=extra)))
    assert not result.messages and result.diagnostics


def test_incomplete_stream_is_explicit_and_later_closed_stream_data_rejected():
    c = client(headers(encoder(), end=False), frame(0, 0, 1, b'abc'))
    result = parse(c)
    assert len(result.messages) == 1 and not result.messages[0].complete
    assert result.messages[0].pairing_status == 'incomplete'
    c = client(headers(encoder()), frame(0, 1, 1, b'abc'))
    result = parse(c)
    assert not result.messages
    assert result.diagnostics[-1]['reason'] == 'http2_stream_closed'


def test_hpack_header_expansion_and_header_context_are_bounded(monkeypatch):
    import packet_pii.http2_extract as h2
    enc = encoder()
    oversized = headers(enc, extra=[('x-large', 'a' * (h2.MAX_HEADER_BYTES + 1))])
    # Split a compressed header block over legal frame payloads when necessary.
    payload = oversized[9:]
    chunks = [payload[i:i+16000] for i in range(0,len(payload),16000)]
    frames = [frame(1 if i==0 else 9, (1 if i==0 else 0) | (4 if i==len(chunks)-1 else 0), 1, p)
              for i,p in enumerate(chunks)]
    result = parse(client(*frames))
    assert not result.messages and result.diagnostics
    monkeypatch.setattr(h2, 'MAX_CONTEXT_BYTES', 4)
    assert parse(client(headers(encoder()))).diagnostics[0]['reason'] == 'http2_header_context_limit_exceeded'


def test_default_settings_trailers_and_stream_reset():
    enc = encoder()
    start = headers(enc, end=False, extra=[('content-length','3')])
    trailer = frame(1, 5, 1, enc.encode([('x-trailer', 'done')]))
    result = parse(client(start, frame(0, 0, 1, b'abc'), trailer))
    assert result.messages[0].message.body == b'abc' and result.messages[0].complete
    assert 'x-trailer' not in result.messages[0].message.headers
    result = parse(client(headers(encoder(), end=False), frame(3, 0, 1, b'\0\0\0\x08')))
    assert result.messages and not result.messages[0].complete
    assert result.diagnostics[0]['reason'] == 'http2_stream_reset'


def test_head_response_content_length_does_not_require_data():
    enc = encoder()
    c = client(frame(1, 5, 1, enc.encode([(':method','HEAD'),(':scheme','http'),(':path','/')])) )
    s = frame(4) + frame(1, 5, 1, encoder().encode([(':status','200'),('content-length','999')]))
    result = parse(c, s)
    assert len(result.messages) == 2 and not result.diagnostics


@pytest.mark.parametrize('field_list', [
    [(':method','GET'),(':scheme','http'),(':path','/'),(':path','/again')],
    [('x-field','first'),(':method','GET'),(':scheme','http'),(':path','/')],
    [(':method','GET'),(':scheme','http'),(':path','/'),('x-secret','bad\r\nvalue')],
    [(':method','CONNECT'),(':authority','example.invalid:443')],
])
def test_invalid_pseudo_header_order_duplicates_and_connect_fail_closed(field_list):
    result = parse(client(frame(1, 5, 1, encoder().encode(field_list))))
    assert not result.messages and result.diagnostics


def test_response_unknown_stream_and_wrong_stream_continuation_rejected():
    c = client(headers(encoder()))
    result = parse(c, frame(4) + frame(1, 5, 3, encoder().encode([(':status','204')])))
    assert len(result.messages) == 1
    assert result.diagnostics[-1]['reason'] == 'http2_response_without_request_context'
    result = parse(client(frame(1, 1, 1, b'\x82'), frame(9, 4, 3, b'\x86\x84')))
    assert not result.messages and result.diagnostics[0]['reason'] == 'http2_interleaved_header_block'


def test_stream_and_aggregate_body_limits(monkeypatch):
    import packet_pii.http2_extract as h2
    enc = encoder()
    monkeypatch.setattr(h2, 'MAX_STREAMS', 1)
    result = parse(client(headers(enc, 1), headers(enc, 3)))
    assert len(result.messages) == 1
    assert result.diagnostics[-1]['reason'] == 'http2_stream_limit_exceeded'
    monkeypatch.setattr(h2, 'MAX_TOTAL_BODY', 2)
    result = parse(client(headers(encoder(), end=False), frame(0, 1, 1, b'abc')))
    assert not result.messages and result.diagnostics[-1]['reason'] == 'http2_body_limit_exceeded'


def test_informational_message_limit_does_not_raise_or_overproduce(monkeypatch):
    import packet_pii.http2_extract as h2
    monkeypatch.setattr(h2, 'MAX_STREAMS', 1)
    c = client(headers(encoder()))
    enc = encoder()
    s = frame(4) + b''.join(frame(1, 4, 1, enc.encode([(':status','103')])) for _ in range(4))
    result = parse(c, s)
    assert len(result.messages) <= 3
    assert result.diagnostics[-1]['reason'] == 'http2_message_limit_exceeded'


def test_empty_headers_body_limit_and_bad_padding_are_sanitized():
    result = parse(client(frame(1, 5, 1, b'')))
    assert not result.messages and result.diagnostics
    result = parse(client(headers(encoder(), end=False), frame(0, 9, 1, b'\xffa')))
    assert not result.messages and result.diagnostics[-1]['reason'] == 'http2_invalid_padding'


def test_pending_streams_cannot_overflow_after_terminal_connection_error(monkeypatch):
    import packet_pii.http2_extract as h2
    monkeypatch.setattr(h2, 'MAX_STREAMS', 2)
    enc = encoder()
    c = client(headers(enc, 1), headers(enc, 3))
    enc = encoder()
    s = (frame(4) + b''.join(frame(1, 4, 1, enc.encode([(':status','103')])) for _ in range(4))
         + frame(1, 4, 3, enc.encode([(':status','200')])) + frame(6, 0, 0, b'bad'))
    result = parse(c, s)
    assert len(result.messages) <= 6
    assert any(d['reason'] == 'http2_message_limit_exceeded' for d in result.diagnostics)


def test_many_data_frames_bound_each_field_source_metadata():
    from packet_pii.http2_extract import http2_evidence_for_fields
    c = client(headers(encoder(), end=False, extra=[('content-type','text/plain')]),
               *(frame(0, int(i == 64), 1, b'x') for i in range(65)))
    result = parse(c)
    assert result.messages[0].message.body == b'x' * 65
    fields = extract_fields(result.messages[0].message)
    item = http2_evidence_for_fields(result.messages[0], fields)[-1]
    assert item['granularity'] == 'message_level_only'
    assert item['stream_ranges'] == []
    assert 'field_source_range_limit' in item['limitations']


def test_pair_with_partial_response_and_interim_only_is_incomplete():
    c = client(headers(encoder()))
    for status in ('200', '103'):
        s = frame(4) + frame(1, 4, 1, encoder().encode([(':status',status)]))
        result = parse(c, s)
        assert result.messages
        assert all(r.pairing_status == 'incomplete' for r in result.messages)
        assert any(d['incomplete'] for d in result.diagnostics)


def test_trailer_credentials_are_uninspected_with_explicit_coverage_notice():
    from packet_pii.http2_extract import http2_evidence_for_fields
    enc = encoder()
    initial = headers(enc, end=False)
    trailer = frame(1, 5, 1, enc.encode([('authorization', 'synthetic-trailer-secret')]))
    result = parse(client(initial, trailer))
    assert len(result.messages) == 1 and result.messages[0].complete
    record = result.messages[0]
    fields = extract_fields(record.message)
    assert all(path != 'header.authorization' for path, _ in fields)
    assert 'http2_trailers_uninspected' in record.limitations
    assert result.diagnostics == [{
        'reason': 'http2_trailers_uninspected', 'direction': 'client_to_server',
        'start_offset': len(client(initial)), 'stream_id': 1, 'incomplete': False,
    }]
    assert 'synthetic-trailer-secret' not in json.dumps(
        [fields, http2_evidence_for_fields(record, fields), result.diagnostics, record.limitations])
