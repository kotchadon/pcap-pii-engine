"""Fictional HTTP evidence fixtures; offsets are checked against original bytes."""
import gzip
import json

import pytest

from packet_pii.http_extract import extract_fields, parse_http_stream_with_spans


def request(body=b'', ct='text/plain', extra=b'', target=b'/'):
    return (b'POST ' + target + b' HTTP/1.1\r\nContent-Type: ' + ct.encode()
            + b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n'
            + extra + b'\r\n' + body)


def evidence(raw):
    from packet_pii.http_evidence import evidence_for_fields
    span = parse_http_stream_with_spans(raw)[0]
    fields = extract_fields(span.message)
    result = evidence_for_fields(raw, span, fields)
    assert len(result) == len(fields)
    for item in result:
        for source in item['stream_ranges']:
            assert span.start_offset <= source['start'] <= source['end'] <= span.end_offset
    return span, fields, result


def test_head_interim_and_final_responses_use_request_order():
    raw = (b'HTTP/1.1 103 Early Hints\r\n\r\n'
           b'HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n'
           b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc')
    spans = parse_http_stream_with_spans(raw, request_methods=['HEAD', 'GET'])
    assert [s.message.body for s in spans] == [b'', b'', b'abc']
    assert spans[-1].end_offset == len(raw)


@pytest.mark.parametrize('status,method', [('200', 'CONNECT'), ('101', 'GET')])
def test_tunnel_and_upgrade_do_not_parse_tunnel_bytes(status, method):
    raw = (f'HTTP/1.1 {status} Switched\r\nContent-Length: 99\r\n\r\n'.encode()
           + b'GET /tunnel HTTP/1.1\r\n\r\n')
    spans = parse_http_stream_with_spans(raw, request_methods=[method])
    assert len(spans) == 1 and spans[0].message.body == b''
    assert spans[0].end_offset == raw.index(b'GET')


def test_header_and_plaintext_exact_offsets_and_no_raw_evidence_values():
    raw = request('Rémi example'.encode(), extra=b'Authorization: secret-token\r\n')
    span, fields, items = evidence(raw)
    assert span.header_end == span.body_start == raw.index(b'\r\n\r\n') + 4
    for (path, value), item in zip(fields, items):
        assert item['granularity'] == 'exact_stream_range'
        source = item['stream_ranges'][0]
        charset = 'iso-8859-1' if path.startswith('header.') else 'utf-8'
        assert raw[source['start']:source['end']].decode(charset) == value
    assert 'secret-token' not in json.dumps(items)


def test_json_simple_unicode_nested_duplicate_and_escaped_values():
    body = '{"user":{"name":"Rémi","escaped":"A\\u0042"},"dup":"one","dup":"two"}'.encode()
    _, fields, items = evidence(request(body, 'application/json'))
    mapped = dict(zip((p for p, _ in fields), items))
    assert mapped['json_body.user.name']['granularity'] == 'exact_stream_range'
    assert mapped['json_body.user.escaped']['granularity'] == 'transformed_source_range'
    assert 'json_string_unescape' in mapped['json_body.user.escaped']['transformations']
    assert mapped['json_body.dup']['granularity'] != 'exact_stream_range'


@pytest.mark.parametrize('body,ct,extra,transformation', [
    (gzip.compress(b'{"email":"test@example.invalid"}'), 'application/json',
     b'Content-Encoding: gzip\r\n', 'gzip'),
    (b'email=test%40example.invalid', 'application/x-www-form-urlencoded', b'', 'url_decode'),
    (b'\xffbad', 'text/plain; charset=utf-8', b'', 'charset_decode'),
    (b'name=test', 'text/plain; charset=madeup', b'', 'charset_decode'),
])
def test_transformed_bodies_never_claim_exact_bytes(body, ct, extra, transformation):
    _, fields, items = evidence(request(body, ct, extra))
    for (path, _), item in zip(fields, items):
        if not path.startswith('header.'):
            assert item['granularity'] == 'transformed_source_range'
            assert transformation in item['transformations']


def test_query_chunked_and_duplicate_header_transformations():
    raw = (b'POST /?email=test%40example.invalid HTTP/1.1\r\n'
           b'X-Tag: one\r\nX-Tag: two\r\nTransfer-Encoding: chunked\r\n'
           b'Content-Type: text/plain\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n')
    span, fields, items = evidence(raw)
    mapped = dict(zip((p for p, _ in fields), items))
    assert mapped['query_parameter.email']['granularity'] == 'transformed_source_range'
    assert mapped['header.x-tag']['granularity'] == 'transformed_source_range'
    assert mapped['body.text']['granularity'] == 'transformed_source_range'
    assert 'chunked_decode' in mapped['body.text']['transformations']
    assert b''.join(raw[a:b] for a, b in span.body_stream_ranges) == b'abcdef'


def test_empty_header_has_valid_empty_source_range():
    raw = request(extra=b'X-Empty: \t \r\n')
    _, fields, items = evidence(raw)
    item = items[[p for p, _ in fields].index('header.x-empty')]
    assert item['granularity'] == 'exact_stream_range'
    assert item['stream_ranges'][0]['start'] == item['stream_ranges'][0]['end']


def test_known_get_response_incomplete_and_exhausted_method_context():
    diagnostics = []
    raw = b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nabc'
    assert parse_http_stream_with_spans(raw, request_methods=['GET'], diagnostics=diagnostics) == []
    assert diagnostics[0].incomplete
    assert diagnostics[0].reason == 'http_incomplete_content_length_body'
    diagnostics = []
    raw = b'HTTP/1.1 204 No Content\r\n\r\n' + raw
    spans = parse_http_stream_with_spans(raw, request_methods=['GET'], diagnostics=diagnostics)
    assert len(spans) == 1
    assert diagnostics[0].reason == 'http_response_body_framing_unknown'


def test_multipart_and_non_utf8_json_remain_transformed():
    multipart = (b'--abc\r\nContent-Disposition: form-data; name="email"\r\n\r\n'
                 b'test@example.invalid\r\n--abc--\r\n')
    for raw in (request(multipart, 'multipart/form-data; boundary=abc'),
                request(b'{"name":"R\xe9mi"}', 'application/json; charset=iso-8859-1')):
        _, fields, items = evidence(raw)
        body_items = [i for (p, _), i in zip(fields, items) if not p.startswith('header.')]
        assert body_items
        assert all(i['granularity'] == 'transformed_source_range' for i in body_items)


def test_pipelined_message_evidence_is_in_second_message_only():
    from packet_pii.http_evidence import evidence_for_fields
    first = request(b'first')
    raw = first + request(b'second')
    span = parse_http_stream_with_spans(raw)[1]
    fields = extract_fields(span.message)
    items = evidence_for_fields(raw, span, fields)
    assert all(r['start'] >= len(first) for i in items for r in i['stream_ranges'])
    assert raw[items[-1]['stream_ranges'][0]['start']:] == b'second'


def test_legacy_spans_do_not_invent_field_ranges():
    from packet_pii.http_extract import HttpSpan
    from packet_pii.http_evidence import evidence_for_fields
    raw = request(b'example')
    parsed = parse_http_stream_with_spans(raw)[0]
    span = HttpSpan(parsed.message, 0, len(raw))
    items = evidence_for_fields(raw, span, extract_fields(span.message))
    assert all(i['granularity'] == 'message_level_only' for i in items)


def test_response_method_callback_overrides_positional_context():
    orphan = b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc'
    interim = b'HTTP/1.1 103 Early Hints\r\n\r\n'
    head = b'HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n'
    seen = []
    def context(start, status):
        seen.append((start, status))
        return None if start == 0 else 'HEAD'
    spans = parse_http_stream_with_spans(orphan + interim + head,
                                        request_methods=['HEAD'],
                                        request_method_for_response=context)
    assert [s.message.body for s in spans] == [b'abc', b'', b'']
    assert seen == [(0, 200), (len(orphan), 103), (len(orphan)+len(interim), 200)]
