"""HTTP parsing and structured-field tests. All content is fabricated."""
from __future__ import annotations

import gzip
import json
import zlib

import pytest

from packet_pii.http_extract import (
    HttpMessage,
    MAX_HTTP_BODY,
    extract_fields,
    parse_http_stream,
)
from packet_pii.detect import detect_fields


def request(method='POST', route='/submit', *, headers=(), body=b''):
    extra = b''.join(f'{key}: {value}\r\n'.encode('ascii') for key, value in headers)
    return f'{method} {route} HTTP/1.1\r\nHost: synthetic.test\r\n'.encode() + extra + b'\r\n' + body


def take(raw: bytes) -> HttpMessage:
    messages = parse_http_stream(raw)
    assert len(messages) == 1
    return messages[0]


def test_nested_json_with_array_and_query_parameters():
    data = json.dumps({'user': {'email': 'fake@example.test', 'aliases': [
        {'full_name': 'Test Example'}, {'full_name': 'Another Test'}]}}).encode()
    message = take(request(route='/signup?phone=0412345678&phone=0499999999',
                           headers=[('Content-Type', 'application/json'),
                                    ('Content-Length', str(len(data)))], body=data))
    fields = extract_fields(message)
    assert ('json_body.user.email', 'fake@example.test') in fields
    assert ('json_body.user.aliases[0].full_name', 'Test Example') in fields
    assert ('json_body.user.aliases[1].full_name', 'Another Test') in fields
    assert [value for key, value in fields if key == 'query_parameter.phone'] == [
        '0412345678', '0499999999']
    assert any(f.pii_type == 'EMAIL' and f.location == 'json_body.user.email'
               for f in detect_fields(fields))


def test_urlencoded_body_unicode_and_repeated_keys():
    body = b'email=demo%40example.test&name=R%C3%A9mi&name=Jo+Lee'
    message = take(request(headers=[('content-type','application/x-www-form-urlencoded'),
                                    ('Content-Length',str(len(body)))], body=body))
    fields = extract_fields(message)
    assert ('form.email', 'demo@example.test') in fields
    assert [v for k, v in fields if k == 'form.name'] == ['Rémi', 'Jo Lee']


def test_multiple_http_messages_in_one_stream_and_204_response():
    two_requests = request('GET', '/a') + request('GET', '/b')
    parsed = parse_http_stream(two_requests)
    assert [x.start_line for x in parsed] == ['GET /a HTTP/1.1', 'GET /b HTTP/1.1']
    no_content = b'HTTP/1.1 204 No Content\r\nContent-Length: 999\r\n\r\n'
    assert len(parse_http_stream(no_content + request('GET', '/next'))) == 2


def test_content_length_response_and_body():
    body = b'{"email":"response@example.test"}'
    resp = (b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
            + f'Content-Length: {len(body)}\r\n\r\n'.encode() + body)
    parsed = take(resp)
    assert not parsed.is_request
    assert ('json_body.email', 'response@example.test') in extract_fields(parsed)


def test_chunked_post_with_extensions_and_trailers_followed_by_next_request():
    payload = b'email=chunk%40example.test'
    chunked = (f'{len(payload):x};anything=ok\r\n'.encode() + payload +
               b'\r\n0\r\nX-Trace: fake\r\n\r\n')
    raw = request(headers=[('Transfer-Encoding','chunked'),
                           ('Content-Type','application/x-www-form-urlencoded')],
                  body=chunked) + request('GET','/next')
    result = parse_http_stream(raw)
    assert len(result) == 2
    assert ('form.email', 'chunk@example.test') in extract_fields(result[0])
    assert result[1].start_line == 'GET /next HTTP/1.1'


@pytest.mark.parametrize('bad_body', [
    b'ZZ\r\nwrong\r\n0\r\n\r\n',
    b'3\r\nabcX\n0\r\n\r\n',
    b'5\r\nshort',
    b'0\r\nBrokenTrailer\r\n\r\n',
])
def test_invalid_chunked_body_not_parsed(bad_body):
    assert not parse_http_stream(request(headers=[('Transfer-Encoding','chunked')],
                                         body=bad_body))


def test_gzip_body_json_and_nested_detection():
    plaintext = b'{"customer":{"email":"zip@example.test"}}'
    zipped = gzip.compress(plaintext)
    msg = take(request(headers=[('content-type','application/json'),
                                ('content-encoding','gzip'),
                                ('content-length',str(len(zipped)))], body=zipped))
    assert ('json_body.customer.email','zip@example.test') in extract_fields(msg)


@pytest.mark.parametrize('wbits', [zlib.MAX_WBITS, -zlib.MAX_WBITS])
def test_deflate_zlib_and_raw_deflate(wbits):
    plaintext = b'{"email":"deflate@example.test"}'
    obj = zlib.compressobj(wbits=wbits)
    zipped = obj.compress(plaintext) + obj.flush()
    msg = take(request(headers=[('content-type','application/json'),
                                ('content-encoding','deflate'),
                                ('content-length',str(len(zipped)))], body=zipped))
    assert ('json_body.email','deflate@example.test') in extract_fields(msg)


def test_reject_expansion_bomb_and_unsupported_encoding_without_inspecting_body():
    zipped = gzip.compress(b'{"email":"' + b'x' * (MAX_HTTP_BODY + 100) + b'"}')
    msg = take(request(headers=[('content-type','application/json'),
                                ('content-encoding','gzip'),
                                ('content-length',str(len(zipped)))], body=zipped))
    assert not any(k.startswith('json_body.') for k, _ in extract_fields(msg))
    fake = b'{"email":"should-not-detect@example.test"}'
    msg2 = take(request(headers=[('content-type','application/json'),
                                 ('content-encoding','br'),
                                 ('content-length',str(len(fake)))], body=fake))
    assert not any(k.startswith('json_body.') for k, _ in extract_fields(msg2))


def test_multipart_text_fields_without_file_contents_or_stripping_hyphens():
    body = (
        b'--Bound-XYZ\r\nContent-Disposition: form-data; name="email"\r\n\r\n'
        b'form@example.test\r\n'
        b'--Bound-XYZ\r\nContent-Disposition: form-data; name="nickname"\r\n\r\n'
        b'nick--\r\n'
        b'--Bound-XYZ\r\nContent-Disposition: form-data; name="attachment"; filename="doc.txt"\r\n'
        b'Content-Type: text/plain\r\n\r\nsecret@example.test\r\n'
        b'--Bound-XYZ--\r\n'
    )
    msg = take(request(headers=[('Content-Type','multipart/form-data; boundary="Bound-XYZ"'),
                                ('Content-Length',str(len(body)))], body=body))
    fields = extract_fields(msg)
    assert ('form.email','form@example.test') in fields
    assert ('form.nickname','nick--') in fields
    assert not any('secret@example.test' in value for _, value in fields)


def test_incomplete_body_is_not_a_message():
    assert parse_http_stream(request(headers=[('Content-Length','50')], body=b'half')) == []


@pytest.mark.parametrize('extra_headers', [
    [('Content-Length','2'),('Content-Length','3')],
    [('Content-Length','3'),('Transfer-Encoding','chunked')],
    [('Content-Length','3, 3')],
    [('Transfer-Encoding','gzip, chunked')],
    [('Transfer-Encoding','unrecognized')],
])
def test_ambiguous_http_framing_rejected(extra_headers):
    assert parse_http_stream(request(headers=extra_headers, body=b'abc')) == []


@pytest.mark.parametrize('bad_header_bytes', [
    b'Host synthetic.test\r\n',
    b' Header: folded\r\n',
    b'Bad Name: x\r\n',
    b'X-Bad: x\x00abc\r\n',
])
def test_invalid_http_headers_do_not_crash_or_produce_messages(bad_header_bytes):
    raw = b'GET / HTTP/1.1\r\n' + bad_header_bytes + b'\r\n'
    assert parse_http_stream(raw) == []


def test_unframed_response_does_not_guess_subsequent_boundaries():
    misleading = (b'HTTP/1.1 200 OK\r\nX-Safe: 1\r\n\r\n'
                  b'GET /?email=fake%40example.test HTTP/1.1\r\nHost: test\r\n\r\n')
    result = parse_http_stream(misleading)
    assert len(result) == 1  # Content could be inside a close-delimited body.
    assert result[0].body == b''


def test_text_body_and_unknown_content_type_not_treated_as_plaintext():
    body = b'My email is demo@example.test'
    plain = take(request(headers=[('Content-Type','text/plain'),
                                  ('Content-Length',str(len(body)))], body=body))
    assert ('body.text',body.decode()) in extract_fields(plain)
    binary = take(request(headers=[('Content-Type','application/octet-stream'),
                                   ('Content-Length',str(len(body)))], body=body))
    assert not any(key == 'body.text' for key, _ in extract_fields(binary))


def test_json_depth_is_bounded():
    nested = {'email':'depth@example.test'}
    for i in range(45):
        nested = {'child':nested}
    raw = json.dumps(nested).encode()
    msg = take(request(headers=[('Content-Type','application/json'),
                                ('Content-Length',str(len(raw)))],body=raw))
    assert not any('depth@example.test' in value for _,value in extract_fields(msg))


def test_end_to_end_gzip_in_out_of_order_tcp(tmp_path):
    """Exercise capture, TCP, HTTP, decompression, detection, and reporting together."""
    import importlib.util
    import struct
    from pathlib import Path
    from packet_pii.engine import analyze

    generator = Path(__file__).resolve().parents[1] / 'examples' / 'generate_demo.py'
    spec = importlib.util.spec_from_file_location('http_fixture_generator', generator)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    body = gzip.compress(b'{"details":{"email":"combined@example.test"}}')
    http = request(headers=[('Content-Type','application/json'),
                            ('Content-Encoding','gzip'),
                            ('Content-Length',str(len(body)))],body=body)
    pieces = (http[:37], http[37:113], http[113:])
    src, dst = '192.0.2.123', '198.51.100.25'
    segments = [
        mod.tcp_frame(src, 40001, dst, 80, 1000+37, pieces[1]),
        mod.tcp_frame(src, 40001, dst, 80, 1000, pieces[0]),
        mod.tcp_frame(src, 40001, dst, 80, 1000+113, pieces[2]),
    ]
    output = tmp_path / 'http-gzip.pcap'
    with output.open('wb') as stream:
        stream.write(b'\xd4\xc3\xb2\xa1')
        stream.write(struct.pack('<HHiIII',2,4,0,0,65535,1))
        for n, frame in enumerate(segments):
            stream.write(struct.pack('<IIII',100,n,len(frame),len(frame)))
            stream.write(frame)
    result = analyze(output)
    assert result['summary']['http_messages'] == 1
    assert result['summary']['stream_gaps'] == 0
    matches = [f for f in result['findings'] if f['pii_type'] == 'EMAIL']
    assert len(matches) == 1
    assert matches[0]['location'] == 'json_body.details.email'
    assert matches[0]['flow_id'] == 'flow_0001'
    assert matches[0]['source_ip'] == src
    assert 'combined@example.test' not in json.dumps(result)


def test_corrupted_compressed_body_leaves_headers_but_not_body():
    raw = b'not-gzip-at-all'
    msg = take(request(headers=[('Content-Type','application/json'),
                                ('Content-Encoding','gzip'),
                                ('X-Sample','visible-header'),
                                ('Content-Length',str(len(raw)))],body=raw))
    assert ('header.x-sample','visible-header') in extract_fields(msg)
    assert not any(name.startswith('json_body') for name,_ in extract_fields(msg))
