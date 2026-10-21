"""Bounded HTTP/1.0 and HTTP/1.1 message and field extraction.

Deliberately conservative: suspicious or unsupported framing terminates parsing
rather than guessing where the next message starts. This is not a general HTTP
security parser and cannot inspect encrypted HTTPS, HTTP/2, or HTTP/3.
"""
from __future__ import annotations

from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
import json
import re
from urllib.parse import parse_qsl, urlsplit
from typing import Callable
import zlib

MAX_HTTP_BODY = 2 * 1024 * 1024
MAX_HTTP_HEADER = 64 * 1024
MAX_MESSAGES = 10000
MAX_FIELDS = 10000
MAX_PARTS = 256
MAX_NESTING = 32
MAX_TRAILER_BYTES = 16 * 1024

_REQUEST = re.compile(rb"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT) [^\x00-\x20]+ HTTP/1\.[01]\Z")
_RESPONSE = re.compile(rb"HTTP/1\.[01] [1-5][0-9]{2}(?: [\x20-\x7e]*)?\Z")
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_QUOTED = rb'"(?:[\t !#-\[\]-~\x80-\xff]|\\[\t !-~\x80-\xff])*"'
_CHUNK_LINE = re.compile(rb'([0-9a-fA-F]+)(?:[ \t]*;[ \t]*' + _TOKEN
                         + rb'(?:[ \t]*=[ \t]*(?:' + _TOKEN + rb'|' + _QUOTED
                         + rb'))?)*\Z')
_BOUNDARY = re.compile(r'boundary=(?:"([^"\r\n]{1,200})"|([^;\s\r\n]{1,200}))', re.I)
_CHARSET = re.compile(r"charset\s*=\s*[\"']?([\w.-]+)", re.I)


@dataclass(frozen=True)
class HttpMessage:
    start_line: str
    headers: dict[str, str]
    body: bytes
    is_request: bool


@dataclass(frozen=True)
class HttpSpan:
    """A parsed HTTP message and its byte boundaries in one TCP direction."""
    message: HttpMessage
    start_offset: int
    end_offset: int
    # Half-open offsets, including the terminating empty header line. Body
    # ranges contain only captured entity octets (chunk metadata excluded).
    header_end: int | None = None
    body_start: int | None = None
    body_stream_ranges: tuple[tuple[int, int], ...] = ()
    body_framing: str = 'unknown'


@dataclass(frozen=True)
class HttpParseDiagnostic:
    """Sanitized terminal parsing observation, relative to a TCP direction.

    ``incomplete`` means observed unfinished HTTP framing, not an inference
    about missing TCP packets. False denotes an unsupported/uncertain tail.
    No start line, header, or body content is retained.
    """
    reason: str
    start_offset: int
    incomplete: bool


def _incomplete_header_prefix(raw: bytes) -> bool:
    """Recognize valid HTTP header prefixes without guessing arbitrary text."""
    lines = raw.split(b'\r\n')
    first = lines[0].removesuffix(b'\r')
    if not (_REQUEST.fullmatch(first) or _RESPONSE.fullmatch(first)):
        # Only recognize a partial start line once its HTTP version is visible.
        return len(lines) == 1 and bool(re.fullmatch(
            rb'(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT) '
            rb'[^\x00-\x20]+ HTTP/1(?:\.[01]?)?'
            rb'|HTTP/1\.[01](?: [1-5][0-9]?)?', first))
    if len(lines) == 1:
        return True
    if _parse_headers(b'\r\n'.join(lines[:-1])) is None:
        return False
    last = lines[-1].removesuffix(b'\r')
    if not last:
        return True
    if b':' not in last:
        return bool(_HEADER_NAME.fullmatch(last))
    key, value = last.split(b':', 1)
    return bool(_HEADER_NAME.fullmatch(key)) and not any(
        c < 32 and c != 9 or c == 127 for c in value)


def _parse_headers(raw: bytes) -> tuple[str, dict[str, str], bool] | None:
    lines = raw.split(b'\r\n')
    if not lines or len(lines) > 201:
        return None
    first = lines[0]
    if not (_REQUEST.fullmatch(first) or _RESPONSE.fullmatch(first)):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or line.startswith((b' ', b'\t')) or b':' not in line:
            return None
        key, value = line.split(b':', 1)
        if not _HEADER_NAME.fullmatch(key):
            return None
        name = key.decode('ascii').lower()
        if any(c < 32 and c != 9 or c == 127 for c in value):
            return None
        val = value.decode('iso-8859-1').strip(' \t')
        # Security-sensitive framing headers cannot be silently overwritten.
        if name in headers:
            if name in ('content-length', 'transfer-encoding'):
                return None
            headers[name] += ', ' + val
        else:
            headers[name] = val
    return first.decode('iso-8859-1'), headers, bool(_REQUEST.fullmatch(first))


def _chunked(data: bytes, position: int, *, diagnostic=None,
             source_ranges=None) -> tuple[bytes, int] | None:
    """Decode one HTTP/1 chunked body; enforce data and trailer size limits."""
    def fail(incomplete=False, reason=None):
        if diagnostic is not None:
            diagnostic(reason or ('http_incomplete_chunked_framing' if incomplete
                                   else 'http_invalid_chunked_framing'), incomplete)
        return None

    result = bytearray()
    for _ in range(10000):
        end = data.find(b'\r\n', position, min(len(data), position + 130))
        if end < 0 or end - position > 128:
            tail = data[position:position + 130]
            # A bounded, plausible chunk-size prefix can be cut off at EOF.
            plausible = tail in (b'', b'\r') or bool(re.fullmatch(
                rb'[0-9a-fA-F]+(?:[ \t]*;[^\r\n\x00-\x08\x0b-\x1f]*)?\r?', tail))
            return fail(len(tail) <= 128 and plausible)
        match = _CHUNK_LINE.fullmatch(data[position:end])
        if match is None:
            return fail()
        size = int(match[1], 16)
        position = end + 2
        if size == 0:
            if data[position:position+2] == b'\r\n':
                return bytes(result), position + 2
            trailer_end = data.find(b'\r\n\r\n', position,
                                    min(len(data), position + MAX_TRAILER_BYTES + 4))
            if trailer_end < 0:
                tail = data[position:position + MAX_TRAILER_BYTES + 4]
                plausible = _incomplete_header_prefix(b'GET / HTTP/1.1\r\n' + tail)
                return fail(len(tail) <= MAX_TRAILER_BYTES and plausible)
            # Don't trust malformed trailer lines and don't expose them as fields.
            for line in data[position:trailer_end].split(b'\r\n'):
                if not line or b':' not in line or not _HEADER_NAME.fullmatch(line.split(b':', 1)[0]):
                    return fail()
                name, value = line.split(b':', 1)
                if name.lower() in (b'content-length', b'transfer-encoding', b'host'):
                    return fail()
                if any(c < 32 and c != 9 or c == 127 for c in value):
                    return fail()
            return bytes(result), trailer_end + 4
        if position + size > len(data):
            return fail(True)
        if size > MAX_HTTP_BODY - len(result):
            return fail(reason='http_body_limit_exceeded')
        result.extend(data[position:position + size])
        if source_ranges is not None:
            source_ranges.append((position, position + size))
        position += size
        if len(data) - position < 2:
            return fail(data[position:] in (b'', b'\r'))
        if data[position:position+2] != b'\r\n':
            return fail()
        position += 2
    return fail(reason='http_chunk_limit_exceeded')


def parse_http_stream_with_spans(
        data: bytes, *, diagnostics: list[HttpParseDiagnostic] | None = None,
        request_methods: list[str] | None = None,
        request_method_for_response: Callable[[int, int], str | None] | None = None,
) -> list[HttpSpan]:
    """Parse a contiguous TCP stream and preserve each message's byte span.

    Offsets allow packet provenance to be associated with the correct message,
    including HTTP pipelining where multiple messages share a TCP segment.
    Optional diagnostics report at most one terminal observation per call;
    existing callers retain identical parsed messages and byte spans.
    Without paired request-method context, unfinished response body framing is
    uncertain: HEAD and successful CONNECT responses may legitimately omit it.
    Such responses remain unparsed. Optional ordered request methods apply to
    final responses; interim responses do not consume a method. Callers must
    establish ordering from observed session evidence, never timestamps alone.
    A method callback receives the response stream offset and status, and takes
    precedence over the list, including when it returns unknown (None).
    """
    messages: list[HttpSpan] = []
    offset = 0
    response_index = 0
    def diagnostic(reason: str, incomplete: bool = False):
        if diagnostics is not None:
            diagnostics.append(HttpParseDiagnostic(reason, offset, incomplete))

    while offset < len(data) and len(messages) < MAX_MESSAGES:
        header_end = data.find(b'\r\n\r\n', offset,
                               min(len(data), offset + MAX_HTTP_HEADER + 4))
        if header_end < 0 or header_end - offset > MAX_HTTP_HEADER:
            tail = data[offset:offset + MAX_HTTP_HEADER + 4]
            unfinished = len(tail) <= MAX_HTTP_HEADER and _incomplete_header_prefix(tail)
            diagnostic('http_incomplete_headers' if unfinished else 'http_unparseable_tail',
                       unfinished)
            break
        parsed = _parse_headers(data[offset:header_end])
        if parsed is None:
            diagnostic('http_unparseable_tail')
            break
        first, headers, is_request = parsed
        code = int(first[9:12]) if not is_request else None
        if code is not None and request_method_for_response is not None:
            method = request_method_for_response(offset, code)
            method = method.upper() if method is not None else None
        else:
            method = (request_methods[response_index].upper()
                      if not is_request and request_methods is not None
                      and response_index < len(request_methods) else None)
        def body_diagnostic(reason: str, incomplete: bool = False):
            if incomplete and not is_request and method is None:
                diagnostic('http_response_body_framing_unknown')
            else:
                diagnostic(reason, incomplete)

        body_at = header_end + 4
        tunnel = code is not None and method == 'CONNECT' and 200 <= code < 300
        no_body = code is not None and (method == 'HEAD' or tunnel or
                                       100 <= code < 200 or code in (204, 304))
        unframed_response = not is_request and not no_body and (
            'content-length' not in headers and 'transfer-encoding' not in headers
        )
        transfer = headers.get('transfer-encoding', '').strip().lower()
        length = headers.get('content-length')
        if not no_body and 'transfer-encoding' in headers and (not transfer or length is not None):
            diagnostic('http_ambiguous_framing')
            break  # Ambiguous framing: fail closed, not vulnerable to CL/TE confusion.
        source_ranges: list[tuple[int, int]] = []
        if no_body:
            body, next_at = b'', body_at
            framing = 'tunnel' if tunnel else 'no_body'
        elif transfer:
            if transfer != 'chunked':
                diagnostic('http_unsupported_transfer_coding')
                break  # Unsupported transfer codings aren't silently treated as plaintext.
            result = _chunked(data, body_at, diagnostic=body_diagnostic,
                              source_ranges=source_ranges)
            if result is None:
                break
            body, next_at = result
            framing = 'chunked'
        elif length is not None:
            if not re.fullmatch(r'[0-9]+', length) or len(length) > 12:
                diagnostic('http_invalid_content_length')
                break
            size = int(length)
            if body_at + size > len(data):
                body_diagnostic('http_incomplete_content_length_body', True)
                break
            if size > MAX_HTTP_BODY:
                diagnostic('http_body_limit_exceeded')
                break
            body, next_at = data[body_at:body_at + size], body_at + size
            framing = 'content_length'
            if size:
                source_ranges.append((body_at, next_at))
        else:
            # No close-delimited response reconstruction without connection state.
            # HTTP/1.0 close-delimited bodies are deliberately not inferred.
            body, next_at = b'', body_at
            framing = 'close_delimited_uninspected' if unframed_response else 'no_body'
        messages.append(HttpSpan(HttpMessage(first, headers, body, is_request),
                                 offset, next_at, body_at, body_at,
                                 tuple(source_ranges), framing))
        if code is not None and (code >= 200 or code == 101):
            response_index += 1
        if next_at <= offset:
            break
        if unframed_response or code == 101 or tunnel:
            if unframed_response:
                diagnostic('http_close_delimited_body_uninspected')
            break  # Unframed body or protocol switch ends supported HTTP parsing.
        offset = next_at
    return messages


def parse_http_stream(data: bytes) -> list[HttpMessage]:
    """Backwards-compatible HTTP parser API without byte offsets."""
    return [span.message for span in parse_http_stream_with_spans(data)]


def _decompress_body(message: HttpMessage) -> bytes | None:
    body = message.body
    encoding = message.headers.get('content-encoding', 'identity').strip().lower()
    if encoding in ('', 'identity'):
        return body if len(body) <= MAX_HTTP_BODY else None
    if encoding not in ('gzip', 'deflate'):
        return None

    # Bound expanded output to prevent gzip/deflate bombs. Extra trailing bytes
    # or an incomplete compressed stream make the body unsafe to inspect.
    def decompress(wbits: int) -> bytes | None:
        obj = zlib.decompressobj(wbits)
        try:
            expanded = obj.decompress(body, MAX_HTTP_BODY + 1)
            if (len(expanded) > MAX_HTTP_BODY or not obj.eof or
                    obj.unconsumed_tail or obj.unused_data):
                return None
            return expanded
        except zlib.error:
            return None

    if encoding == 'gzip':
        return decompress(16 + zlib.MAX_WBITS)
    decoded = decompress(zlib.MAX_WBITS)
    return decoded if decoded is not None else decompress(-zlib.MAX_WBITS)


def _decode_text(body: bytes, content_type: str) -> str:
    charset = 'utf-8'
    match = _CHARSET.search(content_type)
    if match:
        charset = match.group(1)
    try:
        return body.decode(charset, 'replace')
    except (LookupError, UnicodeError):
        return body.decode('utf-8', 'replace')


def _flatten_json(value: object, base: str) -> list[tuple[str, str]]:
    """Iterative, bounded flattening of nested objects and arrays."""
    results: list[tuple[str, str]] = []
    stack = [(value, base, 0)]
    while stack and len(results) < MAX_FIELDS:
        current, path, depth = stack.pop()
        if isinstance(current, dict):
            if depth >= MAX_NESTING:
                continue
            for k, v in reversed(list(current.items())[:MAX_FIELDS]):
                stack.append((v, f'{path}.{k}', depth+1))
        elif isinstance(current, list):
            if depth >= MAX_NESTING:
                continue
            for i in range(min(len(current), MAX_FIELDS)-1, -1, -1):
                stack.append((current[i], f'{path}[{i}]', depth+1))
        elif current is not None:
            if isinstance(current, bool):
                value_text = 'true' if current else 'false'
            else:
                value_text = str(current)
            results.append((path, value_text))
    return results


def _multipart_fields(body: bytes, content_type: str) -> list[tuple[str, str]]:
    match = _BOUNDARY.search(content_type)
    if not match:
        return []
    boundary = match.group(1) or match.group(2)
    if not boundary or any(c in boundary for c in '\r\n'):
        return []
    # MIME parsing is a standard-library facility that respects multipart
    # boundaries, escaping and per-part content-type/charset.
    try:
        wrapper = (f'MIME-Version: 1.0\r\nContent-Type: multipart/form-data; '
                   f'boundary="{boundary}"\r\n\r\n').encode('ascii')
        parsed = BytesParser(policy=policy.default).parsebytes(wrapper + body)
    except (ValueError, UnicodeError, TypeError):
        return []
    if not parsed.is_multipart():
        return []
    results: list[tuple[str, str]] = []
    for idx, part in enumerate(parsed.iter_parts()):
        if idx >= MAX_PARTS or len(results) >= MAX_FIELDS:
            break
        if part.get_content_disposition() != 'form-data':
            continue
        if part.get_filename() is not None:
            continue  # Never inspect uploaded file attachments as form strings.
        field = part.get_param('name', header='content-disposition')
        if not field or part.get_content_maintype() not in ('text', 'application'):
            continue
        if part.get_content_type() not in ('text/plain', 'application/json'):
            continue
        payload = part.get_payload(decode=True)
        if payload is None or len(payload) > MAX_HTTP_BODY:
            continue
        results.append((f'form.{field}', _decode_text(payload,part.get('content-type', ''))))
    return results


def extract_fields(message: HttpMessage) -> list[tuple[str, str]]:
    """Extract HTTP header, query and supported structured body values."""
    fields: list[tuple[str, str]] = [(f'header.{name}', value)
                                    for name, value in message.headers.items()]
    if message.is_request:
        parts = message.start_line.split(' ', 2)
        if len(parts) == 3:
            try:
                for key, value in parse_qsl(urlsplit(parts[1]).query,
                                            keep_blank_values=True, max_num_fields=MAX_FIELDS):
                    fields.append((f'query_parameter.{key}', value))
            except ValueError:
                pass
    body = _decompress_body(message)
    if body is None:
        return fields[:MAX_FIELDS]
    ct = message.headers.get('content-type', '')
    lower_ct = ct.lower()
    if 'multipart/form-data' in lower_ct:
        fields.extend(_multipart_fields(body, ct))
    else:
        text = _decode_text(body, ct)
        if 'application/json' in lower_ct or text.lstrip().startswith(('{', '[')):
            try:
                fields.extend(_flatten_json(json.loads(text), 'json_body'))
            except (ValueError, RecursionError):
                pass
        elif 'application/x-www-form-urlencoded' in lower_ct:
            try:
                for key, value in parse_qsl(text, keep_blank_values=True,
                                            max_num_fields=MAX_FIELDS):
                    fields.append((f'form.{key}', value))
            except ValueError:
                pass
        elif body and (lower_ct.startswith('text/') or not lower_ct):
            fields.append(('body.text', text))
    return fields[:MAX_FIELDS]


@dataclass(frozen=True)
class HttpParseResult:
    """Compatibility with the detailed-parser API used by the labelled evaluator."""
    spans: list[HttpSpan]
    parsed_bytes: int
    total_bytes: int
    unterminated_http: bool


def parse_http_stream_detailed(data: bytes) -> HttpParseResult:
    diagnostics: list[HttpParseDiagnostic] = []
    spans = parse_http_stream_with_spans(data, diagnostics=diagnostics)
    parsed_bytes = spans[-1].end_offset if spans else 0
    return HttpParseResult(spans, parsed_bytes, len(data),
                           any(d.incomplete for d in diagnostics))


def body_skip_reason(message: HttpMessage) -> str | None:
    """Sanitized reason an HTTP body was not inspected."""
    if not message.body:
        return None
    encoding = message.headers.get('content-encoding', 'identity').strip().lower()
    if encoding in ('', 'identity') and len(message.body) <= MAX_HTTP_BODY:
        return None
    if _decompress_body(message) is not None:
        return None
    return ('unsupported_content_encoding'
            if encoding not in ('', 'identity', 'gzip', 'deflate')
            else 'undecodable_body')
