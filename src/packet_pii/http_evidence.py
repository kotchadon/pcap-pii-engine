"""Conservative, value-free HTTP field source evidence.

All ranges are zero-based half-open TCP direction offsets. Exact means the
whole extracted value maps to the indicated bytes using ``text_encoding``;
it does not assert character indices are byte indices. Transformed sources
support the field but cannot be narrowed to a detection's decoded span.
"""
from __future__ import annotations

import codecs
import json
import re

from .http_extract import (HttpSpan, MAX_FIELDS, MAX_NESTING, _CHARSET,
                           _decode_text, _decompress_body)

_JSON_TOKEN = re.compile(rb'\s*("(?:[^"\\\x00-\x1f]|\\.)*"|[{}\[\]:,]|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)')
_JSON_WS = re.compile(rb'\s*')


def _json_sources(body: bytes) -> dict[str, list[tuple[int, int, bool]]]:
    """Locate JSON scalar tokens without conflating keys with values.

    Only UTF-8 byte input is used. Duplicate/logically colliding paths retain
    multiple entries so callers cannot accidentally assert an exact match.
    Token/node budgets fail to conservative whole-body evidence.
    """
    found: dict[str, list[tuple[int, int, bool]]] = {}
    position = 0
    count = 0

    def token():
        nonlocal position, count
        count += 1
        if count > MAX_FIELDS * 16:
            raise ValueError
        match = _JSON_TOKEN.match(body, position)
        if match is None:
            raise ValueError
        position = match.end()
        return match[1], match.start(1), match.end(1)

    def value(path, depth):
        if depth > MAX_NESTING:
            raise ValueError
        raw, start, end = token()
        if raw == b'{':
            # Peek only whitespace + closing delimiter; keys use the same
            # JSON decoder as extraction so escaped keys remain consistent.
            peek = _JSON_WS.match(body, position).end()
            if body[peek:peek + 1] == b'}':
                token()
                return
            while True:
                key, _, _ = token()
                if not key.startswith(b'"') or token()[0] != b':':
                    raise ValueError
                name = json.loads(key.decode('utf-8'))
                value(f'{path}.{name}', depth + 1)
                delim = token()[0]
                if delim == b'}':
                    return
                if delim != b',':
                    raise ValueError
        elif raw == b'[':
            peek = _JSON_WS.match(body, position).end()
            if body[peek:peek + 1] == b']':
                token()
                return
            for index in range(MAX_FIELDS):
                value(f'{path}[{index}]', depth + 1)
                delim = token()[0]
                if delim == b']':
                    return
                if delim != b',':
                    raise ValueError
            raise ValueError
        elif raw not in (b'}', b']', b':', b','):
            escaped = b'\\' in raw if raw.startswith(b'"') else False
            if raw.startswith(b'"'):
                start, end = start + 1, end - 1
            found.setdefault(path, []).append((start, end, escaped))
            if len(found) > MAX_FIELDS:
                raise ValueError
        else:
            raise ValueError

    try:
        value('json_body', 0)
        if body[position:].strip():
            return {}
    except (ValueError, UnicodeError, RecursionError):
        return {}
    return found


def evidence_for_fields(stream: bytes, span: HttpSpan,
                        fields: list[tuple[str, str]]) -> list[dict]:
    """Return metadata aligned with unchanged ``extract_fields`` output.

    No raw field value, path, header value or request target is returned.
    Legacy spans lacking boundary metadata get message-level references.
    """
    message = span.message
    start, end = span.start_offset, span.end_offset
    valid = 0 <= start <= end <= len(stream)
    boundaries = (valid and span.header_end is not None and span.body_start is not None
                  and start <= span.header_end == span.body_start <= end)
    header_sources: dict[str, list[tuple[int, int]]] = {}
    if boundaries:
        pos = stream.find(b'\r\n', start, span.header_end) + 2
        while start < pos < span.header_end - 2:
            line_end = stream.find(b'\r\n', pos, span.header_end)
            if line_end < pos:
                break
            line = stream[pos:line_end]
            name, separator, raw = line.partition(b':')
            if not separator:
                break
            left = len(raw) - len(raw.lstrip(b' \t'))
            right = max(left, len(raw.rstrip(b' \t')))
            a = pos + len(name) + 1
            header_sources.setdefault(name.decode('ascii').lower(), []).append((a + left, a + right))
            pos = line_end + 2

    ct = message.headers.get('content-type', '')
    encoding_match = _CHARSET.search(ct)
    charset = encoding_match.group(1) if encoding_match else 'utf-8'
    body = _decompress_body(message)
    body_transforms = []
    if message.headers.get('transfer-encoding', '').strip().lower() == 'chunked':
        body_transforms.append('chunked_decode')
    content_encoding = message.headers.get('content-encoding', 'identity').strip().lower()
    if content_encoding not in ('', 'identity'):
        body_transforms.append(content_encoding if content_encoding in ('gzip', 'deflate') else 'content_decode')
    # Exact character slicing is supported only for stateless encodings with
    # a validated round trip. BOM/stateful/fallback/replacement paths downgrade.
    exact_charset = None
    if body is not None:
        try:
            normalized = codecs.lookup(charset).name
            if normalized in ('utf-8', 'ascii', 'iso8859-1'):
                text = body.decode(charset, 'strict')
                if text.encode(charset) == body:
                    exact_charset = normalized
        except (LookupError, UnicodeError):
            pass
    if exact_charset is None:
        body_transforms.append('charset_decode')
    json_sources = (_json_sources(body) if body is not None and exact_charset == 'utf-8'
                    and any(p.startswith('json_body') for p, _ in fields) else {})
    results = []
    for path, value in fields[:MAX_FIELDS]:
        category = path.split('.', 1)[0]
        item = {'source_category': category, 'stream_ranges': [],
                'decoded_text_span': {'start': 0, 'end': len(value)},
                'transformations': [], 'granularity': 'unavailable', 'limitations': []}
        ranges = []
        exact = False
        text_encoding = None
        if boundaries and category == 'header':
            ranges = header_sources.get(path[7:], [])
            exact = (len(ranges) == 1 and
                     stream[ranges[0][0]:ranges[0][1]].decode('iso-8859-1') == value)
            text_encoding = 'iso-8859-1'
            if not exact:
                item['transformations'].append('header_normalization')
        elif boundaries and category == 'query_parameter':
            # URL splitting, percent/plus decoding and repeated keys: the
            # captured start line supports the field, not a guessed substring.
            first_end = stream.find(b'\r\n', start, span.header_end)
            ranges = [(start, first_end)]
            item['transformations'].append('url_decode')
        elif boundaries and category in ('body', 'json_body', 'form'):
            ranges = [(span.body_start, end)]
            item['transformations'].extend(body_transforms)
            direct = (not body_transforms and body is not None and
                      stream[span.body_start:end] == body)
            if category == 'body' and direct and _decode_text(body, ct) == value:
                exact = True
                text_encoding = exact_charset
            elif category == 'json_body':
                tokens = json_sources.get(path, [])
                if len(tokens) == 1:
                    a, b, escaped = tokens[0]
                    if escaped:
                        item['transformations'].append('json_string_unescape')
                    if direct and not escaped and body[a:b].decode('utf-8') == value:
                        ranges = [(span.body_start + a, span.body_start + b)]
                        exact, text_encoding = True, 'utf-8'
                if not exact:
                    item['transformations'].append('json_parse')
            elif category == 'form':
                item['transformations'].append('multipart_parse' if 'multipart/form-data' in ct.lower()
                                                else 'url_decode')
        if ranges:
            item['stream_ranges'] = [{'start': a, 'end': b} for a, b in ranges]
            item['granularity'] = 'exact_stream_range' if exact else 'transformed_source_range'
            if exact:
                item['text_encoding'] = text_encoding
            else:
                item['limitations'].append('decoded_span_not_raw_byte_exact')
        elif valid:
            item['stream_ranges'] = [{'start': start, 'end': end}]
            item['granularity'] = 'message_level_only'
            item['limitations'].append('field_source_mapping_unavailable')
        results.append(item)
    return results
