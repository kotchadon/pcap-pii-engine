"""Indexed, value-free HTTP navigation and opt-in captured response source.

All byte coordinates are half-open. A field's source ranges support the whole
field, never a detector character span. This module does not fetch resources.
"""
from __future__ import annotations

import hashlib
import json
import os
import re

from .http_extract import parse_http_stream_with_spans, _decompress_body, _decode_text

MAX_PAGE = 100
MAX_SOURCE_RANGES = 256
MAX_CONTENT_BYTES = 64 * 1024
_ID = re.compile(r'[A-Za-z0-9_-]{1,160}\Z')
# Unknown names can themselves encode sensitive values. Export only this fixed
# vocabulary, with every value withheld in metadata.
_HEADER_NAMES = frozenset(('host', 'content-type', 'content-length', 'content-encoding',
    'transfer-encoding', 'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
    'accept', 'accept-encoding', 'accept-language', 'user-agent', 'referer', 'origin',
    'connection', 'expect', 'location', 'cache-control', 'date', 'server', 'vary'))


def message_metadata(record, session):
    """Small additive engine hook; contains no header/body/target values."""
    request = record.message.is_request
    src, sport, dst, dport = record.direction
    parts = record.message.start_line.split(' ', 2)
    status = None if request else int(parts[1])
    client, server = ((src, sport), (dst, dport)) if request else ((dst, dport), (src, sport))
    return dict(message_type='request' if request else 'response', session=session,
                direction='client_to_server' if request else 'server_to_client',
                source={'ip': src, 'port': sport}, destination={'ip': dst, 'port': dport},
                client={'ip': client[0], 'port': client[1]}, server={'ip': server[0], 'port': server[1]},
                endpoint_attribution='http_role_observed', timestamp=record.timestamp,
                ordinal=record.ordinal, method=parts[0] if request else None, status=status,
                interim_response=status is not None and 100 <= status < 200 and status != 101,
                association_basis='http2_stream_id' if record.protocol == 'h2' else 'directional_fifo_best_effort',
                reconstruction_complete=(False if getattr(record.span, 'body_framing', '') == 'close_delimited_uninspected'
                                         else bool(getattr(record.span, 'complete', True))),
                header_names=sorted(name for name in record.message.headers if name in _HEADER_NAMES),
                header_count=len(record.message.headers),
                unknown_header_count=sum(name not in _HEADER_NAMES for name in record.message.headers),
                header_values='withheld')


def create_index(conn):
    conn.executescript("""
        CREATE INDEX investigation_messages ON rows(kind,json_extract(data,'$.http_message_id'),n);
        CREATE INDEX investigation_findings ON rows(kind,json_extract(data,'$.evidence.http_message_id'),n);
        CREATE INDEX investigation_flows ON rows(kind,json_extract(data,'$.flow_id'));
        CREATE TABLE transactions(transaction_id TEXT PRIMARY KEY, n INTEGER, flow_id TEXT);
        CREATE INDEX transactions_order ON transactions(n);
        CREATE TABLE transaction_messages(message_id TEXT PRIMARY KEY, transaction_id TEXT, n INTEGER);
        CREATE INDEX transaction_members ON transaction_messages(transaction_id,n);
        CREATE TABLE source_intervals(stream_id TEXT,start INTEGER,end INTEGER,n INTEGER);
        CREATE INDEX source_lookup ON source_intervals(stream_id,end,start);
        CREATE TABLE finding_fields(field_id TEXT,n INTEGER,PRIMARY KEY(field_id,n));
    """)


def index_row(conn, kind, row, n):
    if kind == 'http_evidence':
        tx = row.get('http_request_id') or row['http_message_id']
        conn.execute('INSERT OR IGNORE INTO transactions VALUES(?,?,?)', (tx, n, row['flow_id']))
        conn.execute('INSERT INTO transaction_messages VALUES(?,?,?)', (row['http_message_id'], tx, n))
    elif kind == 'stream_evidence' and row.get('row_type') == 'source_range':
        conn.execute('INSERT INTO source_intervals VALUES(?,?,?,?)',
                     (row['stream_id'], row['stream_start'], row['stream_end'], n))
    elif kind == 'findings':
        conn.executemany('INSERT OR IGNORE INTO finding_fields VALUES(?,?)',
                         [(fid, n) for fid in row.get('evidence', {}).get('field_ids', [])])


def _bounds(offset, limit):
    if type(offset) is not int or type(limit) is not int or not 0 <= offset <= 4_000_000 or not 1 <= limit <= MAX_PAGE:
        raise ValueError('Invalid page')


def _id(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError('Invalid evidence identifier')
    return value


def _one(conn, kind, evidence_id):
    row = conn.execute("SELECT data FROM rows WHERE kind=? AND json_extract(data,'$.evidence_id')=?",
                       (kind, evidence_id)).fetchone()
    if row is None:
        raise KeyError('Evidence unavailable')
    return json.loads(row[0])


def _transaction(conn, transaction_id):
    rows = conn.execute("SELECT r.data FROM transaction_messages m JOIN rows r ON r.kind='http_evidence' AND r.n=m.n WHERE m.transaction_id=? ORDER BY m.n LIMIT ?",
                        (transaction_id, MAX_PAGE + 1)).fetchall()
    messages = [json.loads(r[0]) for r in rows[:MAX_PAGE]]
    return dict(transaction_id=transaction_id, request_id=messages[0].get('http_request_id') if messages else None,
                flow_id=messages[0]['flow_id'] if messages else None, messages=messages,
                messages_truncated=len(rows) > MAX_PAGE)


def conversations(conn, *, offset=0, limit=25):
    _bounds(offset, limit)
    total = conn.execute('SELECT count(*) FROM transactions').fetchone()[0]
    ids = conn.execute('SELECT transaction_id FROM transactions ORDER BY n LIMIT ? OFFSET ?', (limit, offset)).fetchall()
    return dict(items=[_transaction(conn, row[0]) for row in ids], total=total, offset=offset, limit=limit)


def _page(conn, kind, message_id, offset, limit, field_id=''):
    _bounds(offset, limit)
    if kind == 'findings' and field_id:
        clause = "kind='findings' AND n IN (SELECT n FROM finding_fields WHERE field_id=?)"
        params = [field_id]
    else:
        path = '$.evidence.http_message_id' if kind == 'findings' else '$.http_message_id'
        clause = f"kind=? AND json_extract(data,'{path}')=?"
        params = [kind, message_id]
    total = conn.execute('SELECT count(*) FROM rows WHERE '+clause, params).fetchone()[0]
    items = conn.execute('SELECT data FROM rows WHERE '+clause+' ORDER BY n LIMIT ? OFFSET ?', params+[limit, offset])
    decoded = [json.loads(r[0]) for r in items]
    if kind == 'findings':
        for item in decoded:
            location = item.get('location', '')
            if location.startswith('header.') and location[7:] not in _HEADER_NAMES:
                item['location'] = 'header.[withheld-name]'
    return dict(items=decoded, total=total, offset=offset, limit=limit)


def source_ranges(conn, stream_id, ranges):
    """Intersect recorded source intervals; never infer offsets from text."""
    result = []
    truncated = False
    for wanted in ranges:
        start, end = wanted['start'], wanted['end']
        if not (type(start) is int and type(end) is int and 0 <= start <= end):
            raise ValueError('Invalid source range')
        rows = conn.execute("SELECT r.data FROM source_intervals s JOIN rows r ON r.kind='stream_evidence' AND r.n=s.n WHERE s.stream_id=? AND s.end>? ORDER BY s.end,s.start LIMIT ?",
                            (stream_id, start, MAX_SOURCE_RANGES + 1))
        for raw, in rows:
            source = json.loads(raw)
            # Canonical reconstruction intervals are disjoint and ordered. An
            # indexed seek plus this stop prevents scanning the entire suffix
            # of a very long stream for a small range with no source coverage.
            if source['stream_start'] >= end:
                break
            if len(result) >= MAX_SOURCE_RANGES:
                truncated = True
                break
            a, b = max(start, source['stream_start']), min(end, source['stream_end'])
            shift, length = a-source['stream_start'], b-a
            clipped = dict(source, stream_start=a, stream_end=b,
                           frame_start=source['frame_start']+shift, frame_end=source['frame_start']+shift+length,
                           tcp_seq_start=(source['tcp_seq_start']+shift) % 2**32,
                           tcp_seq_end=(source['tcp_seq_start']+shift+length) % 2**32)
            clipped['file_start'] = None if source['file_start'] is None else source['file_start']+shift
            clipped['file_end'] = None if clipped['file_start'] is None else clipped['file_start']+length
            clipped['packet'] = _one(conn, 'packet_evidence', source['frame_id'])
            result.append(clipped)
        if truncated:
            break
    return result, truncated


def investigation(conn, *, message_id, field_id='', field_offset=0, finding_offset=0, limit=50):
    message = _one(conn, 'http_evidence', _id(message_id))
    selected = _one(conn, 'field_evidence', _id(field_id)) if field_id else None
    if selected and selected['http_message_id'] != message_id:
        raise KeyError('Field does not belong to message')
    ranges = (selected['stream_ranges'] if selected else message.get('stream_ranges',
              [{'start': message['stream_start'], 'end': message['stream_end']}]))
    sources, truncated = source_ranges(conn, message['stream_id'], ranges)
    covered = bool(ranges)
    for wanted in ranges:
        position = wanted['start']
        for source in sorted(sources, key=lambda r: r['stream_start']):
            if source['stream_start'] <= position < source['stream_end']:
                position = min(wanted['end'], source['stream_end'])
        if position != wanted['end']:
            covered = False
    flow = conn.execute("SELECT data FROM rows WHERE kind='flows' AND json_extract(data,'$.flow_id')=?", (message['flow_id'],)).fetchone()
    return dict(message=message, transaction=_transaction(conn, message.get('http_request_id') or message_id),
                stream=_one(conn, 'stream_evidence', message['stream_id']),
                flow=json.loads(flow[0]) if flow else None,
                fields=_page(conn, 'field_evidence', message_id, field_offset, limit),
                findings=_page(conn, 'findings', message_id, finding_offset, limit, field_id),
                selected_field=selected, source_ranges=sources, source_ranges_truncated=truncated,
                verification={'status': 'recorded_source_ranges' if covered and not truncated else 'incomplete_source_coverage',
                              'coverage_complete': covered and not truncated, 'raw_detection_span': 'unavailable',
                              'scope': 'whole_field' if selected else 'whole_message'},
                limitations=['recorded_offsets_are_not_independently_reverified_capture_bytes',
                             'detector_character_offsets_are_not_raw_byte_offsets'] +
                             ([] if not truncated else ['source_range_page_limit']))


def recover_content(conn, capture, identity, *, message_id):
    """Return plain source text only after checking the complete retained file.

    Reuse the HTTP parser on one small, fully sourced message. No arbitrary
    paths, URLs, keys, or cross-capture references are accepted.
    """
    message = _one(conn, 'http_evidence', _id(message_id))
    if message.get('message_type') != 'response' or message.get('protocol') != 'http/1' or not message.get('contiguous'):
        raise ValueError('Only contiguous HTTP/1 response source is supported')
    if message.get('body_framing') == 'close_delimited_uninspected':
        raise ValueError('Close-delimited response completeness is unknown')
    start, end = message['stream_start'], message['stream_end']
    if not 0 < end-start <= MAX_CONTENT_BYTES:
        raise ValueError('Response exceeds 64 KiB captured-message limit')
    sources, truncated = source_ranges(conn, message['stream_id'], [{'start': start, 'end': end}])
    if truncated or not sources:
        raise ValueError('Incomplete source coverage')
    sources.sort(key=lambda s: s['stream_start'])
    descriptor = os.open(capture, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.sha256()
        while block := stream.read(256 * 1024):
            digest.update(block)
        if (identity.get('identity_status') != 'verified_read' or
            digest.hexdigest() != identity.get('capture_sha256') or before.st_size != identity.get('capture_bytes')):
            raise ValueError('Retained capture identity mismatch')
        pieces, position = [], start
        for source in sources:
            a, b = source['file_start'], source['file_end']
            if source['stream_start'] != position or a is None or b is None or not 0 <= a <= b <= before.st_size or b-a != source['stream_end']-position:
                raise ValueError('Incomplete or ambiguous source coverage')
            stream.seek(a)
            raw = stream.read(b-a)
            if len(raw) != b-a:
                raise ValueError('Captured source unavailable')
            pieces.append(raw)
            position = source['stream_end']
        after = os.fstat(stream.fileno())
        if position != end or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Retained capture changed during verification')
    spans = parse_http_stream_with_spans(b''.join(pieces))
    if len(spans) != 1 or spans[0].end_offset != end-start or spans[0].body_framing != message['body_framing']:
        raise ValueError('Response requires unavailable request framing context')
    response = spans[0].message
    media = response.headers.get('content-type', '').split(';', 1)[0].strip().lower()
    if not (media.startswith('text/') or media in ('application/json', 'application/xml', 'application/xhtml+xml')):
        raise ValueError('Only declared textual response content is supported')
    body = _decompress_body(response)
    if body is None:
        raise ValueError('Unsupported or excessive content transformation')
    partial = len(body) > MAX_CONTENT_BYTES
    text = _decode_text(body[:MAX_CONTENT_BYTES], response.headers.get('content-type', ''))
    return dict(message_id=message_id, text=text, is_html=media in ('text/html', 'application/xhtml+xml'),
                content_type=media, status='partial' if partial else 'recovered',
                captured_message_bytes=end-start, decoded_body_bytes=len(body), capture_sha256=digest.hexdigest(),
                verification='capture_sha256_reverified',
                limitations=['source_text_only_not_a_rendered_webpage', 'external_resources_not_fetched',
                             'text_decoding_may_replace_invalid_characters'] + (['decoded_content_truncated_at_64_kib'] if partial else []))
