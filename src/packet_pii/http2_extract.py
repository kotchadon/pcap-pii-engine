"""Bounded optional plaintext HTTP/2 evidence decoder (RFC 9113 / RFC 7541).

Requires an observed client connection preface and optional ``hpack``. It is a
passive, conservative subset: no TLS decryption, h2c upgrade, push, CONNECT,
non-default compression/frame-size SETTINGS or cross-direction flow-control
chronology. Diagnostics are constant codes; raw evidence never enters them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re

from .http_extract import HttpMessage, MAX_HTTP_BODY, MAX_FIELDS

PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
MAX_FRAME_BYTES = 16384
MAX_FRAMES = 1024
MAX_STREAMS = 256
MAX_HEADER_BYTES = 64 * 1024
MAX_CONTEXT_BYTES = 256 * 1024
MAX_TOTAL_BODY = 4 * 1024 * 1024
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_FIELD_SOURCE_RANGES = 64
_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9a-z-]+\Z")
_METHOD = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


@dataclass
class Http2Message:
    message: HttpMessage
    stream_id: int
    direction: str
    stream_ranges: tuple[tuple[int, int], ...]
    header_source_ranges: tuple[tuple[int, int], ...]
    body_stream_ranges: tuple[tuple[int, int], ...]
    complete: bool
    pairing_status: str = 'request_only'
    limitations: tuple[str, ...] = ('http2_flow_control_not_validated',)

    @property
    def start_offset(self):
        return self.stream_ranges[0][0]

    @property
    def end_offset(self):
        return self.stream_ranges[-1][1]


@dataclass
class Http2ParseResult:
    messages: list[Http2Message]
    diagnostics: list[dict]
    recognized: bool


@dataclass
class _MessageState:
    message: HttpMessage
    ranges: list[tuple[int, int]]
    header_sources: tuple[tuple[int, int], ...]
    no_body: bool = False
    body: bytearray = field(default_factory=bytearray)
    body_ranges: list[tuple[int, int]] = field(default_factory=list)


class _Stop(Exception):
    def __init__(self, reason, incomplete=False):
        self.reason, self.incomplete = reason, incomplete


def _headers(decoded, request, trailer=False):
    pseudo, headers = {}, {}
    regular = False
    if len(decoded) > 200:
        raise _Stop('http2_header_limit_exceeded')
    for name, value in decoded:
        if (not name or any(c in (0, 10, 13) for c in value)
                or value[:1] in (b' ', b'\t') or value[-1:] in (b' ', b'\t')):
            raise _Stop('http2_invalid_http_fields')
        if name.startswith(b':'):
            if trailer or regular or name in pseudo or not _NAME.fullmatch(name[1:]):
                raise _Stop('http2_invalid_http_fields')
            pseudo[name] = value
            continue
        if not _NAME.fullmatch(name):
            raise _Stop('http2_invalid_http_fields')
        regular = True
        key, val = name.decode('ascii'), value.decode('iso-8859-1')
        if key in ('connection', 'proxy-connection', 'keep-alive', 'transfer-encoding', 'upgrade'):
            raise _Stop('http2_invalid_http_fields')
        if key == 'te' and (not request or val != 'trailers'):
            raise _Stop('http2_invalid_http_fields')
        if key == 'content-length':
            if key in headers or trailer or not re.fullmatch('[0-9]{1,12}', val):
                raise _Stop('http2_invalid_content_length')
        if key in headers:
            headers[key] += ('; ' if key == 'cookie' else ', ') + val
        else:
            headers[key] = val
    if trailer:
        return '', headers
    if request:
        if pseudo.get(b':method') == b'CONNECT':
            raise _Stop('http2_connect_unsupported')
        if (set(pseudo) - {b':method', b':scheme', b':path', b':authority'} or
                not {b':method', b':scheme', b':path'} <= set(pseudo) or
                not _METHOD.fullmatch(pseudo[b':method']) or not pseudo[b':scheme'] or
                not pseudo[b':path'] or any(c <= 32 or c == 127 for c in pseudo[b':path'])):
            raise _Stop('http2_invalid_http_fields')
        # Authority remains a regular logical field for existing extractors.
        if b':authority' in pseudo:
            authority = pseudo[b':authority'].decode('iso-8859-1')
            if 'host' in headers and headers['host'] != authority:
                raise _Stop('http2_invalid_http_fields')
            headers.setdefault('host', authority)
        return (pseudo[b':method'].decode('ascii') + ' ' +
                pseudo[b':path'].decode('iso-8859-1') + ' HTTP/2'), headers
    if set(pseudo) != {b':status'} or not re.fullmatch(rb'[1-5][0-9]{2}', pseudo[b':status']):
        raise _Stop('http2_invalid_http_fields')
    if pseudo[b':status'] == b'101':
        raise _Stop('http2_invalid_http_fields')
    return 'HTTP/2 ' + pseudo[b':status'].decode('ascii'), headers


def _direction(data, request, decoder_type, methods, diagnostics):
    direction = 'client_to_server' if request else 'server_to_client'
    records, active, closed, seen = [], {}, set(), set()
    offset = len(PREFACE) if request else 0
    first = True
    highest = 0
    decoder = decoder_type(max_header_list_size=MAX_HEADER_BYTES)
    decoder.max_allowed_table_size = 4096
    context, context_bytes, total_body = [], 0, 0
    pending = None
    sid = 0

    def stop(reason, incomplete=False):
        raise _Stop(reason, incomplete)

    def emit(stream_id, complete):
        if len(records) >= MAX_STREAMS * 2:
            stop('http2_message_limit_exceeded')
        state = active.pop(stream_id)
        length = state.message.headers.get('content-length')
        if complete and not state.no_body and length is not None and int(length) != len(state.body):
            stop('http2_content_length_mismatch')
        message = HttpMessage(state.message.start_line, state.message.headers,
                              bytes(state.body), request)
        records.append(Http2Message(message, stream_id, direction, tuple(state.ranges),
                                    state.header_sources, tuple(state.body_ranges), complete))
        if complete:
            closed.add(stream_id)

    try:
        if len(data) > MAX_INPUT_BYTES:
            stop('http2_input_limit_exceeded')
        for _ in range(MAX_FRAMES):
            if offset == len(data):
                break
            if len(data) - offset < 9:
                stop('http2_incomplete_frame', True)
            size = int.from_bytes(data[offset:offset+3], 'big')
            kind, flags = data[offset+3:offset+5]
            sid = int.from_bytes(data[offset+5:offset+9], 'big') & 0x7fffffff
            if size > MAX_FRAME_BYTES:
                stop('http2_frame_limit_exceeded')
            end = offset + 9 + size
            if end > len(data):
                stop('http2_incomplete_frame', True)
            payload_at = offset + 9
            payload = data[payload_at:end]
            full_range = (offset, end)
            if first and (kind != 4 or flags & 1):
                stop('http2_initial_settings_missing')
            first = False
            if pending is not None and (kind != 9 or sid != pending['sid']):
                stop('http2_interleaved_header_block')
            if kind == 4:
                if sid or size % 6 or (flags & 1 and size):
                    stop('http2_invalid_settings')
                for i in range(0, size, 6):
                    setting = int.from_bytes(payload[i:i+2], 'big')
                    val = int.from_bytes(payload[i+2:i+6], 'big')
                    if (setting == 2 and (val not in (0, 1) or not request)
                            or setting == 4 and val > 0x7fffffff
                            or setting == 5 and not 16384 <= val <= 0xffffff):
                        stop('http2_invalid_settings')
                    # Direction-only byte order cannot prove when peer SETTINGS
                    # took effect; only default table/frame negotiation is used.
                    if setting == 1 and val != 4096 or setting == 5 and val != 16384 or setting == 8:
                        stop('http2_settings_context_unsupported')
            elif kind in (1, 9):
                if not sid or not sid & 1:
                    stop('http2_invalid_stream_id')
                if sid in closed:
                    stop('http2_stream_closed')
                if kind == 9:
                    if pending is None:
                        stop('http2_unexpected_continuation')
                else:
                    if request and sid not in seen:
                        if sid <= highest:
                            stop('http2_invalid_stream_order')
                        highest = sid
                    if not request and sid not in methods:
                        stop('http2_response_without_request_context')
                    if sid not in seen:
                        if len(seen) >= MAX_STREAMS:
                            stop('http2_stream_limit_exceeded')
                        seen.add(sid)
                    padding = 0
                    if flags & 8:
                        if not payload:
                            stop('http2_invalid_padding')
                        padding, payload_at = payload[0], payload_at + 1
                    if flags & 32:
                        if end - padding - payload_at < 5:
                            stop('http2_invalid_priority')
                        dep = int.from_bytes(data[payload_at:payload_at+4], 'big') & 0x7fffffff
                        if dep == sid:
                            stop('http2_invalid_priority')
                        payload_at += 5
                    if payload_at > end - padding:
                        stop('http2_invalid_padding')
                    payload = data[payload_at:end-padding]
                    pending = {'sid': sid, 'block': bytearray(), 'ranges': [],
                               'end_stream': bool(flags & 1), 'trailer': sid in active}
                if len(pending['block']) + len(payload) > MAX_HEADER_BYTES:
                    stop('http2_header_limit_exceeded')
                pending['block'].extend(payload)
                pending['ranges'].append(full_range)
                context_bytes += len(payload)
                if context_bytes > MAX_CONTEXT_BYTES:
                    stop('http2_header_context_limit_exceeded')
                context.append((payload_at, payload_at + len(payload)))
                if flags & 4:
                    try:
                        decoded = list(decoder.decode(bytes(pending['block']), raw=True))
                    except Exception:
                        # HPACK exception text can contain raw input. Never retain it.
                        stop('http2_hpack_decode_failed')
                    line, headers = _headers(decoded, request, pending['trailer'])
                    if pending['trailer']:
                        if not pending['end_stream']:
                            stop('http2_invalid_trailers')
                        active[sid].ranges.extend(pending['ranges'])
                        emit(sid, True)
                        # Trailers update HPACK state and message framing, but
                        # are not merged into the initial extracted headers.
                        records[-1].limitations += ('http2_trailers_uninspected',)
                        diagnostics.append({'reason': 'http2_trailers_uninspected',
                                            'direction': direction,
                                            'start_offset': pending['ranges'][0][0],
                                            'stream_id': sid, 'incomplete': False})
                    else:
                        status = int(line.split()[1]) if not request else None
                        no_body = status is not None and (status < 200 or status in (204, 304)
                                                         or methods[sid] == 'HEAD')
                        active[sid] = _MessageState(HttpMessage(line, headers, b'', request),
                                                    pending['ranges'], tuple(context), no_body)
                        if status is not None and status < 200:
                            if pending['end_stream']:
                                stop('http2_invalid_interim_response')
                            if len(records) >= MAX_STREAMS * 2:
                                stop('http2_message_limit_exceeded')
                            state = active.pop(sid)
                            records.append(Http2Message(state.message, sid, direction,
                                                        tuple(state.ranges), state.header_sources, (), True))
                        elif pending['end_stream']:
                            emit(sid, True)
                    pending = None
            elif kind == 0:
                if sid in closed:
                    stop('http2_stream_closed')
                if not sid or sid not in active:
                    stop('http2_data_without_headers')
                padding = 0
                if flags & 8:
                    if not payload:
                        stop('http2_invalid_padding')
                    padding, payload_at = payload[0], payload_at + 1
                if payload_at > end - padding:
                    stop('http2_invalid_padding')
                payload = data[payload_at:end-padding]
                state = active[sid]
                if state.no_body and payload:
                    stop('http2_body_forbidden')
                if len(state.body) + len(payload) > MAX_HTTP_BODY or total_body + len(payload) > MAX_TOTAL_BODY:
                    stop('http2_body_limit_exceeded')
                state.body.extend(payload)
                total_body += len(payload)
                state.ranges.append(full_range)
                if payload:
                    state.body_ranges.append((payload_at, payload_at + len(payload)))
                if flags & 1:
                    emit(sid, True)
            elif kind == 5:
                stop('http2_push_unsupported')
            elif kind == 3:
                if not sid or size != 4 or sid not in seen:
                    stop('http2_invalid_control_frame')
                if sid in active:
                    active[sid].ranges.append(full_range)
                    emit(sid, False)
                closed.add(sid)
                diagnostics.append({'reason': 'http2_stream_reset', 'direction': direction,
                                    'start_offset': offset, 'stream_id': sid, 'incomplete': True})
            elif kind == 8:
                if size != 4 or int.from_bytes(payload, 'big') & 0x7fffffff == 0:
                    stop('http2_invalid_window_update')
            elif kind == 2:
                if not sid or size != 5 or int.from_bytes(payload[:4], 'big') & 0x7fffffff == sid:
                    stop('http2_invalid_priority')
            elif kind == 6:
                if sid or size != 8:
                    stop('http2_invalid_control_frame')
            elif kind == 7:
                if sid or size < 8:
                    stop('http2_invalid_control_frame')
                stop('http2_goaway_observed')
            # Unknown extension frames are ignored under RFC 9113 §4.1; they
            # never become HTTP fields and remain inside frame/byte budgets.
            offset = end
        else:
            if offset < len(data):
                stop('http2_frame_count_limit_exceeded')
        if first:
            stop('http2_initial_settings_missing', True)
        if pending is not None:
            sid = pending['sid']
            stop('http2_incomplete_header_block', True)
    except _Stop as exc:
        diagnostics.append({'reason': exc.reason, 'direction': direction,
                            'start_offset': offset, 'stream_id': sid,
                            'incomplete': exc.incomplete})
        # Invalid bytes on a stream cannot leave a definitive message for it.
        if not exc.incomplete and sid:
            active.pop(sid, None)
            records = [r for r in records if r.stream_id != sid]
    for stream_id in list(active):
        if len(records) >= MAX_STREAMS * 2:
            diagnostics.append({'reason': 'http2_message_limit_exceeded', 'direction': direction,
                                'start_offset': offset, 'stream_id': stream_id, 'incomplete': False})
            break
        emit(stream_id, False)
        diagnostics.append({'reason': 'http2_incomplete_stream', 'direction': direction,
                            'start_offset': offset, 'stream_id': stream_id, 'incomplete': True})
    return records


def parse_http2_connection(client_stream: bytes, server_stream: bytes = b'') -> Http2ParseResult:
    """Decode a supported observed plaintext connection, never infer TLS keys.

    Caller supplies safe contiguous TCP prefixes in their actual directions.
    Server-only/midconnection traffic has no independently proven HPACK state
    and is unrecognized. Stream identifiers establish request/response pairing.
    """
    if not client_stream.startswith(PREFACE):
        return Http2ParseResult([], [], False)
    try:
        from hpack import Decoder
    except ImportError:
        return Http2ParseResult([], [{'reason': 'http2_hpack_unavailable',
                                     'direction': 'client_to_server', 'start_offset': 0,
                                     'stream_id': 0, 'incomplete': False}], True)
    diagnostics = []
    requests = _direction(client_stream, True, Decoder, {}, diagnostics)
    methods = {r.stream_id: r.message.start_line.split()[0] for r in requests}
    responses = _direction(server_stream, False, Decoder, methods, diagnostics) if server_stream else []
    req_ids = {r.stream_id for r in requests}
    resp_ids = {r.stream_id for r in responses}
    unfinished = {r.stream_id for r in requests + responses if not r.complete}
    final_ids = {r.stream_id for r in responses if int(r.message.start_line.split()[1]) >= 200}
    for stream_id in resp_ids - final_ids:
        unfinished.add(stream_id)
        diagnostics.append({'reason': 'http2_final_response_unobserved',
                            'direction': 'server_to_client', 'start_offset': len(server_stream),
                            'stream_id': stream_id, 'incomplete': True})
    for record in requests + responses:
        if record.stream_id in unfinished:
            record.pairing_status = 'incomplete'
            record.limitations += ('http2_stream_incomplete',)
        elif record.stream_id in req_ids & resp_ids:
            record.pairing_status = 'paired'
        else:
            record.pairing_status = 'request_only' if record.message.is_request else 'response_only'
    return Http2ParseResult(requests + responses, diagnostics, True)


def http2_evidence_for_fields(record: Http2Message, fields: list[tuple[str, str]]) -> list[dict]:
    """Conservative source dependencies, not raw substring or exact HPACK spans."""
    result = []
    # Build each shared dependency list once, and downgrade before expanding
    # ranges per field. A 10k-field body must not allocate millions of dicts.
    bounded = {}
    for header, sources in ((True, record.header_source_ranges), (False, record.body_stream_ranges)):
        limited = len(sources) > MAX_FIELD_SOURCE_RANGES
        bounded[header] = ([], limited) if limited else ([{'start': a, 'end': b} for a,b in sources], False)
    for path, value in fields[:MAX_FIELDS]:
        category = path.split('.', 1)[0]
        header = category in ('header', 'query_parameter')
        sources, limited = bounded[header]
        transforms = ['hpack_decode'] if header else ['http2_data_reassembly', 'charset_decode']
        if not header:
            encoding = record.message.headers.get('content-encoding', 'identity').strip().lower()
            if encoding not in ('', 'identity'):
                transforms.append(encoding if encoding in ('gzip','deflate') else 'content_decode')
        if category == 'query_parameter' or category == 'form':
            transforms.append('multipart_or_url_decode' if category == 'form' else 'url_decode')
        if category == 'json_body':
            transforms.append('json_parse')
        result.append({'source_category': category,
                       'stream_ranges': sources,
                       'decoded_text_span': {'start': 0, 'end': len(value)},
                       'transformations': transforms,
                       'granularity': 'transformed_source_range' if sources else 'message_level_only',
                       'limitations': ['decoded_span_not_raw_byte_exact'] +
                                      (['hpack_prior_header_context_dependency'] if header else []) +
                                      (['field_source_range_limit'] if limited else [])})
    return result
