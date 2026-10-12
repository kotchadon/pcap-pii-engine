"""Packet capture -> TCP streams -> HTTP messages -> traceable PII findings.

HTTP/1.x request-response pairing is best-effort: it uses direction, stream
order and packet timing, and makes no claim to understand encrypted HTTP/2 or
missing session context.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
import time
from urllib.parse import urlsplit

from .capture import read_frames, decode_tcp, endpoint_key, reassemble, TcpPacket
from .http_extract import HttpMessage, parse_http_stream_with_spans, extract_fields
from .detect import detect_fields


@dataclass
class _Record:
    message: HttpMessage
    direction: tuple[str, int, str, int]
    timestamp: float
    start_offset: int
    message_id: str = ''
    request_id: str | None = None
    paired: bool = False


def safe_http_start_line(line: str, include_path: bool = False) -> str:
    """Redact URI paths/queries by default; remove untrusted reason phrases.

    Paths can themselves contain emails, session tokens, or user identifiers.
    An investigator who explicitly opts into raw values can see the URI path,
    but query strings remain excluded from start-line metadata.
    """
    parts = line.split(' ', 2)
    if len(parts) == 3 and not line.startswith('HTTP/'):
        url = urlsplit(parts[1])
        path = (url.path or '/') if include_path else '[path-redacted]'
        return f'{parts[0]} {path} {parts[2]}'[:300]
    if line.startswith('HTTP/'):
        return ' '.join(parts[:2])[:300]
    return line[:300]


_SAFE_FIELD_SEGMENT = re.compile(r'[A-Za-z_][A-Za-z0-9_-]{0,63}(?:\[[0-9]{1,8}\])*\Z')


def safe_field_location(location: str, include_values: bool = False) -> str:
    """Preserve useful paths while redacting suspicious attacker-controlled keys.

    JSON keys, query parameter names and multipart field names may themselves
    contain secrets or PII. The original path is still used by the detector;
    only its exported representation is redacted. This is a conservative
    syntactic filter, not a proof of complete anonymization.
    """
    if include_values:
        return location
    # A dot inside an email/identifier could masquerade as path nesting.
    # Collapse the entire attacker-controlled suffix rather than exposing it.
    if '@' in location or any(ord(c) < 32 for c in location):
        prefix = location.split('.', 1)[0]
        return f'{prefix}.[redacted-key]'
    return '.'.join(segment if _SAFE_FIELD_SEGMENT.fullmatch(segment)
                    else '[redacted-key]' for segment in location.split('.'))


def _timestamp_for_byte(segments: list[TcpPacket], offset: int) -> float:
    """Capture time of the TCP segment carrying the message's first byte.

    A segment received later in capture order may still have an earlier TCP
    sequence number. For that reason we map the stream byte offset to sequence
    numbers, not to input record order or the first SYN timestamp.
    """
    syn_starts = [p.seq + 1 for p in segments if p.flags & 0x02]
    payload_starts = [p.seq for p in segments if p.payload]
    if not payload_starts:
        return min(p.timestamp for p in segments)
    base = min(syn_starts) if syn_starts else min(payload_starts)
    seq = base + offset
    times = [p.timestamp for p in segments
             if p.payload and p.seq <= seq < p.seq + len(p.payload)]
    return min(times) if times else min(p.timestamp for p in segments)


def _pair_requests(records: list[_Record], fid: str) -> tuple[int, int, int]:
    """Correlate HTTP/1.x responses FIFO, but only for unambiguous directions.

    One initiating direction and one opposing response direction are required.
    Interim 1xx responses are linked without consuming their request, except
    101 Switching Protocols which is a terminal protocol switch. Capture gaps,
    multiplexing, and TCP tuple reuse remain limitations.
    """
    requests = [r for r in records if r.message.is_request]
    responses = [r for r in records if not r.message.is_request]
    reqdirs = {r.direction for r in requests}
    respdirs = {r.direction for r in responses}
    for index, r in enumerate(requests, 1):
        r.request_id = f'{fid}_req_{index:04d}'

    paired = 0
    if len(reqdirs) == 1 and len(respdirs) == 1:
        reqdir = next(iter(reqdirs))
        respdir = next(iter(respdirs))
        if reqdir == (respdir[2], respdir[3], respdir[0], respdir[1]):
            pending = 0
            for response in responses:
                if pending >= len(requests):
                    break
                request = requests[pending]
                # Avoid attributing earlier orphan traffic to a later request.
                if response.timestamp < request.timestamp:
                    continue
                response.request_id = request.request_id
                response.paired = True
                status = int(response.message.start_line.split(' ', 2)[1])
                if not (100 <= status < 200 and status != 101):
                    request.paired = True
                    paired += 1
                    pending += 1
    return (paired,
            sum(not r.paired for r in requests),
            sum(not r.paired for r in responses))


def analyze(path: str | Path, threshold: float = 0.8,
            include_values: bool = False) -> dict:
    if not 0 <= threshold <= 1:
        raise ValueError('Confidence threshold must be in [0,1]')
    started = time.monotonic()
    flow_packets: dict[tuple, list[TcpPacket]] = defaultdict(list)
    frames = bytes_processed = ignored = 0
    for frame in read_frames(path):
        frames += 1
        bytes_processed += len(frame.data)
        packet = decode_tcp(frame)
        if packet:
            flow_packets[endpoint_key(packet)].append(packet)
        else:
            ignored += 1

    findings = []
    http_count = http_flows = gaps = 0
    transactions = orphan_requests = orphan_responses = 0
    flow_summaries = []

    for i, (endpoints, packets) in enumerate(flow_packets.items(), start=1):
        fid = f'flow_{i:04d}'
        directions: dict[tuple, list[TcpPacket]] = defaultdict(list)
        for packet in packets:
            directions[(packet.src, packet.sport, packet.dst, packet.dport)].append(packet)
        records: list[_Record] = []
        flow_gaps = 0
        for direction, segs in directions.items():
            stream, missing = reassemble(segs)
            if missing:
                gaps += 1
                flow_gaps += 1
            for span in parse_http_stream_with_spans(stream):
                records.append(_Record(span.message, direction,
                                       _timestamp_for_byte(segs, span.start_offset),
                                       span.start_offset))

        # If two messages share a packet timestamp, keep byte order stable.
        # Stable sorting also avoids treating initial SYN times as data times.
        records.sort(key=lambda r: (r.timestamp, r.direction, r.start_offset))
        for j, r in enumerate(records, 1):
            r.message_id = f'{fid}_msg_{j:04d}'
        # Requests/responses are separately sequenced per direction; sorting
        # by packet timestamp could be misleading for out-of-order captures.
        ordered = sorted(records, key=lambda r: (r.direction, r.start_offset))
        flow_tx, flow_orphan_req, flow_orphan_resp = _pair_requests(ordered, fid)
        transactions += flow_tx
        orphan_requests += flow_orphan_req
        orphan_responses += flow_orphan_resp
        http_count += len(records)
        if records:
            http_flows += 1

        for record in records:
            src, sport, dst, dport = record.direction
            timestamp = datetime.fromtimestamp(record.timestamp, timezone.utc).isoformat()
            for detected in detect_fields(extract_fields(record.message), threshold, include_values):
                # Do not publish unsalted deterministic hashes of PII/credentials.
                # Low-entropy values could be recovered by offline guessing.
                # The detector may retain internal fingerprints for deduplication,
                # but the public report deliberately excludes them.
                entry = asdict(detected)
                entry.pop('fingerprint', None)
                entry['location'] = safe_field_location(detected.location, include_values)
                entry.update({
                    'flow_id': fid,
                    'http_message_id': record.message_id,
                    'http_request_id': record.request_id,
                    'http_message_type': 'request' if record.message.is_request else 'response',
                    'timestamp': timestamp,
                    'source_ip': src, 'source_port': sport,
                    'destination_ip': dst, 'destination_port': dport,
                    'http_start_line': safe_http_start_line(record.message.start_line, include_path=include_values),
                })
                findings.append(entry)
        flow_summaries.append({
            'flow_id': fid,
            'endpoints': [{'ip': e[0], 'port': e[1]} for e in endpoints],
            'packets': len(packets),
            'http_messages': len(records),
            'http_transactions': flow_tx,
            'unpaired_requests': flow_orphan_req,
            'unpaired_responses': flow_orphan_resp,
            'stream_gaps': flow_gaps,
        })

    return {
        'metadata': {
            'engine': 'pcap-pii-engine', 'version': '0.1.0',
            'report_schema_version': '1.0.0',
            'detection_method': 'rules_only',
            'confidence_type': 'heuristic_not_calibrated',
            'threshold': threshold, 'raw_values_included': include_values,
            'scope': 'unencrypted HTTP/1.x over TCP',
        },
        'summary': {
            'packets_captured': frames,
            'non_tcp_or_unsupported_packets': ignored,
            'flows_processed': len(flow_packets),
            'http_flows': http_flows,
            'http_messages': http_count,
            'http_transactions': transactions,
            'unpaired_requests': orphan_requests,
            'unpaired_responses': orphan_responses,
            'total_data_bytes': bytes_processed,
            'processing_time_seconds': round(time.monotonic() - started, 4),
            'potential_leaks': len(findings),
            'stream_gaps': gaps,
        },
        'flows': flow_summaries, 'findings': findings,
        'limitations': [
            'Encrypted HTTPS payloads cannot be inspected without decryption',
            'No IP fragmentation or TCP sequence wraparound/reused-tuple session separation',
            'HTTP/2 and HTTP/3 not decoded; incomplete streams are ignored',
            'HTTP/1.x request-response pairing is best-effort (direction, stream order, packet timing)',
            'Rule-based detection only; contextual ML is not yet integrated',
            'Packets are buffered in memory; not for production-scale captures',
            'Findings mean possible PII exposure, not proof of exfiltration',
        ],
    }
