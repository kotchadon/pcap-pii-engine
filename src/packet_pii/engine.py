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
import hashlib
import json
import resource
import sys
import time
from urllib.parse import urlsplit

from .capture import (CaptureDiagnostics, read_frames, decode_tcp, decode_tcp_with_reason, EVIDENCE_LOSS_REASONS,
                      endpoint_key, reassemble_detailed, sequence_offset, split_tcp_sessions, TcpPacket)
from .http_extract import (HttpMessage, parse_http_stream_detailed, extract_fields, body_skip_reason,
                           MAX_MESSAGES, MAX_FIELDS)
from .detect import detect_fields, MAX_FIELD_LENGTH
from .ml_runner import MLBatchRunner, MLWorkBudget
from .hybrid import MLWorkBudget as LegacyMLWorkBudget
from .ml.detector import ContextualPIIDetector


class AnalysisLimitError(ValueError):
    """The analysis exceeded configured resources; no partial report is returned."""


MIB = 1024 * 1024
GIB = 1024 * MIB


@dataclass(frozen=True)
class AnalysisLimits:
    """Validated retention/work budgets; profiles never change Standard defaults.

    RSS is a sampled process-lifetime high-water guard, not an OS reservation.
    Prefer analyze_to_report for large workloads: analyze materializes results.
    """
    max_capture_bytes: int = 128 * MIB
    max_packets: int = 100_000
    max_flows: int = 20_000
    max_tcp_payload_bytes: int = 64 * MIB
    max_report_bytes: int = 512 * MIB
    max_findings: int = 500_000
    max_memory_bytes: int = GIB

    def __post_init__(self) -> None:
        ceilings = dict(max_capture_bytes=512*MIB, max_packets=2_000_000,
                        max_flows=300_000, max_tcp_payload_bytes=512*MIB,
                        max_report_bytes=2*GIB, max_findings=4_000_000,
                        max_memory_bytes=6*GIB)
        for key, value in asdict(self).items():
            if type(value) is not int or value <= 0:
                raise ValueError(f'{key} must be a positive integer')
            if value > ceilings[key]:
                raise ValueError(f'{key} exceeds supported configuration ceiling {ceilings[key]}')

    @classmethod
    def for_profile(cls, profile: str = 'standard', **overrides) -> 'AnalysisLimits':
        profiles = {
            'standard': {},
            'large': dict(max_capture_bytes=256*MIB, max_packets=500_000,
                          max_flows=100_000, max_tcp_payload_bytes=192*MIB,
                          max_report_bytes=GIB, max_findings=2_000_000,
                          max_memory_bytes=3*GIB),
            'stress': dict(max_capture_bytes=512*MIB, max_packets=2_000_000,
                           max_flows=300_000, max_tcp_payload_bytes=480*MIB,
                           max_report_bytes=2*GIB, max_findings=4_000_000,
                           max_memory_bytes=4*GIB),
        }
        if profile not in profiles:
            raise ValueError('profile must be standard, large or stress')
        return cls(**(profiles[profile] | overrides))


def _peak_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == 'darwin' else peak * 1024)


def _check_memory(budget: AnalysisLimits) -> None:
    if _peak_rss_bytes() > budget.max_memory_bytes:
        raise AnalysisLimitError('Analysis exceeded configured process memory budget')


@dataclass
class _Record:
    message: HttpMessage
    direction: tuple[str, int, str, int]
    timestamp: float
    start_offset: int
    message_id: str = ''
    request_id: str | None = None
    paired: bool = False
    ordinal: int = 0  # 1-based position among the same-direction messages of this TCP session


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


def _timestamp_for_byte(segments: list[TcpPacket], offset: int, base_seq: int | None = None) -> float:
    """Capture time of the TCP segment carrying the message's first byte.

    A segment received later in capture order may still have an earlier TCP
    sequence number. For that reason we map the stream byte offset to sequence
    numbers, not to input record order or the first SYN timestamp.
    """
    if base_seq is None:
        base_seq = reassemble_detailed(segments).base_seq
    times = [p.timestamp for p in segments if p.payload and base_seq is not None
             and sequence_offset(p.seq + bool(p.flags & 2), base_seq) <= offset
             < sequence_offset(p.seq + bool(p.flags & 2), base_seq) + len(p.payload)]
    if not times:
        raise ValueError('No captured payload proves the requested stream offset')
    return min(times)


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


def _analyze(path: str | Path, threshold: float = 0.8,
            include_values: bool = False, *,
            limits: AnalysisLimits | None = None, profile: str = 'standard',
            progress=None, _rows=None, timings=None,
            ml_detector: ContextualPIIDetector | None = None,
            ml_budget: 'MLWorkBudget | str | None' = None,
            ml_work_budget: 'LegacyMLWorkBudget | None' = None,
            field_observer=None, disposition_observer=None) -> dict:
    if not 0 <= threshold <= 1:
        raise ValueError('Confidence threshold must be in [0,1]')
    selected = AnalysisLimits.for_profile(profile)
    budget = limits if limits is not None else selected
    if not isinstance(budget, AnalysisLimits):
        raise TypeError('limits must be AnalysisLimits')
    _check_memory(budget)
    if ml_work_budget is not None:
        if ml_budget is not None:
            raise ValueError('Choose ml_budget or ml_work_budget, not both')
        if not isinstance(ml_work_budget, LegacyMLWorkBudget):
            raise TypeError('ml_work_budget must be hybrid.MLWorkBudget')
        ml_budget = MLWorkBudget(max_fields=ml_work_budget.max_total_fields,
                                 max_characters=ml_work_budget.max_total_characters,
                                 batch_fields=ml_work_budget.max_fields_per_batch,
                                 batch_characters=ml_work_budget.max_characters_per_batch,
                                 max_field_chars=ml_work_budget.max_field_characters,
                                 name='legacy_explicit')
    if ml_budget is None:
        ml_budget = MLWorkBudget.for_profile('standard')
    elif isinstance(ml_budget, str):
        ml_budget = MLWorkBudget.for_profile(ml_budget)
    elif not isinstance(ml_budget, MLWorkBudget):
        raise TypeError('ml_budget must be an MLWorkBudget or a profile name')
    model_version = None
    if ml_detector is not None:
        model_version = ml_detector.model_version
        if (not isinstance(model_version, str) or not model_version.strip()
                or len(model_version) > 128):
            raise ValueError('ML detector must have a valid model_version')
    started = time.monotonic()
    stages = timings if timings is not None else {}
    for stage in ('read_decode_group','session_segmentation','reassembly','http_parse',
                  'field_extraction','rule_detection','ml_inference','result_aggregation'):
        stages[stage] = 0.0
    def emit(stage, **counts):
        _check_memory(budget)
        if progress is not None:
            progress(dict(stage=stage, elapsed_seconds=time.monotonic()-started, **counts))
    emit('reading', packets=0, endpoint_pairs=0)
    read_started = time.perf_counter()
    diagnostics = CaptureDiagnostics()
    flow_packets: dict[tuple, list[tuple]] = defaultdict(list)
    frames = bytes_processed = ignored = buffered_tcp_bytes = 0
    skipped_packets: dict[str, int] = {}
    for frame in read_frames(path, diagnostics=diagnostics,
                             max_file_bytes=budget.max_capture_bytes):
        if frames >= budget.max_packets:
            raise AnalysisLimitError('Capture exceeds configured packet limit')
        frames += 1
        bytes_processed += len(frame.data)
        packet = decode_tcp(frame)
        if packet:
            key = endpoint_key(packet)
            if key not in flow_packets and len(flow_packets) >= budget.max_flows:
                raise AnalysisLimitError('Capture exceeds configured flow limit')
            if len(packet.payload) > budget.max_tcp_payload_bytes - buffered_tcp_bytes:
                raise AnalysisLimitError('Capture exceeds configured buffered TCP payload limit')
            buffered_tcp_bytes += len(packet.payload)
            # Retain only direction, time, serial number, flags and payload.
            # Endpoint strings/ports live once per pair, not in every packet.
            direction = int((packet.src,packet.sport) != key[0])
            flow_packets[key].append((direction,packet.timestamp,packet.seq,packet.flags,packet.payload))
        else:
            ignored += 1
            skip_reason = decode_tcp_with_reason(frame)[1] or 'unclassified'  # classification only for skipped frames
            skipped_packets[skip_reason] = skipped_packets.get(skip_reason, 0) + 1
        if frames % 4096 == 0:
            emit('reading', packets=frames, endpoint_pairs=len(flow_packets))
    stages['read_decode_group'] = time.perf_counter()-read_started
    emit('reconstructing', packets=frames, endpoint_pairs=len(flow_packets), sessions=0)

    findings = [] if _rows is None else _rows.findings
    http_count = http_flows = gaps = unterminated = 0
    bodies_skipped: dict[str, int] = {}
    http2_streams = tls_streams = 0
    evidence_loss_packets = sum(n for r, n in skipped_packets.items() if r in EVIDENCE_LOSS_REASONS)
    location_signals: dict[int, int] = {}  # digest(flow, message, location) -> bit 1 rules, bit 2 model; no values retained
    transactions = orphan_requests = orphan_responses = 0
    flow_summaries = [] if _rows is None else _rows.flows
    sessions_processed = 0
    result_bytes = 0
    fields_extracted = rules_findings = ml_findings = 0
    contexts: dict[int, tuple] = {}  # messages whose ML results are still pending: ticket -> (provenance, rule entries)
    ticket_seq = 0
    runner = None
    if ml_detector is not None:
        def ml_checkpoint(counts):  # progress + cooperative cancellation between detector calls
            emit('ml_inference', findings=len(findings), **counts)
        runner = MLBatchRunner(ml_detector, ml_budget, include_values=include_values, checkpoint=ml_checkpoint,
                               disposition=(None if disposition_observer is None else
                                            lambda ticket, index, status: disposition_observer(
                                                contexts[ticket][0]['http_message_id'], index, status)))

    def publish(provenance, entries):
        """Attach provenance and append one message's findings (rules first, then model), enforcing result budgets."""
        nonlocal result_bytes, ml_findings
        tick = time.perf_counter()
        for entry in entries:
            if len(findings) >= budget.max_findings:
                raise AnalysisLimitError('Analysis exceeded configured findings limit')
            entry['location'] = safe_field_location(entry['location'], include_values)
            entry.update(provenance)
            if _rows is None:
                result_bytes += len(json.dumps(entry,ensure_ascii=False).encode('utf-8'))
                if result_bytes > budget.max_report_bytes:
                    raise AnalysisLimitError('Analysis exceeded configured report budget')
            key = int.from_bytes(hashlib.blake2b(
                f"{provenance['flow_id']}\0{provenance['http_message_id']}\0{entry['location']}".encode('utf-8', 'surrogatepass'),
                digest_size=8).digest(), 'big')
            location_signals[key] = location_signals.get(key, 0) | (2 if entry['detector'] == 'bilstm' else 1)
            ml_findings += entry['detector'] == 'bilstm'
            findings.append(entry)
            if len(findings) % 1024 == 0:
                _check_memory(budget)
        stages['result_aggregation'] += time.perf_counter()-tick

    def drain():
        for ticket, model_entries in runner.take_ready():
            provenance, rule_entries = contexts.pop(ticket)
            publish(provenance, rule_entries + model_entries)

    for i, (endpoints, packed) in enumerate(flow_packets.items(), start=1):
        tick = time.perf_counter()
        packets = [TcpPacket(ts, endpoints[d][0], endpoints[1-d][0],
                             endpoints[d][1], endpoints[1-d][1], seq, flags, payload)
                   for d, ts, seq, flags, payload in packed]
        sessions = split_tcp_sessions(packets)
        # All capture records were retained until EOF. Only now is release safe.
        flow_packets[endpoints] = []
        stages['session_segmentation'] += time.perf_counter()-tick
        for session_index, packets in enumerate(sessions, 1):
            sessions_processed += 1
            if sessions_processed > budget.max_flows:
                raise AnalysisLimitError('Capture exceeds configured session/flow limit')
            fid = f'flow_{i:04d}' + (f'_session_{session_index:04d}' if len(sessions)>1 else '')
            directions: dict[tuple, list[TcpPacket]] = defaultdict(list)
            for packet in packets:
                directions[(packet.src, packet.sport, packet.dst, packet.dport)].append(packet)
            records: list[_Record] = []
            flow_gaps = flow_unterminated = 0
            for direction, segs in directions.items():
                tick = time.perf_counter()
                assembled = reassemble_detailed(segs)
                stream, missing = assembled.safe_prefix, assembled.unsafe
                stages['reassembly'] += time.perf_counter()-tick
                if missing:
                    gaps += 1
                    flow_gaps += 1
                tick = time.perf_counter()
                if stream[:14] == b'PRI * HTTP/2.0':
                    http2_streams += 1
                elif stream[:2] in (b'\x16\x03', b'\x17\x03', b'\x15\x03'):
                    tls_streams += 1
                parsed_stream = parse_http_stream_detailed(stream)
                spans = parsed_stream.spans
                if parsed_stream.unterminated_http:
                    unterminated += 1
                    flow_unterminated += 1
                if len(spans) == MAX_MESSAGES and spans[-1].end_offset < len(stream):
                    raise AnalysisLimitError('HTTP message limit prevents complete analysis')
                stages['http_parse'] += time.perf_counter()-tick
                for span in spans:
                    records.append(_Record(span.message, direction,
                                           _timestamp_for_byte(segs, span.start_offset, assembled.base_seq),
                                           span.start_offset))

            # If two messages share a packet timestamp, keep byte order stable.
            # Stable sorting also avoids treating initial SYN times as data times.
            records.sort(key=lambda r: (r.timestamp, r.direction, r.start_offset))
            for j, r in enumerate(records, 1):
                r.message_id = f'{fid}_msg_{j:04d}'
            direction_counts: dict[tuple, int] = {}
            for r in sorted(records, key=lambda r: (r.direction, r.start_offset)):
                direction_counts[r.direction] = direction_counts.get(r.direction, 0) + 1
                r.ordinal = direction_counts[r.direction]
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
                tick = time.perf_counter()
                fields = extract_fields(record.message)
                skip = body_skip_reason(record.message)
                if skip:
                    bodies_skipped[skip] = bodies_skipped.get(skip, 0) + 1
                if len(fields) >= MAX_FIELDS or any(len(value)>MAX_FIELD_LENGTH for _,value in fields):
                    raise AnalysisLimitError('HTTP field limits prevent complete detection')
                stages['field_extraction'] += time.perf_counter()-tick
                fields_extracted += len(fields)
                tick = time.perf_counter()
                detections = detect_fields(fields, threshold, include_values)
                if len(detections) >= 10000:
                    raise AnalysisLimitError('Per-message detection limit prevents complete analysis')
                stages['rule_detection'] += time.perf_counter()-tick
                rules_findings += len(detections)
                if field_observer is not None:
                    # In-process only: raw texts are handed to the evaluator, never serialised or retained by the engine.
                    client, server = ((record.direction[:2], record.direction[2:]) if record.message.is_request
                                      else (record.direction[2:], record.direction[:2]))
                    field_observer({
                        'flow_id': fid, 'http_message_id': record.message_id, 'session': session_index,
                        'client': client, 'server': server,
                        'message_type': 'request' if record.message.is_request else 'response',
                        'ordinal': record.ordinal, 'fields': fields, 'rule_detections': detections,
                        'quality': {**({'stream_gap': 'true'} if flow_gaps else {}),
                                    **({'capture_incomplete': 'true'} if diagnostics.incomplete else {}),
                                    **({'truncated': 'true'} if flow_unterminated else {})}})
                entries = []
                for detected in detections:
                    entry = asdict(detected)
                    # Never export unsalted PII/credential fingerprints.
                    entry.pop('fingerprint', None)
                    entries.append(entry)
                provenance = {
                    'flow_id': fid,
                    'http_message_id': record.message_id,
                    'http_request_id': record.request_id,
                    'http_message_type': 'request' if record.message.is_request else 'response',
                    'timestamp': timestamp,
                    'source_ip': src, 'source_port': sport,
                    'destination_ip': dst, 'destination_port': dport,
                    'http_start_line': safe_http_start_line(record.message.start_line, include_path=include_values),
                }
                if runner is None:
                    publish(provenance, entries)
                else:
                    ticket_seq += 1
                    contexts[ticket_seq] = (provenance, entries)
                    quality = {**({'stream_gap': 'true'} if flow_gaps else {}),
                               **({'capture_incomplete': 'true'} if diagnostics.incomplete else {}),
                               **({'truncated': 'true'} if flow_unterminated else {})}
                    runner.add(ticket_seq, fields, quality)
                    drain()
            tick = time.perf_counter()
            flow_summary = {
                'flow_id': fid,
                'endpoints': [{'ip': e[0], 'port': e[1]} for e in endpoints],
                'packets': len(packets),
                'http_messages': len(records),
                'http_transactions': flow_tx,
                'unpaired_requests': flow_orphan_req,
                'unpaired_responses': flow_orphan_resp,
                'stream_gaps': flow_gaps,
                'unterminated_http_messages': flow_unterminated,
            }
            if _rows is None:
                result_bytes += len(json.dumps(flow_summary,ensure_ascii=False).encode('utf-8'))
                if result_bytes > budget.max_report_bytes:
                    raise AnalysisLimitError('Analysis exceeded configured report budget')
            flow_summaries.append(flow_summary)

            stages['result_aggregation'] += time.perf_counter()-tick
            if sessions_processed % 128 == 0:
                emit('analysing', packets=frames, endpoint_pairs=len(flow_packets),
                     sessions=sessions_processed, http_messages=http_count, findings=len(findings))

    if runner is not None:
        runner.flush()
        drain()
        assert not contexts, 'every message must be released after the final flush'
        stages['ml_inference'] = runner.seconds
        ml_eligible, ml_evaluated, ml_skipped = runner.eligible, runner.evaluated, runner.skipped
        ml_excluded, ml_empty, ml_seconds, ml_invoked = runner.excluded, runner.empty, runner.seconds, runner.invoked
        ml_labels = {'PERSON_NAME': 0, 'USERNAME': 0, **runner.labels}
        ml_status, ml_ratio = runner.status, runner.coverage_ratio
        ml_skip_reasons, ml_batches = dict(sorted(runner.skip_reasons.items())), runner.batches
    else:
        ml_eligible = ml_evaluated = ml_skipped = ml_excluded = ml_empty = ml_batches = 0
        ml_labels, ml_seconds, ml_invoked = {'PERSON_NAME': 0, 'USERNAME': 0}, 0.0, False
        ml_status, ml_ratio, ml_skip_reasons = 'not_requested', None, {}

    return {
        'metadata': {
            'engine': 'pcap-pii-engine', 'version': '0.1.0',
            'report_schema_version': '1.0.0',
            'detection_method': 'rules_plus_bilstm' if ml_detector is not None else 'rules_only',
            'confidence_type': ('separate_rule_heuristic_and_uncalibrated_model_scores'
                                if ml_detector is not None else 'heuristic_not_calibrated'),
            'ml_requested': ml_detector is not None,
            'ml_model_loaded': ml_detector is not None,
            'ml_model_version': model_version,
            'ml_work_limits': ml_budget.public() if ml_detector is not None else None,
            'threshold': threshold, 'raw_values_included': include_values,
            'scope': 'unencrypted HTTP/1.x over TCP',
            'analysis_limits': {k:v for k,v in asdict(budget).items() if k in
                                ('max_capture_bytes','max_packets','max_flows','max_tcp_payload_bytes')},
            'analysis_profile': profile,
            'limits_overridden': limits is not None and limits != selected,
            'resource_budgets': {k:v for k,v in asdict(budget).items() if k in
                                 ('max_report_bytes','max_findings','max_memory_bytes')},
        },
        'summary': {
            'packets_captured': frames,
            'non_tcp_or_unsupported_packets': ignored,
            'unsupported_packets_by_reason': dict(sorted(skipped_packets.items())),
            'unsupported_packets_hiding_tcp': evidence_loss_packets,
            'flows_processed': sessions_processed,
            'endpoint_pairs': len(flow_packets),
            'http_flows': http_flows,
            'http_messages': http_count,
            'http_transactions': transactions,
            'unpaired_requests': orphan_requests,
            'unpaired_responses': orphan_responses,
            'total_data_bytes': bytes_processed,
            'processing_time_seconds': round(time.monotonic() - started, 4),
            'distinct_exposed_locations': len(location_signals),
            'locations_flagged_by_rules': sum(1 for v in location_signals.values() if v & 1),
            'locations_flagged_by_model': sum(1 for v in location_signals.values() if v & 2),
            'locations_flagged_by_both': sum(1 for v in location_signals.values() if v == 3),
            'potential_leaks': len(findings),
            'fields_extracted': fields_extracted,
            'rules_findings': rules_findings,
            'ml_findings': ml_findings,
            'ml_fields_eligible': ml_eligible,
            'ml_fields_evaluated': ml_evaluated,
            'ml_fields_excluded_by_policy': ml_excluded,
            'ml_fields_skipped': ml_skipped,
            'ml_fields_skipped_by_reason': ml_skip_reasons,
            'ml_skip_reasons': {('ml_field_path_too_long' if k == 'location_too_long' else 'ml_' + k): v
                                for k, v in ml_skip_reasons.items()},
            'ml_inference_complete': (ml_skipped == 0 if ml_detector is not None else None),
            'ml_inference_invoked': ml_invoked,
            'ml_inference_batches': ml_batches,
            'ml_coverage_status': ml_status,
            'ml_coverage_ratio': ml_ratio,
            'ml_batches': ml_batches,
            'ml_fields_empty': ml_empty,
            'ml_predictions_by_label': ml_labels,
            'ml_processing_time_seconds': ml_seconds,
            'ml_invoked': ml_invoked,
            'ml_inference_failed': False,
            'ml_incomplete': ml_skipped > 0,
            'stream_gaps': gaps,
            'unterminated_http_messages': unterminated,
            'http_incomplete_streams': unterminated,
            'http2_streams_not_decoded': http2_streams,
            'tls_streams_not_inspected': tls_streams,
            'http_bodies_not_inspected': sum(bodies_skipped.values()),
            'http_bodies_not_inspected_by_reason': dict(sorted(bodies_skipped.items())),
            'capture_truncated_records': diagnostics.truncated_records,
            'capture_malformed_records': diagnostics.malformed_records,
            'analysis_incomplete': diagnostics.incomplete or gaps > 0 or unterminated > 0 or ml_skipped > 0
                                   or evidence_loss_packets > 0 or bool(bodies_skipped) or http2_streams > 0,
        },
        'flows': flow_summaries, 'findings': findings,
        'limitations': [
            'Encrypted HTTPS payloads cannot be inspected without decryption',
            'IP fragments are not reassembled (counted and flagged); unobserved TCP lifecycle and delayed packets after tuple reuse remain ambiguous',
            'HTTP/2 and HTTP/3 not decoded; incomplete streams are ignored',
            'HTTP/1.x request-response pairing is best-effort (direction, stream order, packet timing)',
            ('Experimental BiLSTM enabled: model scores are uncalibrated; no real-traffic precision/recall established'
             if ml_detector is not None else 'Rules only; optional contextual ML is not enabled'),
            *(['Headers and obvious credential/contact fields are excluded from ML and still evaluated by rules']
              if ml_detector is not None else []),
            *(['ML processing limits skipped eligible fields: hybrid analysis is incomplete']
              if ml_skipped else []),
            'TCP is buffered until EOF under explicit budgets; large results should use analyze_to_report',
            'No SYN/FIN does not prove capture completeness; analysis_incomplete flags observed damage',
            'Findings mean possible PII exposure, not proof of exfiltration',
            *(['Capture corruption/truncation or missing TCP data: analysis is incomplete']
              if diagnostics.incomplete or gaps > 0 else []),
            *(['Some packets (IP fragments, IPv6 extension headers or truncated packets) may carry TCP data that was not analysed']
              if evidence_loss_packets else []),
            *(['Some HTTP bodies (unsupported or corrupt Content-Encoding) were present but not inspected']
              if bodies_skipped else []),
            *(['An HTTP message was unterminated at the end of a stream (truncated or ambiguous framing); its content was not analysed']
              if unterminated else []),
        ],
    }


def analyze(path: str | Path, threshold: float = 0.8, include_values: bool = False,
            *, limits: AnalysisLimits | None = None, profile: str = 'standard',
            progress=None, timings=None,
            ml_detector: ContextualPIIDetector | None = None,
            ml_budget: 'MLWorkBudget | str | None' = None,
            ml_work_budget: 'LegacyMLWorkBudget | None' = None,
            field_observer=None, disposition_observer=None) -> dict:
    """Compatible in-memory report API; use analyze_to_report for large outputs."""
    from .reporting import ReportLimitError
    try:
        report = _analyze(path, threshold, include_values, limits=limits, profile=profile,
                          progress=progress, timings=timings, ml_detector=ml_detector, ml_budget=ml_budget, ml_work_budget=ml_work_budget,
                          field_observer=field_observer, disposition_observer=disposition_observer)
        budget = limits if limits is not None else AnalysisLimits.for_profile(profile)
        _check_memory(budget)
        # Include containers, metadata and UTF-8 encoding without a giant string.
        total = 0
        for chunk in json.JSONEncoder(ensure_ascii=False,allow_nan=False).iterencode(report):
            total += len(chunk.encode('utf-8'))
            if total > budget.max_report_bytes:
                raise ReportLimitError('Complete report exceeds configured byte budget')
        if progress is not None:
            progress(dict(stage='complete', **report['summary']))
        return report
    except (MemoryError, ReportLimitError) as exc:
        raise AnalysisLimitError('Analysis exhausted memory or report budget; no complete report') from exc


def analyze_to_report(path: str | Path, target: str | Path, threshold: float = 0.8,
                      include_values: bool = False, *, limits: AnalysisLimits | None = None,
                      profile: str = 'standard', overwrite: bool = False,
                      progress=None, timings=None, row_observer=None,
                      ml_detector: ContextualPIIDetector | None = None,
                      ml_budget: 'MLWorkBudget | str | None' = None,
            ml_work_budget: 'LegacyMLWorkBudget | None' = None,
                      field_observer=None, disposition_observer=None) -> dict:
    """Bounded disk-backed results, atomic JSON publication, small receipt.

    Temporary results stay private next to target and are removed on success or
    failure. The receipt omits findings/flows; the complete arrays are in target.
    Progress callbacks are synchronous and contain no payload. Raise to cancel
    before publication; complete is a non-cancellable notification.
    """
    from .reporting import ReportSpool, ReportLimitError, write_private_report
    source, output = Path(path), Path(target)
    if source.resolve() == output.resolve():
        raise ValueError('Output report must not be the input capture file')
    if not overwrite and (output.exists() or output.is_symlink()):
        raise FileExistsError('Output already exists (use --overwrite explicitly)')
    selected = AnalysisLimits.for_profile(profile)
    budget = limits if limits is not None else selected
    if not isinstance(budget,AnalysisLimits):
        raise TypeError('limits must be AnalysisLimits')
    clock=time.monotonic()
    try:
        with ReportSpool(output.parent,budget.max_report_bytes,row_observer=row_observer) as rows:
            report = _analyze(source,threshold,include_values,limits=budget,profile=profile,
                              progress=progress,_rows=rows,timings=timings,ml_detector=ml_detector,ml_budget=ml_budget, ml_work_budget=ml_work_budget,
                              field_observer=field_observer,disposition_observer=disposition_observer)
            report['flows'], report['findings'] = [], []
            _check_memory(budget)
            if progress is not None:
                progress(dict(stage='writing_report',elapsed_seconds=time.monotonic()-clock,
                              **report['summary']))
            tick=time.perf_counter()
            write_private_report(report,output,overwrite=overwrite,max_bytes=budget.max_report_bytes,
                                 row_sources={'flows':rows.flows.iter_json(),
                                              'findings':rows.findings.iter_json()})
            if timings is not None:
                timings['report_write']=time.perf_counter()-tick
        receipt={k:v for k,v in report.items() if k not in ('flows','findings')}
        receipt['output_bytes']=output.stat().st_size
        receipt['output_path']=str(output)
        if progress is not None:
            try:
                progress(dict(stage='complete',elapsed_seconds=time.monotonic()-clock,
                              **report['summary']))
            except Exception:
                # Publication already succeeded; observer failure cannot undo it.
                receipt['progress_notification_failed'] = True
        return receipt
    except (MemoryError, ReportLimitError) as exc:
        raise AnalysisLimitError('Analysis exhausted memory or report budget; no complete report') from exc
