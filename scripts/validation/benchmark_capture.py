#!/usr/bin/env python3
"""Bounded network-only benchmark; no rules, ML, dashboard or plaintext output."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import resource
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from packet_pii.capture import (CaptureDiagnostics, decode_tcp, endpoint_key, read_frames,
                                reassemble_detailed, split_tcp_sessions)
from packet_pii.http_extract import parse_http_stream_with_spans, extract_fields

MIB = 1024*1024


def benchmark(path, *, max_capture_mib=128, max_packets=100000,
              max_flows=20000, max_tcp_mib=64):
    if min(max_capture_mib,max_packets,max_flows,max_tcp_mib) <= 0:
        raise ValueError('limits must be positive')
    start = time.perf_counter()
    flows = defaultdict(list)
    diag = CaptureDiagnostics()
    counters = Counter()
    payload_bytes = 0
    limit_failure = None
    for frame in read_frames(path,diagnostics=diag,max_file_bytes=int(max_capture_mib*MIB)):
        if counters['packets'] >= max_packets:
            limit_failure = 'max_packets'; break
        counters['packets'] += 1
        packet = decode_tcp(frame)
        if packet is None:
            counters['unsupported_or_invalid_packets'] += 1; continue
        key = endpoint_key(packet)
        if key not in flows and len(flows) >= max_flows:
            limit_failure = 'max_flows'; break
        if payload_bytes + len(packet.payload) > max_tcp_mib*MIB:
            limit_failure = 'max_tcp_mib'; break
        flows[key].append(packet)
        payload_bytes += len(packet.payload)
    decode_done = time.perf_counter()
    assembly_seconds = parse_seconds = extract_seconds = 0.
    notes = Counter()
    for packets in flows.values():
        tick = time.perf_counter()
        sessions = split_tcp_sessions(packets)
        counters['sessions'] += len(sessions)
        assembly_seconds += time.perf_counter()-tick
        for session in sessions:
            directions = defaultdict(list)
            tick = time.perf_counter()
            for p in session:
                directions[(p.src,p.sport)].append(p)
            assembly_seconds += time.perf_counter()-tick
            for direction in directions.values():
                tick = time.perf_counter()
                result = reassemble_detailed(direction)
                assembly_seconds += time.perf_counter()-tick
                counters['unsafe_directions'] += result.unsafe
                counters['reassembled_bytes'] += len(result.safe_prefix)
                notes.update(result.diagnostics)
                tick = time.perf_counter()
                spans = parse_http_stream_with_spans(result.safe_prefix)
                parse_seconds += time.perf_counter()-tick
                counters['http_messages'] += len(spans)
                tick = time.perf_counter()
                for span in spans:
                    counters['fields'] += len(extract_fields(span.message))
                extract_seconds += time.perf_counter()-tick
    wall = time.perf_counter()-start
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_mib = peak / (MIB if sys.platform == 'darwin' else 1024)
    size = Path(path).stat().st_size
    return {'capture_bytes':size,'counters':dict(counters),'flows':len(flows),
        'buffered_payload_bytes':payload_bytes,'limit_failure':limit_failure,
        'capture_diagnostics':vars(diag),'reassembly_diagnostics':dict(notes),
        'wall_seconds':wall,'read_decode_group_seconds':decode_done-start,
        'reassembly_seconds':assembly_seconds,'http_parse_seconds':parse_seconds,
        'field_extraction_seconds':extract_seconds,'peak_rss_mib':peak_mib,
        'throughput_mib_s':(size/MIB)/wall if not limit_failure else None,
        'limits':{'capture_mib':max_capture_mib,'packets':max_packets,
                  'flows':max_flows,'tcp_mib':max_tcp_mib},
        'python':sys.version.split()[0],'platform':sys.platform,
        'note':'Network only; read/decode/group combined. RSS is process lifetime peak.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture',type=Path)
    parser.add_argument('--max-capture-mib',type=int,default=128)
    parser.add_argument('--max-packets',type=int,default=100000)
    parser.add_argument('--max-flows',type=int,default=20000)
    parser.add_argument('--max-tcp-mib',type=int,default=64)
    args = parser.parse_args()
    result = benchmark(args.capture,max_capture_mib=args.max_capture_mib,
        max_packets=args.max_packets,max_flows=args.max_flows,max_tcp_mib=args.max_tcp_mib)
    print(json.dumps(result,indent=2))
    return 2 if result['limit_failure'] else 0

if __name__ == '__main__':
    raise SystemExit(main())
