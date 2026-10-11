"""Analysis orchestrator: packet capture -> streams -> HTTP fields -> findings."""
from __future__ import annotations
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from urllib.parse import urlsplit
import time
from pathlib import Path
from .capture import read_frames, decode_tcp, endpoint_key, reassemble, TcpPacket
from .http_extract import parse_http_stream,extract_fields
from .detect import detect_fields


def safe_http_start_line(line: str) -> str:
    """Strip query strings from report metadata (they may contain PII)."""
    parts = line.split(' ', 2)
    if len(parts) == 3 and not line.startswith('HTTP/'):
        url = urlsplit(parts[1])
        return f'{parts[0]} {url.path or "/"} {parts[2]}'[:300]
    return line[:300]


def analyze(path: str | Path, threshold: float=0.8, include_values: bool=False) -> dict:
    if not 0<=threshold<=1:
        raise ValueError('Confidence threshold must be in [0,1]')
    started=time.monotonic()
    flow_packets: dict[tuple,list[TcpPacket]]=defaultdict(list)
    frames=0
    bytes_processed=0
    ignored=0
    for frame in read_frames(path):
        frames+=1
        bytes_processed+=len(frame.data)
        packet=decode_tcp(frame)
        if packet:
            flow_packets[endpoint_key(packet)].append(packet)
        else:
            ignored+=1
    findings=[]
    http_count=0
    http_flows=0
    flow_summaries=[]
    gaps=0
    for i, (endpoints,packets) in enumerate(flow_packets.items(),start=1):
        fid=f'flow_{i:04d}'
        directions: dict[tuple,list[TcpPacket]]=defaultdict(list)
        for p in packets:
            directions[(p.src,p.sport,p.dst,p.dport)].append(p)
        flow_http=0
        flow_gaps=0
        for (src,sport,dst,dport),segs in directions.items():
            stream,missing=reassemble(segs)
            if missing:
                gaps+=1
                flow_gaps+=1
            # A gap can conceal message content; only the contiguous prefix is parsed.
            messages=parse_http_stream(stream)
            for msg in messages:
                http_count+=1
                flow_http+=1
                timestamp=datetime.fromtimestamp(min(p.timestamp for p in segs),timezone.utc).isoformat()
                for d in detect_fields(extract_fields(msg),threshold,include_values):
                    entry=asdict(d)
                    entry.update({
                        'flow_id':fid,'timestamp':timestamp,
                        'source_ip':src,'source_port':sport,
                        'destination_ip':dst,'destination_port':dport,
                        'http_start_line':safe_http_start_line(msg.start_line),
                    })
                    findings.append(entry)
        if flow_http:
            http_flows+=1
        flow_summaries.append({'flow_id':fid,'endpoints':[
            {'ip':e[0],'port':e[1]} for e in endpoints
        ],'packets':len(packets),'http_messages':flow_http,'stream_gaps':flow_gaps})
    return {
        'metadata':{'engine':'pcap-pii-engine','version':'0.1.0',
                    'detection_method':'rules_only','confidence_type':'heuristic_not_calibrated',
                    'threshold':threshold,'raw_values_included':include_values,
                    'scope':'unencrypted HTTP/1.x over TCP'},
        'summary':{'packets_captured':frames,'non_tcp_or_unsupported_packets':ignored,
                   'flows_processed':len(flow_packets),'http_flows':http_flows,
                   'http_messages':http_count,'total_data_bytes':bytes_processed,
                   'processing_time_seconds':round(time.monotonic()-started,4),
                   'potential_leaks':len(findings),'stream_gaps':gaps},
        'flows':flow_summaries,'findings':findings,
        'limitations':['Encrypted HTTPS payloads cannot be inspected without decryption',
                       'No IP fragmentation or TCP sequence wraparound/reused-tuple session separation',
                       'HTTP/2 and HTTP/3 not decoded; incomplete streams are ignored',
                       'Rule-based detection only; contextual ML is not yet integrated',
                       'Packets are buffered in memory; not for production-scale captures',
                       'Findings mean possible PII exposure, not proof of exfiltration']
    }
