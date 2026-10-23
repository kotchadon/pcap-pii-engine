#!/usr/bin/env python3
"""Independent small-fixture oracle using dpkt + h11, not TRACE parsing.

Only for the deterministic mentor fixture (bounded at 64 KiB). Optional TRACE
report comparison verifies exact field source bytes against original capture.
No credentials or captured text are printed. Requires dpkt and h11 locally.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import socket

import dpkt
import h11


def parse_http(raw, response=False):
    out = []
    while raw:
        conn = h11.Connection(h11.CLIENT if response else h11.SERVER)
        if response:
            conn.send(h11.Request(method=b'GET', target=b'/', headers=[(b'host', b'example.invalid')]))
            conn.send(h11.EndOfMessage())
        conn.receive_data(raw)
        body = bytearray()
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA or event is h11.PAUSED:
                raise AssertionError('Reference parser encountered incomplete message')
            if isinstance(event, h11.InformationalResponse):
                out.append({'status': event.status_code, 'body': b'', 'headers': dict(event.headers)})
            elif isinstance(event, (h11.Request, h11.Response)):
                entry = {'status': event.status_code} if response else {'method': event.method.decode()}
                entry['headers'] = dict(event.headers)
            elif isinstance(event, h11.Data):
                body.extend(event.data)
            elif isinstance(event, h11.EndOfMessage):
                entry['body'] = bytes(body); out.append(entry)
                raw = conn.trailing_data[0]
                break
    return out


def verify(capture, report=None):
    raw = capture.read_bytes()
    assert len(raw) <= 65536, 'This oracle is bounded to the small mentor fixture'
    streams, frames = {}, []
    with capture.open('rb') as file:
        reader = dpkt.pcap.Reader(file)
        assert reader.datalink() == dpkt.pcap.DLT_EN10MB
        for number, (_ts, packet) in enumerate(reader, 1):
            ip = dpkt.ethernet.Ethernet(packet).data; tcp = ip.data
            key = (socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport)
            frames.append((tcp.seq, tcp.ack, tcp.flags))
            positions = streams.setdefault(key, {})
            for i, value in enumerate(tcp.data):
                position = tcp.seq + i
                assert position not in positions or positions[position] == value, 'Conflicting TCP overlap'
                positions[position] = value
    assert frames[:3] == [(1000, 0, 2), (9000, 1001, 18), (1001, 9001, 16)]
    assembled = {}
    for key, positions in streams.items():
        first, last = min(positions), max(positions)
        assert len(positions) == last - first + 1, 'Gap in reference stream'
        assembled[key] = bytes(positions[n] for n in range(first, last + 1))
    requests = next(v for k, v in assembled.items() if k[1] == 50123)
    responses = next(v for k, v in assembled.items() if k[1] == 80)
    req, res = parse_http(requests), parse_http(responses, response=True)
    assert [x['method'] for x in req] == ['POST', 'GET']
    assert [x['status'] for x in res] == [100, 200, 200]
    assert json.loads(req[0]['body'])['email'] == 'alex@example.invalid'
    assert b'<script>' in res[1]['body'] and b'alex@example.invalid' in res[1]['body']
    assert json.loads(gzip.decompress(res[2]['body']))['full_name'] == 'Alex Fiction'
    supporting_frames = []
    if report:
        r = json.loads(report.read_text())
        assert r['capture_evidence']['capture_sha256'] == hashlib.sha256(raw).hexdigest()
        assert r['summary']['http_messages'] == len(req) + len(res)
        assert r['summary']['http_transactions'] == 2
        first = next(h for h in r['http_evidence'] if h['start_line'].startswith('POST '))
        fields = [f for f in r['field_evidence'] if f['http_message_id'] == first['http_message_id']]
        found = False
        for field in fields:
            if field['granularity'] != 'exact_stream_range':
                continue
            value = bytearray(); sources = []
            for interval in field['stream_ranges']:
                at = interval['start']
                rows = sorted((s for s in r['stream_evidence'] if s.get('row_type') == 'source_range'
                               and s['stream_id'] == field['stream_id']), key=lambda s: s['stream_start'])
                for source in rows:
                    a, b = max(at, source['stream_start']), min(interval['end'], source['stream_end'])
                    if a < b:
                        assert a == at
                        offset = source['file_start'] + a - source['stream_start']
                        value.extend(raw[offset:offset+b-a]); at = b; sources.append(source['frame_index'])
                assert at == interval['end']
            if value == b'alex@example.invalid':
                assert sources == [5, 4], sources
                supporting_frames = sources; found = True
        assert found, 'TRACE exact field source does not recover the independently parsed email'
    return {'independent_tools': {'dpkt': dpkt.__version__, 'h11': h11.__version__},
            'capture_sha256': hashlib.sha256(raw).hexdigest(), 'frames': len(frames),
            'handshake_seq_ack_verified': True, 'requests': len(req), 'responses_including_interim': len(res),
            'request_stream_sha256': hashlib.sha256(requests).hexdigest(),
            'response_stream_sha256': hashlib.sha256(responses).hexdigest(),
            'chunked_gzip_unicode_verified': True, 'report_compared': report is not None,
            'exact_email_support_frames': supporting_frames,
            'wireshark_tshark_executed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path); parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.capture, args.report), indent=2))
