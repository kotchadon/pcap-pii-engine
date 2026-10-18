#!/usr/bin/env python3
"""Generate a reproducible ~5 MiB synthetic field-heavy capture, never real PII.

This is a representative workload, not a copy of the user's unavailable lab PCAP.
Each of 400 sessions has 220 contextual fields and 48 policy-excluded emails.
No engine, extractor or model is used to create these bytes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct

from generate_captures import tcp_frame


def generate(path: Path, sessions=400):
    if type(sessions) is not int or not 1 <= sessions <= 1000:
        raise ValueError('sessions must be an integer in 1..1000')
    packet_count = 0
    with path.open('xb') as out:
        os.fchmod(out.fileno(), 0o600)
        out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        def emit(frame):
            nonlocal packet_count
            out.write(struct.pack('<IIII', 1700000000 + packet_count//1000000,
                                  packet_count%1000000, len(frame), len(frame)))
            out.write(frame)
            packet_count += 1
        for session in range(sessions):
            values = {f'note_{i:03d}': 'Customer name is Fictional Example.' for i in range(220)}
            values.update({f'email_{i:03d}': f'fixture{i}@example.test' for i in range(48)})
            body = json.dumps(values, separators=(',', ':')).encode()
            request = (b'POST /fixture HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n'
                       + f'Content-Length: {len(body)}\r\n\r\n'.encode() + body)
            response = b'HTTP/1.1 204 No Content\r\n\r\n'
            src, dst, sport = '192.0.2.10', '198.51.100.20', 10000+session
            emit(tcp_frame(src, dst, sport, 80, 1000, 0, 2))
            emit(tcp_frame(dst, src, 80, sport, 2000, 1001, 0x12))
            emit(tcp_frame(src, dst, sport, 80, 1001, 2001, 0x10))
            for offset in range(0, len(request), 1300):
                emit(tcp_frame(src, dst, sport, 80, 1001+offset, 2001, 0x18,
                               request[offset:offset+1300]))
            emit(tcp_frame(dst, src, 80, sport, 2001, 1001+len(request), 0x18, response))
            emit(tcp_frame(src, dst, sport, 80, 1001+len(request), 2001+len(response), 0x11))
            emit(tcp_frame(dst, src, 80, sport, 2001+len(response), 1002+len(request), 0x11))
    digest = hashlib.sha256()
    with path.open('rb') as capture:
        for chunk in iter(lambda: capture.read(1024*1024), b''):
            digest.update(chunk)
    return dict(generator_version=1, source='synthetic representative, not original user lab capture',
                capture_bytes=path.stat().st_size, sha256=digest.hexdigest(), packets=packet_count,
                sessions=sessions, http_messages=2*sessions,
                contextual_body_fields=220*sessions, email_body_fields=48*sessions)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('output', type=Path)
    p.add_argument('--sessions', type=int, default=400)
    args = p.parse_args()
    print(json.dumps(generate(args.output, args.sessions), indent=2))
