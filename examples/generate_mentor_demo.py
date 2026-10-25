"""Deterministic fictional Ethernet/IPv4/TCP conversation; no TRACE imports.

Generates a valid handshake, reordered/retransmitted request, two exchanges,
interim response, inert-viewer attack probes, and a gzip + chunked response.
The JSON sidecar is a generator oracle, not measured model ground truth.
"""
from pathlib import Path
import gzip
import hashlib
import json
import socket
import struct
import sys

CLIENT, SERVER = '192.0.2.10', '198.51.100.20'
SPORT, DPORT = 50123, 80
CSEQ, SSEQ = 1000, 9000


def checksum(raw):
    raw += b'\0' * (len(raw) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(raw) // 2), raw))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return ~total & 65535


def frame(reverse, seq, ack, flags, payload=b''):
    src, dst = (SERVER, CLIENT) if reverse else (CLIENT, SERVER)
    sport, dport = (DPORT, SPORT) if reverse else (SPORT, DPORT)
    a, b = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack('!HHIIHHHH', sport, dport, seq, ack, (5 << 12) | flags, 8192, 0, 0)
    csum = checksum(a + b + struct.pack('!BBH', 0, 6, len(tcp) + len(payload)) + tcp + payload)
    tcp = tcp[:16] + struct.pack('!H', csum) + tcp[18:] + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 7, 0x4000, 64, 6, 0, a, b)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return bytes.fromhex('0200000000020200000000010800') + ip + tcp


def messages():
    body = ('{"full_name":"Élodie Fiction","email":"alex@example.invalid",'
            '"age":27,"gender":"nonbinary","idfa":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}').encode()
    request1 = (b'POST /profile?demo=fictional HTTP/1.1\r\nHost: demo.example.invalid\r\n'
                b'Content-Type: application/json; charset=utf-8\r\nExpect: 100-continue\r\n'
                b'Authorization: Bearer fictional-demo-only-token\r\nContent-Length: '
                + str(len(body)).encode() + b'\r\n\r\n' + body)
    html = (b'<!doctype html><html><head><title>Fictional receipt</title></head><body>'
            b'<h1>Profile received</h1><p>alex@example.invalid</p>'
            b'<script>window.TRACE_UNTRUSTED_EXECUTED=true;fetch("https://example.invalid/leak")</script>'
            b'<img src="https://example.invalid/remote.png" onerror="window.TRACE_UNTRUSTED_EXECUTED=true">'
            b'</body></html>')
    response1 = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: '
                 + str(len(html)).encode() + b'\r\n\r\n' + html)
    request2 = b'GET /status HTTP/1.1\r\nHost: demo.example.invalid\r\n\r\n'
    encoded = bytearray(gzip.compress(b'{"full_name":"A\\u006cex Fiction","email":"reply@example.invalid"}', compresslevel=9, mtime=0))
    # Python 3.13+ emits OS=255 while earlier zlib-backed gzip emits OS=3.
    # Fix this informational header byte so the established fixture SHA stays
    # identical across the supported Python versions on macOS and Linux.
    encoded[9] = 3
    encoded = bytes(encoded)
    chunks = b''.join(format(len(p), 'x').encode() + b'\r\n' + p + b'\r\n'
                      for p in (encoded[:17], encoded[17:])) + b'0\r\n\r\n'
    response2 = (b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n'
                 b'Transfer-Encoding: chunked\r\n\r\n' + chunks)
    return request1, b'HTTP/1.1 100 Continue\r\n\r\n', response1, request2, response2


def write_demo(path):
    path = Path(path)
    req, interim, resp, req2, resp2 = messages()
    # Split within the fictional email so its exact field needs two packets.
    split = req.index(b'alex@example.invalid') + 7
    response_split = resp.index(b'Profile received') + 9
    c, s = CSEQ + 1, SSEQ + 1
    packets = [
        (False, CSEQ, 0, 2, b'', 'client SYN'),
        (True, SSEQ, c, 18, b'', 'server SYN ACK'),
        (False, c, s, 16, b'', 'client ACK'),
        (False, c + split, s, 24, req[split:], 'request tail arrives first'),
        (False, c, s, 24, req[:split], 'request head fills gap'),
        (False, c, s, 24, req[:split], 'consistent retransmission'),
        (True, s, c + len(req), 24, interim, 'interim 100 response'),
        (True, s + len(interim), c + len(req), 24, resp[:response_split], 'HTML response head'),
        (True, s + len(interim) + response_split, c + len(req), 24, resp[response_split:], 'HTML response tail'),
        (False, c + len(req), s + len(interim) + len(resp), 24, req2, 'second request'),
        (True, s + len(interim) + len(resp), c + len(req) + len(req2), 24, resp2, 'gzip chunked response'),
    ]
    raw = bytearray(bytes.fromhex('d4c3b2a1') + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1))
    records = []
    for number, (reverse, seq, ack, flags, payload, note) in enumerate(packets, 1):
        packet = frame(reverse, seq, ack, flags, payload)
        record_offset = len(raw)
        raw += struct.pack('<IIII', 1700000000, number * 10000, len(packet), len(packet)) + packet
        records.append({'frame': number, 'description': note, 'direction': 'server_to_client' if reverse else 'client_to_server',
                        'seq': seq, 'ack': ack, 'flags': flags, 'payload_bytes': len(payload),
                        'payload_file_start': record_offset + 16 + 54,
                        'payload_file_end': record_offset + 16 + len(packet)})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    oracle = {'synthetic': True, 'scope': 'generator oracle; not a model accuracy manifest',
              'sha256': hashlib.sha256(raw).hexdigest(), 'capture_bytes': len(raw),
              'client': f'{CLIENT}:{SPORT}', 'server': f'{SERVER}:{DPORT}', 'frames': records,
              'expected_http_messages': 5, 'expected_transactions': 2,
              'request_stream_sha256': hashlib.sha256(req + req2).hexdigest(),
              'response_stream_sha256': hashlib.sha256(interim + resp + resp2).hexdigest(),
              'email': 'alex@example.invalid', 'email_support_frames': [5, 4],
              'html_response_frames': [8, 9]}
    path.with_suffix('.oracle.json').write_text(json.dumps(oracle, indent=2) + '\n')
    return oracle


if __name__ == '__main__':
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('mentor-demo.pcap')
    print(json.dumps(write_demo(target), indent=2))
