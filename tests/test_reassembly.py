"""Milestone 2: deterministic tests for TCP stream assembly on fake traffic.

Every address is RFC 5737 documentation space. No live/user PCAPs are needed.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct

from packet_pii.capture import TcpPacket, reassemble
from packet_pii.engine import analyze


SRC = '192.0.2.10'
DST = '198.51.100.20'


def packet(seq: int, payload: bytes = b'', flags: int = 0x18) -> TcpPacket:
    return TcpPacket(
        timestamp=1.0, src=SRC, dst=DST, sport=50123, dport=80,
        seq=seq, flags=flags, payload=payload,
    )


def test_out_of_order_segments_reassemble_exact_bytes():
    original = b'GET /search?q=example HTTP/1.1\r\nHost: example.test\r\n\r\n'
    parts = [original[:13], original[13:27], original[27:]]
    stream, gap = reassemble([
        packet(1013, parts[1]),
        packet(1027, parts[2]),
        packet(1000, parts[0]),
    ])
    assert not gap
    assert stream == original


def test_exact_retransmission_does_not_duplicate_bytes():
    stream, gap = reassemble([
        packet(2000, b'hello '),
        packet(2000, b'hello '),
        packet(2006, b'world'),
    ])
    assert (stream, gap) == (b'hello world', False)


def test_partially_overlapping_retransmission_extends_prefix():
    stream, gap = reassemble([
        packet(100, b'abcdefgh'),
        packet(104, b'efghijkl'),
    ])
    assert (stream, gap) == (b'abcdefghijkl', False)


def test_missing_middle_segment_returns_only_contiguous_prefix():
    stream, gap = reassemble([
        packet(100, b'first'),
        packet(110, b'third'),  # 5 bytes absent: 105..109
    ])
    assert stream == b'first'
    assert gap is True


def test_missing_first_segment_is_detected_when_syn_available():
    # The SYN's sequence number is 1000; first payload byte should be 1001.
    # If we only captured data from 1006, silently treating it as complete is unsafe.
    stream, gap = reassemble([
        packet(1000, flags=0x02),
        packet(1006, b'second'),
    ])
    assert stream == b''
    assert gap is True


def test_overlapping_retransmission_with_different_bytes_is_rejected():
    stream, gap = reassemble([
        packet(400, b'username=alice'),
        packet(409, b'bobXX'),  # overlaps original bytes with conflicting content
    ])
    assert gap is True
    assert stream == b'username=alice'  # do not invent/select an ambiguous value


def test_handshake_only_has_no_application_bytes():
    stream, gap = reassemble([
        packet(1000, flags=0x02),
        packet(1001, flags=0x10),
    ])
    assert (stream, gap) == (b'', False)


GENERATOR = Path(__file__).resolve().parents[1] / 'examples' / 'generate_demo.py'
spec = importlib.util.spec_from_file_location('demo_generator_m2', GENERATOR)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def write_test_pcap(path: Path, frames: list[bytes]) -> None:
    """Minimal PCAP writer for controlled Ethernet/IPv4/TCP fixture packets."""
    with path.open('wb') as out:
        out.write(b'\xd4\xc3\xb2\xa1')
        out.write(struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            out.write(struct.pack('<IIII', 10, index, len(frame), len(frame)))
            out.write(frame)


def test_two_independent_tcp_flows_do_not_get_merged(tmp_path):
    msg_a = b'GET /?email=first%40example.com HTTP/1.1\r\nHost: demo.test\r\n\r\n'
    msg_b = b'GET /?email=second%40example.com HTTP/1.1\r\nHost: demo.test\r\n\r\n'
    frames = [
        mod.tcp_frame(SRC, 55001, DST, 80, 100, msg_a),
        mod.tcp_frame(SRC, 55002, DST, 80, 200, msg_b),
    ]
    capture = tmp_path / 'two_flows.pcap'
    write_test_pcap(capture, frames)
    report = analyze(capture)
    assert report['summary']['flows_processed'] == 2
    assert report['summary']['http_messages'] == 2
    assert sum(f['pii_type'] == 'EMAIL' for f in report['findings']) == 2
    assert {f['source_port'] for f in report['findings']} == {55001, 55002}


def test_truncated_http_stream_is_not_reported_as_a_complete_message(tmp_path):
    # Deliberately omit the middle of an HTTP request body after seeing SYN.
    header = (b'POST / HTTP/1.1\r\nHost: demo.test\r\n'
              b'Content-Type: application/json\r\nContent-Length: 45\r\n\r\n')
    first = header + b'{"email":"'
    last = b'leak@example.com"}'
    frames = [
        mod.tcp_frame(SRC, 55001, DST, 80, 1000, flags=0x02),
        mod.tcp_frame(SRC, 55001, DST, 80, 1001, first),
        mod.tcp_frame(SRC, 55001, DST, 80, 1001 + len(first) + 7, last),
    ]
    capture = tmp_path / 'gapped.pcap'
    write_test_pcap(capture, frames)
    report = analyze(capture)
    assert report['summary']['stream_gaps'] == 1
    assert report['summary']['http_messages'] == 0
    assert report['summary']['potential_leaks'] == 0


def test_invalid_short_packet_is_ignored_without_crashing(tmp_path):
    valid = mod.tcp_frame(SRC, 55001, DST, 80, 1,
                          b'GET / HTTP/1.1\r\nHost: demo.test\r\n\r\n')
    capture = tmp_path / 'mixed.pcap'
    write_test_pcap(capture, [b'bad', valid])
    report = analyze(capture)
    assert report['summary']['packets_captured'] == 2
    assert report['summary']['non_tcp_or_unsupported_packets'] == 1
    assert report['summary']['http_messages'] == 1
