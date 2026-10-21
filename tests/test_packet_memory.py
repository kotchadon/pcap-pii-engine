"""Per-buffered-packet memory: every TCP packet is retained until EOF, so its fixed overhead bounds capture size."""
import importlib.util
from pathlib import Path

import pytest

import packet_pii.engine as engine
from packet_pii.capture import PacketSourceRange, TcpPacket, with_endpoints, _checksum

ROOT = Path(__file__).resolve().parents[1]


def test_per_packet_dataclasses_use_slots():
    for cls in (TcpPacket, PacketSourceRange):
        assert '__slots__' in cls.__dict__ and not hasattr(cls(*([1] * len(cls.__slots__))), '__dict__')


def test_with_endpoints_equals_dataclasses_replace():
    from dataclasses import replace
    src = PacketSourceRange(0, 5, 3, 54, 59, 100, 116, 59, 59, 1.5, 1e-6, 1, 0, 0)
    packet = TcpPacket(1.5, '192.0.2.1', '198.51.100.2', 1234, 80, 7, 0x18, b'hello', 9, 'ipv4', 14, 54,
                       'valid', 'valid', (src,), 3, False, None)
    assert with_endpoints(packet, 'a', 'b') == replace(packet, src='a', dst='b')


def test_endpoint_strings_are_shared_across_a_flow(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('demo_mem', ROOT / 'examples' / 'generate_demo.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    path = tmp_path / 'demo.pcap'
    mod.write_pcap(path)
    seen = []
    original = engine.split_tcp_sessions

    def spy(packets):
        seen.append(list(packets))
        return original(packets)
    monkeypatch.setattr(engine, 'split_tcp_sessions', spy)
    engine.analyze(path)
    packets = [p for flow in seen for p in flow]
    assert len(packets) == 8
    by_value = {}
    for p in packets:
        for address in (p.src, p.dst):
            assert by_value.setdefault(address, address) is address   # one string object per endpoint per flow


def test_checksum_matches_rfc1071_word_loop_on_edge_cases():
    import struct

    def reference(data):
        if len(data) & 1:
            data += b'\0'
        total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
        while total >> 16:
            total = (total & 0xffff) + (total >> 16)
        return (~total) & 0xffff
    cases = [b'', b'\0', b'\0' * 40, b'\xff\xff', b'\xff' * 99, b'\x00\x01', b'\xff\xfe', bytes(range(256)) * 7]
    data = bytes(range(60))
    cases.append(data + reference(data).to_bytes(2, 'big'))   # a valid checksum folds to zero
    for case in cases:
        assert _checksum(case) == reference(case), case[:8]
    assert _checksum(cases[-1]) == 0
