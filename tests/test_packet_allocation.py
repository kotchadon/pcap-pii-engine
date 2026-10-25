"""Independent reference checks for the selected PR #32 packet optimisations."""
from dataclasses import asdict, replace
import random

import pytest

from packet_pii import capture


def test_checksum_matches_independent_word_fold():
    rng = random.Random(251025)
    cases = [b'', b'\0', b'\0' * 40, b'\xff' * 40]
    cases += [rng.randbytes(n) for n in (*range(128), 511, 1500, 65535)]
    for data in cases:
        padded = data + (b'\0' if len(data) % 2 else b'')
        value = sum(int.from_bytes(padded[i:i+2], 'big') for i in range(0, len(padded), 2))
        while value >> 16:
            value = (value & 65535) + (value >> 16)
        assert capture._checksum(data) == (~value & 65535)


def test_clipped_rebased_source_preserves_every_other_identity():
    source = capture.PacketSourceRange(10, 90, 7, 50, 130, 24, 40, 150, 160, 1.5, 1e-9, 101, 3, 2)
    expected = replace(source, payload_start=5, payload_end=25, frame_start=60, frame_end=80)
    actual = capture.clip_packet_source(source, 20, 40, shift=15)
    assert asdict(actual) == asdict(expected)
    assert not hasattr(actual, '__dict__')
    with pytest.raises(ValueError):
        capture.clip_packet_source(source, 0, 40)


def test_endpoint_clone_preserves_all_packet_and_fragment_metadata():
    packet = capture.TcpPacket(1.5, '192.0.2.1', '198.51.100.2', 12, 80, 42, 24, b'fictional',
                               ack=11, network_protocol='ipv4', network_offset=14, payload_offset=54,
                               ipv4_checksum='valid', tcp_checksum='valid', frame_index=9,
                               reassembled_fragments=True)
    actual = capture.with_endpoints(packet, '192.0.2.3', '198.51.100.4')
    assert asdict(actual) == asdict(replace(packet, src='192.0.2.3', dst='198.51.100.4'))
    assert not hasattr(actual, '__dict__')
