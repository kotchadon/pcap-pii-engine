"""Bounded synthetic IP fragmentation and extension-chain regressions."""
from dataclasses import replace
import ipaddress
import struct

import pytest

from packet_pii.capture import RawFrame, TcpDecoder, decode_tcp_with_reason, reassemble_detailed
from packet_pii.ip_reassembly import FragmentLimits


def tcp(payload=b'abcdefghijklmnopqrstuvwx', seq=100):
    return struct.pack('!HHIIBBHHH', 1234, 80, seq, 7, 0x50, 0x18, 4096, 0, 0) + payload


def v4(piece, offset=0, more=False, identity=9):
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(piece), identity,
                       offset // 8 | (0x2000 if more else 0), 64, 6, 0,
                       b'\xc0\x00\x02\x01', b'\xc6\x33\x64\x02') + piece


def v6base(piece, next_header=44):
    return struct.pack('!IHBB16s16s', 6 << 28, len(piece), next_header, 64,
                       ipaddress.IPv6Address('2001:db8::1').packed,
                       ipaddress.IPv6Address('2001:db8::2').packed) + piece


def v6(piece, offset=0, more=False, identity=9, next_header=6):
    fragment = struct.pack('!BBHI', next_header, 0, offset | bool(more), identity)
    return v6base(fragment + piece)


def frame(data, index=1, timestamp=1., interface=0, section=0):
    return RawFrame(timestamp, 101, data, index, index * 100, index * 100 + 16,
                    len(data), len(data), 1e-6, interface, section)


@pytest.mark.parametrize('builder', [v4, v6])
def test_fragment_reassembly_out_of_order_exact_tcp_payload_slices(builder):
    segment = tcp()
    frames = [frame(builder(segment[24:], 24), 1), frame(builder(segment[:24], more=True), 2)]
    decoder = TcpDecoder()
    assert decoder.ingest(frames[0]) == (None, 'fragment_pending')
    packet, reason = decoder.ingest(frames[1])
    assert reason is None and packet.payload == segment[20:]
    assert packet.payload_offset is None and packet.frame_index is None
    assert packet.reassembled_fragments and packet.ack == 7
    assert [s.frame_index for s in packet.source_ranges] == [2, 1]
    for source in packet.source_ranges:
        original = frames[source.frame_index - 1].data
        assert original[source.frame_start:source.frame_end] == packet.payload[source.payload_start:source.payload_end]
    result = reassemble_detailed([packet])
    assert result.safe_prefix == packet.payload
    assert sum(s.stream_end - s.stream_start for s in result.source_ranges) == len(packet.payload)
    assert decoder.finish()['fragment_reassembled'] == 1
    assert decoder.fragments.buffered_bytes == 0


@pytest.mark.parametrize('builder', [v4, v6])
def test_overlap_rejects_entire_datagram_and_quarantines_identity(builder):
    segment = tcp()
    decoder = TcpDecoder()
    assert decoder.ingest(frame(builder(segment[:24], more=True)))[1] == 'fragment_pending'
    assert decoder.ingest(frame(builder(segment[16:32], 16, more=True), 2))[1] == 'fragment_overlap'
    assert decoder.ingest(frame(builder(segment[24:], 24), 3))[1] == 'fragment_identity_reuse'
    assert decoder.fragments.buffered_bytes == 0
    assert decoder.finish()['fragment_overlap'] == 1


def test_ipv4_exact_duplicate_ignored_ipv6_duplicate_strictly_rejected():
    for builder, reason in [(v4, 'fragment_duplicate'), (v6, 'fragment_overlap')]:
        decoder = TcpDecoder()
        first = frame(builder(tcp()[:24], more=True))
        decoder.ingest(first)
        assert decoder.ingest(replace(first, frame_index=2))[1] == reason


def test_missing_fragments_finish_idempotent_and_timestamp_reversal_frame_window():
    decoder = TcpDecoder(FragmentLimits(max_capture_frames=2))
    decoder.ingest(frame(v4(tcp()[:24], more=True), timestamp=20.))
    decoder.ingest(frame(v4(tcp(), identity=8), 2, timestamp=19.))
    decoder.ingest(frame(v4(tcp(), identity=8), 3, timestamp=18.))
    assert decoder.diagnostics['fragment_timeout'] == 1
    assert decoder.fragments.buffered_bytes == 0
    decoder.ingest(frame(v4(tcp()[:24], more=True, identity=10), 4, timestamp=18.))
    one = decoder.finish()
    assert one['fragment_incomplete'] == 1 and decoder.finish() == one


def test_lifetime_expires_without_later_fragment():
    decoder = TcpDecoder()
    decoder.ingest(frame(v6(tcp()[:24], more=True), timestamp=1.))
    decoder.ingest(frame(v4(tcp()), 2, timestamp=61.))
    assert decoder.finish()['fragment_timeout'] == 1


@pytest.mark.parametrize('limits,second,reason', [
    (FragmentLimits(max_datagrams=1), v4(tcp()[:24], more=True, identity=10), 'fragment_limit'),
    (FragmentLimits(max_buffered_bytes=25), v4(tcp()[24:], 24), 'fragment_limit'),
    (FragmentLimits(max_fragments=1), v4(tcp()[24:], 24), 'fragment_limit'),
    (FragmentLimits(max_datagram_bytes=32), v4(tcp()[24:], 24), 'fragment_malformed'),
])
def test_fragment_resource_budgets_fail_closed(limits, second, reason):
    decoder = TcpDecoder(limits)
    decoder.ingest(frame(v4(tcp()[:24], more=True)))
    assert decoder.ingest(frame(second, 2)) == (None, reason)
    assert decoder.fragments.buffered_bytes <= limits.max_buffered_bytes
    assert len(decoder.fragments.entries) <= limits.max_datagrams


@pytest.mark.parametrize('builder', [v4, v6])
def test_nonfinal_length_must_be_multiple_of_eight(builder):
    decoder = TcpDecoder()
    assert decoder.ingest(frame(builder(tcp()[:25], more=True)))[1] == 'fragment_malformed'


def test_fragments_from_different_interfaces_or_sections_never_combine():
    for changed in [{'interface': 1}, {'section': 1}]:
        decoder = TcpDecoder()
        decoder.ingest(frame(v4(tcp()[:24], more=True)))
        assert decoder.ingest(frame(v4(tcp()[24:], 24), 2, **changed))[1] == 'fragment_pending'
        assert decoder.finish()['fragment_incomplete'] == 2


def test_ipv6_extension_chain_and_postfragment_destination_options():
    extension = bytes([6, 0]) + b'\0' * 6
    packet, reason = decode_tcp_with_reason(frame(v6base(extension + tcp(), 60)))
    assert reason is None and packet.payload == tcp()[20:]
    assert packet.payload_offset == 68
    fragmentable = extension + tcp()
    decoder = TcpDecoder()
    decoder.ingest(frame(v6(fragmentable[:32], more=True, next_header=60)))
    packet, reason = decoder.ingest(frame(v6(fragmentable[32:], 32, next_header=60), 2))
    assert reason is None and packet.payload == tcp()[20:]
    assert packet.source_ranges[0].payload_start == 0
    assert packet.source_ranges[0].frame_start == 76


def test_ipv6_extension_depth_and_esp_are_bounded_unsupported():
    chain = b''.join(bytes([60 if i < 8 else 6, 0]) + b'\0' * 6 for i in range(9))
    assert decode_tcp_with_reason(frame(v6base(chain + tcp(), 60)))[1] == 'ipv6_extension_header'
    assert decode_tcp_with_reason(frame(v6base(tcp(), 50)))[1] == 'ipv6_extension_header'


def test_ipv6_atomic_fragment_does_not_change_pending_datagram():
    decoder = TcpDecoder()
    decoder.ingest(frame(v6(tcp()[:24], more=True)))
    packet, reason = decoder.ingest(frame(v6(tcp(b'atomic')), 2))
    assert reason is None and packet.payload == b'atomic' and not packet.reassembled_fragments
    packet, reason = decoder.ingest(frame(v6(tcp()[24:], 24), 3))
    assert reason is None and packet.payload == tcp()[20:]


def test_ipv6_first_fragment_requires_complete_tcp_header():
    decoder = TcpDecoder()
    assert decoder.ingest(frame(v6(tcp()[:16], more=True)))[1] == 'fragment_malformed'


def test_completed_identity_not_reused_inside_capture_window():
    decoder = TcpDecoder()
    decoder.ingest(frame(v4(tcp()[:24], more=True)))
    assert decoder.ingest(frame(v4(tcp()[24:], 24), 2))[0] is not None
    assert decoder.ingest(frame(v4(tcp(b'changed')[:24], more=True), 3))[1] == 'fragment_identity_reuse'


@pytest.mark.parametrize('kwargs', [{'max_datagrams': 0}, {'max_fragments': True},
                                    {'lifetime_seconds': float('nan')}, {'max_datagram_bytes': 65536}])
def test_invalid_fragment_limits_rejected(kwargs):
    with pytest.raises(ValueError):
        FragmentLimits(**kwargs)


def test_late_fragment_invalidates_already_emitted_packet_evidence():
    decoder = TcpDecoder()
    decoder.ingest(frame(v6(tcp()[:24], more=True)))
    packet, _ = decoder.ingest(frame(v6(tcp()[24:], 24), 2))
    assert packet.fragment_evidence.trusted
    decoder.ingest(frame(v6(tcp(b'conflicting')[:24], more=True), 3))
    assert not packet.fragment_evidence.trusted
    result = reassemble_detailed([packet])
    assert result.unsafe and result.safe_prefix == b'' and result.source_ranges == ()


def test_vlan_scopes_do_not_merge_fragment_identities():
    def ethernet(data, vlan):
        return b'\0' * 12 + b'\x81\0' + struct.pack('!HH', vlan, 0x0800) + data
    decoder = TcpDecoder()
    first = replace(frame(ethernet(v4(tcp()[:24], more=True), 10)), linktype=1)
    last = replace(frame(ethernet(v4(tcp()[24:], 24), 20), 2), linktype=1)
    assert decoder.ingest(first)[1] == 'fragment_pending'
    assert decoder.ingest(last)[1] == 'fragment_pending'
    assert decoder.finish()['fragment_incomplete'] == 2


def test_ipv6_udp_fragments_are_out_of_scope_without_buffering():
    decoder = TcpDecoder()
    assert decoder.ingest(frame(v6(b'\0' * 24, more=True, next_header=17)))[1] == 'non_tcp'
    assert decoder.ingest(frame(v6(b'\0' * 16, 24, next_header=17), 2))[1] == 'non_tcp'
    assert decoder.finish() == {}


def test_invalid_ipv6_first_fragment_quarantines_existing_pending_fragments():
    decoder = TcpDecoder()
    decoder.ingest(frame(v6(tcp()[24:], 24)))
    assert decoder.ingest(frame(v6(tcp()[:16], more=True), 2))[1] == 'fragment_malformed'
    assert decoder.ingest(frame(v6(tcp()[:24], more=True), 3))[1] == 'fragment_identity_reuse'


def test_changed_next_header_invalidates_completed_ipv6_identity():
    decoder = TcpDecoder()
    decoder.ingest(frame(v6(tcp()[:24], more=True)))
    packet, _ = decoder.ingest(frame(v6(tcp()[24:], 24), 2))
    assert decoder.ingest(frame(v6(tcp()[:24], more=True, next_header=17), 3))[1] == 'fragment_identity_reuse'
    assert not packet.fragment_evidence.trusted
