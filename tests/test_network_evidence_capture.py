"""Synthetic exact source-slice tests; no timestamp-based association."""
import struct
from dataclasses import replace

from packet_pii.capture import RawFrame, decode_tcp, read_frames, reassemble_detailed


def ipv4(payload=b'abcdefgh', seq=100):
    tcp = struct.pack('!HHIIBBHHH', 1234, 80, seq, 7, 0x50, 0x18, 4096, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 9, 0, 64, 6, 0,
                     b'\xc0\x00\x02\x01', b'\xc6\x33\x64\x02')
    return ip + tcp


def raw(data, index):
    return RawFrame(1., 101, data, frame_index=index, record_offset=24,
                    data_offset=40, captured_length=len(data), wire_length=len(data))


def test_pcap_metadata_offsets_and_nanosecond_resolution(tmp_path):
    data = ipv4()
    path = tmp_path / 'source.pcap'
    path.write_bytes(b'\x4d\x3c\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 101)
                     + struct.pack('<IIII', 1, 123, len(data), len(data)) + data)
    frame, = read_frames(path)
    assert (frame.frame_index, frame.record_offset, frame.data_offset) == (1, 24, 40)
    assert frame.timestamp_resolution == 1e-9
    packet = decode_tcp(frame)
    assert packet.ack == 7 and packet.network_protocol == 'ipv4'
    assert packet.payload_offset == 40
    source, = packet.source_ranges
    assert path.read_bytes()[source.data_offset + source.frame_start:source.data_offset + source.frame_end] == packet.payload
    assert packet.tcp_checksum == 'mismatch_offload_possible'


def test_stream_source_slices_survive_overlap_reordering_and_wrap():
    frames = [raw(ipv4(b'efghijkl', 0), 1), raw(ipv4(b'abcdefgh', 0xfffffffc), 2),
              raw(ipv4(b'abcdefgh', 0xfffffffc), 3)]
    result = reassemble_detailed([decode_tcp(f) for f in frames])
    assert result.safe_prefix == b'abcdefghijkl'
    assert [(s.stream_start, s.stream_end, s.source.frame_index) for s in result.source_ranges] == [(0, 8, 2), (8, 12, 1)]
    assert 'retransmission' in result.diagnostics and 'consistent_overlap' in result.diagnostics
    for s in result.source_ranges:
        f = frames[s.source.frame_index - 1]
        assert f.data[s.source.frame_start:s.source.frame_end] == result.data[s.stream_start:s.stream_end]
        assert s.tcp_seq_start == (result.base_seq + s.stream_start) & 0xffffffff


def test_conflict_mapping_never_extends_safe_prefix():
    packets = [decode_tcp(raw(ipv4(b'abcdefgh'), 1)), decode_tcp(raw(ipv4(b'XX', 104), 2))]
    result = reassemble_detailed(packets)
    assert result.safe_prefix == b'abcd'
    assert max(s.stream_end for s in result.source_ranges) == len(result.safe_prefix)


def test_pcapng_packet_ordinals_include_rejected_records_and_sections(tmp_path):
    def block(kind, body):
        size = 12 + len(body)
        return struct.pack('<II', kind, size) + body + struct.pack('<I', size)
    shb = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    idb = block(1, struct.pack('<HHI', 101, 0, 65535) + struct.pack('<HH', 9, 1) + b'\x89\0\0\0')
    data = ipv4()
    epb = lambda interface: block(6, struct.pack('<IIIII', interface, 0, 512, len(data), len(data)) + data)
    path = tmp_path / 'sections.pcapng'
    path.write_bytes(shb + idb + epb(2) + epb(0) + shb + idb + epb(0))
    frames = list(read_frames(path))
    assert [f.frame_index for f in frames] == [2, 3]
    assert [f.section_index for f in frames] == [0, 1]
    assert all(f.interface_id == 0 and f.timestamp_resolution == 2**-9 for f in frames)
    assert all(path.read_bytes()[f.data_offset:f.data_offset + f.captured_length] == f.data for f in frames)


def test_capture_hash_covers_exact_read_including_malformed_tail(tmp_path):
    import hashlib
    from packet_pii.capture import CaptureDiagnostics
    data = ipv4()
    contents = (b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 101)
                + struct.pack('<IIII', 1, 0, len(data), len(data)) + data + b'trailing!')
    path = tmp_path / 'identity.pcap'
    path.write_bytes(contents)
    diag = CaptureDiagnostics()
    assert len(list(read_frames(path, diagnostics=diag))) == 1
    assert diag.capture_sha256 == hashlib.sha256(contents).hexdigest()
    assert diag.capture_bytes == len(contents) and diag.identity_status == 'verified_read'
    assert diag.truncated_records == 1


def test_capture_mutation_invalidates_identity(tmp_path):
    import pytest
    from packet_pii.capture import CaptureDiagnostics, CaptureFormatError
    data = ipv4()
    path = tmp_path / 'changing.pcap'
    path.write_bytes(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 101)
                    + struct.pack('<IIII', 1, 0, len(data), len(data)) + data)
    diag = CaptureDiagnostics()
    iterator = read_frames(path, diagnostics=diag)
    next(iterator)
    with path.open('r+b') as output:
        output.seek(-1, 2)
        output.write(b'X')
    with pytest.raises(CaptureFormatError, match='changed during analysis'):
        list(iterator)
    assert diag.capture_sha256 is None and diag.identity_status == 'changed_during_read'


def test_valid_ipv4_tcp_checksums_and_modified_payload_uncertainty():
    def check(data):
        total = 0
        for index in range(0, len(data), 2):
            total += int.from_bytes(data[index:index+2].ljust(2, b'\0'), 'big')
            total = (total & 65535) + (total >> 16)
        return total ^ 65535
    data = bytearray(ipv4(b'odd'))
    struct.pack_into('!H', data, 10, check(data[:20]))
    pseudo = bytes(data[12:20]) + b'\0\x06' + struct.pack('!H', len(data)-20)
    struct.pack_into('!H', data, 36, check(pseudo + data[20:]))
    packet = decode_tcp(raw(bytes(data), 1))
    assert packet.ipv4_checksum == 'valid' and packet.tcp_checksum == 'valid'
    data[-1] ^= 1
    packet = decode_tcp(raw(bytes(data), 2))
    assert packet.tcp_checksum == 'mismatch_offload_possible'
    assert packet.payload  # Uncertainty is reported, not silently discarded.


def test_unsupported_pcapng_packet_block_is_explicit_evidence_loss(tmp_path):
    from packet_pii.capture import CaptureDiagnostics
    def block(kind, body):
        size = 12+len(body)
        return struct.pack('<II', kind, size)+body+struct.pack('<I', size)
    path = tmp_path/'unsupported.pcapng'
    path.write_bytes(block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
                     +block(3, struct.pack('<I', 4)+b'abcd'))
    diagnostics=CaptureDiagnostics()
    assert list(read_frames(path, diagnostics=diagnostics)) == []
    assert diagnostics.unsupported_packet_records == 1 and diagnostics.incomplete
    assert diagnostics.identity_status == 'verified_read'
