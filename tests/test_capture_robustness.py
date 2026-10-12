"""Capture input/resource regressions; synthetic data only, no ML overlap."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import struct

import pytest

from packet_pii.capture import (CaptureDiagnostics, CaptureFormatError,
                                read_frames)
from packet_pii.cli import main
from packet_pii.engine import AnalysisLimits, AnalysisLimitError, analyze

SPEC = importlib.util.spec_from_file_location(
    'gen_robustness', Path(__file__).resolve().parents[1] / 'examples/generate_demo.py')
assert SPEC and SPEC.loader
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)


def demo_pcap(tmp_path: Path) -> Path:
    path = tmp_path / 'demo.pcap'
    DEMO.write_pcap(path)
    return path


def demo_pcapng(tmp_path: Path) -> Path:
    path = tmp_path / 'demo.pcapng'
    DEMO.write_pcapng(path)
    return path


def write_frames(path: Path, frames: list[bytes]) -> None:
    with path.open('wb') as output:
        output.write(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1))
        for frame in frames:
            output.write(struct.pack('<IIII', 1, 0, len(frame), len(frame)))
            output.write(frame)


def test_unchanged_demo_is_complete_and_records_budgets(tmp_path):
    result = analyze(demo_pcap(tmp_path))
    assert result['summary']['analysis_incomplete'] is False
    assert result['summary']['capture_truncated_records'] == 0
    assert result['summary']['capture_malformed_records'] == 0
    assert result['metadata']['analysis_limits']['max_packets'] == 100_000
    assert result['summary']['potential_leaks'] == 7


def test_pcap_truncated_trailing_record_is_reported_not_silently_ignored(tmp_path):
    path = demo_pcap(tmp_path)
    with path.open('ab') as output:
        output.write(b'\x00' * 8)
    result = analyze(path)
    assert result['summary']['http_messages'] == 2
    assert result['summary']['capture_truncated_records'] == 1
    assert result['summary']['analysis_incomplete'] is True
    assert any('analysis is incomplete' in x for x in result['limitations'])


def test_pcap_truncated_payload_is_flagged(tmp_path):
    path = tmp_path / 'truncated.pcap'
    with path.open('wb') as output:
        output.write(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1))
        output.write(struct.pack('<IIII', 1, 0, 100, 100))
        output.write(b'only a few bytes')
    result = analyze(path)
    assert result['summary']['packets_captured'] == 0
    assert result['summary']['capture_truncated_records'] == 1
    assert result['summary']['analysis_incomplete'] is True


def test_oversized_record_claim_is_rejected_without_allocation(tmp_path):
    path = tmp_path / 'giant.pcap'
    with path.open('wb') as output:
        output.write(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1))
        output.write(struct.pack('<IIII', 1, 0, 0xFFFFFFFF, 0xFFFFFFFF))
    result = analyze(path)
    assert result['summary']['capture_malformed_records'] == 1
    assert result['summary']['analysis_incomplete'] is True


def test_corrupt_pcap_included_length_exceeding_wire_length_flagged(tmp_path):
    path = tmp_path / 'corrupt.pcap'
    with path.open('wb') as output:
        output.write(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1))
        output.write(struct.pack('<IIII', 1, 0, 40, 20))
    result = analyze(path)
    assert result['summary']['capture_malformed_records'] == 1


@pytest.mark.parametrize('bad', [b'', b'not a capture', b'\xd4\xc3\xb2\xa1short'])
def test_invalid_capture_errors_without_false_success(tmp_path, bad):
    path = tmp_path / 'invalid.pcap'
    path.write_bytes(bad)
    with pytest.raises(CaptureFormatError):
        analyze(path)


def test_input_file_limit_is_checked_before_packet_read(tmp_path):
    path = demo_pcap(tmp_path)
    with pytest.raises(CaptureFormatError, match='file-size limit'):
        analyze(path, limits=AnalysisLimits(max_capture_bytes=64))


def test_packet_count_limit_prevents_partial_report(tmp_path):
    path = demo_pcap(tmp_path)
    with pytest.raises(AnalysisLimitError, match='packet limit'):
        analyze(path, limits=AnalysisLimits(max_packets=7))


def test_flow_count_limit_works_independently_of_packet_count(tmp_path):
    frames = [DEMO.tcp_frame('192.0.2.10', 30001, '198.51.100.20', 80, 10),
              DEMO.tcp_frame('192.0.2.10', 30002, '198.51.100.20', 80, 10)]
    path = tmp_path / 'flows.pcap'
    write_frames(path, frames)
    with pytest.raises(AnalysisLimitError, match='flow limit'):
        analyze(path, limits=AnalysisLimits(max_flows=1))


def test_tcp_payload_buffer_limit_counts_each_packet(tmp_path):
    path = demo_pcap(tmp_path)
    with pytest.raises(AnalysisLimitError, match='TCP payload limit'):
        analyze(path, limits=AnalysisLimits(max_tcp_payload_bytes=8))


@pytest.mark.parametrize('bad', [0, -1, 1.5, True, '100'])
def test_invalid_resource_limit_values_rejected(bad):
    with pytest.raises(ValueError, match='positive integer'):
        AnalysisLimits(max_packets=bad)


def test_limits_wrong_type_is_rejected(tmp_path):
    with pytest.raises(TypeError, match='AnalysisLimits'):
        analyze(demo_pcap(tmp_path), limits={'max_packets': 10})


def test_pcapng_trailing_short_block_is_marked_incomplete(tmp_path):
    path = demo_pcapng(tmp_path)
    with path.open('ab') as stream:
        stream.write(b'\x06\x00\x00')
    result = analyze(path)
    assert result['summary']['http_messages'] == 2
    assert result['summary']['capture_truncated_records'] == 1
    assert result['summary']['analysis_incomplete'] is True


def test_pcapng_bad_block_trailer_is_reported(tmp_path):
    path = demo_pcapng(tmp_path)
    raw = bytearray(path.read_bytes())
    # The first block is a 28-byte section header; damage only its trailing size.
    raw[24:28] = b'\x00\x00\x00\x00'
    path.write_bytes(raw)
    result = analyze(path)
    assert result['summary']['packets_captured'] == 0
    assert result['summary']['capture_malformed_records'] == 1
    assert result['summary']['analysis_incomplete'] is True


def test_pcapng_unknown_packet_interface_is_reported(tmp_path):
    path = demo_pcapng(tmp_path)
    raw = bytearray(path.read_bytes())
    shb_len = struct.unpack_from('<I', raw, 4)[0]
    idb_len = struct.unpack_from('<I', raw, shb_len + 4)[0]
    epb = shb_len + idb_len
    assert struct.unpack_from('<I', raw, epb)[0] == 6
    struct.pack_into('<I', raw, epb + 8, 555)
    path.write_bytes(raw)
    result = analyze(path)
    assert result['summary']['capture_malformed_records'] == 1
    assert result['summary']['analysis_incomplete'] is True
    assert result['summary']['packets_captured'] == 7


def test_cli_resource_error_does_not_publish_partial_report(tmp_path, capsys):
    path = demo_pcap(tmp_path)
    output = tmp_path / 'result.json'
    assert main([str(path), '-o', str(output), '--max-packets', '1']) == 1
    assert not output.exists()
    assert 'packet limit' in capsys.readouterr().err


def test_cli_invalid_budget_does_not_publish_partial_report(tmp_path, capsys):
    path = demo_pcap(tmp_path)
    output = tmp_path / 'result.json'
    assert main([str(path), '-o', str(output), '--max-flows', '0']) == 1
    assert not output.exists()
    assert 'positive integer' in capsys.readouterr().err


def test_cli_valid_small_cap_succeeds_with_clean_summary(tmp_path):
    path = demo_pcap(tmp_path)
    output = tmp_path / 'result.json'
    assert main([str(path), '-o', str(output), '--max-packets', '8']) == 0
    report = json.loads(output.read_text())
    assert report['summary']['analysis_incomplete'] is False
    assert report['metadata']['analysis_limits']['max_packets'] == 8


@pytest.mark.skipif(os.name != 'posix' or not hasattr(os, 'mkfifo'),
                    reason='FIFO test requires POSIX')
def test_fifo_is_rejected_before_opening_and_cannot_hang(tmp_path):
    fifo = tmp_path / 'pipe.pcap'
    os.mkfifo(fifo)
    with pytest.raises(CaptureFormatError, match='regular file'):
        list(read_frames(fifo))


def test_pcapng_truncated_enhanced_packet_block_flagged(tmp_path):
    path = demo_pcapng(tmp_path)
    path.write_bytes(path.read_bytes()[:-5])
    report = analyze(path)
    assert report['summary']['capture_truncated_records'] == 1
    assert report['summary']['analysis_incomplete'] is True
    assert report['summary']['packets_captured'] == 7


def test_stream_gap_marks_analysis_incomplete(tmp_path):
    header = b'GET /?email=a%40example.com HTTP/1.1\r\nHost: test\r\n\r\n'
    first = header[:14]
    last = header[17:]
    frames = [DEMO.tcp_frame('192.0.2.10', 60000, '198.51.100.20', 80, 1000,
                             flags=0x02),
              DEMO.tcp_frame('192.0.2.10', 60000, '198.51.100.20', 80, 1001, first),
              DEMO.tcp_frame('192.0.2.10', 60000, '198.51.100.20', 80,
                             1001 + len(first) + 3, last)]
    path = tmp_path / 'gapped.pcap'
    write_frames(path, frames)
    report = analyze(path)
    assert report['summary']['stream_gaps'] == 1
    assert report['summary']['capture_malformed_records'] == 0
    assert report['summary']['analysis_incomplete'] is True
