"""Small deterministic generator and benchmark contract; no large CI fixtures."""
import hashlib
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'/'validation'))
from generate_captures import generate
from compare_reassembly import compare
from benchmark_capture import benchmark


def test_generator_is_reproducible_and_exact_byte_oracle_passes(tmp_path):
    first,second = tmp_path/'a.pcap',tmp_path/'b.pcap'
    expected = generate(first,0.1)
    assert generate(second,0.1) == expected
    assert hashlib.sha256(first.read_bytes()).hexdigest() == expected['sha256']
    report = compare(first,manifest=expected)
    assert report['directional_digest_checks'] == 2*expected['flows']
    measured = benchmark(first)
    assert measured['counters']['packets'] == expected['packets']
    assert measured['flows'] == measured['counters']['sessions'] == expected['flows']
    assert measured['counters']['http_messages'] == expected['http_messages']
    assert measured['counters']['reassembled_bytes'] == expected['unique_payload_bytes']
    assert measured['counters']['unsafe_directions'] == 0
    assert measured['limit_failure'] is None
    diagnostics = measured['capture_diagnostics']
    assert all(diagnostics[key] == 0 for key in ('truncated_records','malformed_records','unsupported_packet_records'))
    assert diagnostics['capture_sha256'] == expected['sha256']
    assert diagnostics['capture_bytes'] == first.stat().st_size
    assert diagnostics['identity_status'] == 'verified_read'


def test_generator_does_not_overwrite_and_benchmark_honors_run_limits(tmp_path):
    path = tmp_path/'fixture.pcap'
    generate(path,0.1)
    with pytest.raises(FileExistsError):
        generate(path,0.1)
    report = benchmark(path,max_packets=10)
    assert report['limit_failure'] == 'max_packets'
    assert report['counters']['packets'] == 10
    assert report['throughput_mib_s'] is None


def test_oracle_rejects_empty_and_truncated_captures(tmp_path):
    path = tmp_path/'bad.pcap'
    generate(path,0.1)
    raw = path.read_bytes()
    path.write_bytes(raw+b'broken record')
    with pytest.raises(AssertionError,match='damaged capture'):
        compare(path)
    path.write_bytes(raw[:24])
    with pytest.raises(AssertionError,match='empty'):
        compare(path)
