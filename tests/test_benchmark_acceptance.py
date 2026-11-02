"""Acceptance harness must fail closed and hash evidence, not just totals."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/validation/bench_performance_memory.py'


def run(tmp_path, *args):
    return subprocess.run([sys.executable, str(SCRIPT), '--source-root', str(ROOT),
                           '--capture', str(tmp_path / 'fictional.pcap'),
                           '--output', str(tmp_path / 'result.json'), *args],
                          capture_output=True, text=True, timeout=30)


def test_stress_indexed_benchmark_records_memory_and_verified_identity(tmp_path):
    result = run(tmp_path, '--mib', '.01', '--profile', 'stress', '--indexed', '--worker-timeout', '30')
    assert result.returncode == 0, result.stderr
    report = json.loads((tmp_path / 'result.json').read_text())
    assert report['worker_timeout_seconds'] == 30
    assert report['runs'][0]['status'] == 'completed'
    assert report['runs'][0]['memory']
    import hashlib
    assert report['capture_sha256'] == hashlib.sha256((tmp_path / 'fictional.pcap').read_bytes()).hexdigest()


def test_wrong_capture_hash_fails_before_scan_or_model_load(tmp_path):
    (tmp_path / 'fictional.pcap').write_bytes(b'wrong capture')
    result = run(tmp_path, '--expected-capture-sha256', '0' * 64)
    assert result.returncode != 0
    assert 'capture SHA-256 mismatch' in result.stderr
    assert not (tmp_path / 'result.json').exists()


def test_capture_changed_after_preflight_is_rejected(tmp_path, monkeypatch):
    first = run(tmp_path, '--mib', '.01')
    assert first.returncode == 0
    (tmp_path / 'result.json').unlink()
    (tmp_path / 'result.scan0.json').unlink()
    spec = importlib.util.spec_from_file_location('bench_race', SCRIPT)
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    from packet_pii import engine
    real = engine.analyze_to_report
    def changed_capture(capture, *args, **kwargs):
        data = bytearray(capture.read_bytes())
        data[24] ^= 1  # valid first-record timestamp change after the preflight hash
        capture.write_bytes(data)
        return real(capture, *args, **kwargs)
    monkeypatch.setattr(engine, 'analyze_to_report', changed_capture)
    monkeypatch.setattr(sys, 'argv', [str(SCRIPT), '--source-root', str(ROOT), '--capture',
                                    str(tmp_path / 'fictional.pcap'), '--output', str(tmp_path / 'result.json')])
    assert bench.main() == 1
    result = json.loads((tmp_path / 'result.json').read_text())
    assert 'capture identity' in result['runs'][0]['error']


def test_digest_failure_closes_private_job_and_returns_failure(tmp_path, monkeypatch):
    first = run(tmp_path, '--mib', '.01')
    assert first.returncode == 0
    (tmp_path / 'result.json').unlink()
    spec = importlib.util.spec_from_file_location('bench_cleanup', SCRIPT)
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    from packet_pii import jobs, engine
    original_runner = engine.MLBatchRunner
    managers = []
    class RecordingManager(jobs.JobManager):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            managers.append(self)
    monkeypatch.setattr(jobs, 'JobManager', RecordingManager)
    def failed_digest(*a, **kw):
        raise subprocess.CalledProcessError(1, 'digest')
    monkeypatch.setattr(bench.subprocess, 'check_output', failed_digest)
    monkeypatch.setattr(sys, 'argv', [str(SCRIPT), '--source-root', str(ROOT), '--capture',
                                    str(tmp_path / 'fictional.pcap'), '--output', str(tmp_path / 'result.json'), '--indexed'])
    assert bench.main() == 1
    assert managers[0].closed and not managers[0].root.exists()
    assert engine.MLBatchRunner is original_runner


def test_failed_scan_is_not_a_successful_benchmark(tmp_path):
    (tmp_path / 'fictional.pcap').write_bytes(b'not a pcap')
    result = run(tmp_path)
    assert result.returncode != 0
    assert json.loads((tmp_path / 'result.json').read_text())['runs'][0]['status'] == 'failed'


def test_partial_capture_is_rejected_by_complete_acceptance(tmp_path):
    # Real generated capture with a truncated final record; parser may publish a
    # truthful partial report, but the performance gate must reject that result.
    first = run(tmp_path, '--mib', '.01')
    assert first.returncode == 0
    (tmp_path / 'result.json').unlink()
    capture = tmp_path / 'fictional.pcap'
    capture.write_bytes(capture.read_bytes()[:-1])
    result = run(tmp_path, '--require-complete', '--indexed')
    assert result.returncode == 1
    report = json.loads((tmp_path / 'result.json').read_text())
    assert report['runs'][0]['status'] == 'failed'
    assert 'complete analysis' in report['runs'][0]['error']


def test_stream_signature_ignores_only_clocks_and_detects_provenance_change(tmp_path):
    pytest.importorskip('ijson')
    spec = importlib.util.spec_from_file_location('bench_acceptance', SCRIPT)
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    path = tmp_path / 'report.json'
    report = {'metadata': {'generated_at': 'first'},
              'summary': {'processing_time_seconds': 1, 'ml_processing_time_seconds': 2, 'ml_fields_evaluated': 3},
              'findings': [{'field_index': 0, 'packet_ids': [1], 'start': 1, 'end': 4, 'score': .35}]}
    path.write_text(json.dumps(report))
    initial = bench.stream_signature(path)
    report['metadata']['generated_at'] = 'second'
    report['summary']['processing_time_seconds'] = 5
    report['summary']['ml_processing_time_seconds'] = 6
    path.write_text(json.dumps(report))
    assert bench.stream_signature(path) == initial
    report['findings'][0]['packet_ids'] = [2]
    path.write_text(json.dumps(report))
    assert bench.stream_signature(path) != initial


@pytest.mark.parametrize('seconds', ['0', '-1', '7201', 'nan'])
def test_invalid_worker_timeout_rejected(tmp_path, seconds):
    result = run(tmp_path, '--worker-timeout', seconds)
    assert result.returncode == 2
    assert not (tmp_path / 'result.json').exists()
