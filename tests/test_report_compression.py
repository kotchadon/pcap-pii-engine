"""Lossless storage, privacy and failure boundaries; no model dependency."""
import gzip
import json
import os
import stat

import pytest

from packet_pii.reporting import ReportLimitError, ReportSpool, write_private_report


def test_streamed_evidence_bytes_round_trip_and_deterministic_header(tmp_path):
    # Preserve distinct identities, unknown ranges and decoded Unicode offsets.
    rows = [dict(evidence_id=f'm1_field_{i}', field_index=i,
                 decoded_text_span={'start': 1, 'end': 4}, stream_ranges=[],
                 granularity='message_level_only', limitations=['unknown_source'],
                 text='José') for i in range(100)]
    report = {'metadata': {'capture_identity': {'sha256': 'a' * 64}}, 'field_evidence': []}
    with ReportSpool(tmp_path, 100_000) as spool:
        for row in rows:
            spool.field_evidence.append(row)
        for name in ('plain.json', 'first.json.gz', 'second.json.gz'):
            write_private_report(report, tmp_path / name, max_bytes=100_000,
                                 row_sources={'field_evidence': spool.field_evidence.iter_json()})
    raw = (tmp_path / 'plain.json').read_bytes()
    compressed = (tmp_path / 'first.json.gz').read_bytes()
    assert gzip.decompress(compressed) == raw
    assert json.loads(raw)['field_evidence'] == rows
    assert compressed == (tmp_path / 'second.json.gz').read_bytes()
    assert compressed[3] == 0  # no filename/comment flags
    assert compressed[4:8] == b'\0' * 4  # no timestamp
    assert len(compressed) < len(raw)
    assert stat.S_IMODE((tmp_path / 'first.json.gz').stat().st_mode) == 0o600


@pytest.mark.parametrize('suffix', ['.json', '.json.gz'])
def test_logical_byte_limit_and_serialization_failure_are_atomic(tmp_path, suffix):
    target = tmp_path / ('report' + suffix)
    target.write_bytes(b'old complete report')
    with pytest.raises(ReportLimitError):
        write_private_report({'repeated': 'x' * 10_000}, target, overwrite=True, max_bytes=100)
    assert target.read_bytes() == b'old complete report'
    with pytest.raises(TypeError):
        write_private_report({'bad': object()}, target, overwrite=True)
    assert target.read_bytes() == b'old complete report'
    assert not list(tmp_path.glob('.*.tmp'))


def test_compressed_no_overwrite_symlink_and_explicit_replacement(tmp_path):
    victim = tmp_path / 'victim'
    victim.write_bytes(b'untouched')
    target = tmp_path / 'report.json.gz'
    target.symlink_to(victim)
    with pytest.raises(FileExistsError):
        write_private_report({'safe': True}, target)
    assert target.is_symlink()
    write_private_report({'safe': True}, target, overwrite=True)
    assert victim.read_bytes() == b'untouched'
    assert not target.is_symlink()
    assert json.loads(gzip.decompress(target.read_bytes())) == {'safe': True}
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_compressor_failure_never_publishes(tmp_path, monkeypatch):
    target = tmp_path / 'report.json.gz'
    target.write_bytes(b'old complete report')
    original = gzip.GzipFile.close

    def fail_after_trailer(self):
        was_open = self.fileobj is not None
        original(self)
        if was_open:
            raise OSError('injected trailer failure')

    monkeypatch.setattr(gzip.GzipFile, 'close', fail_after_trailer)
    with pytest.raises(OSError, match='trailer failure'):
        write_private_report({'safe': True}, target, overwrite=True)
    assert target.read_bytes() == b'old complete report'
    assert not list(tmp_path.glob('.*.tmp'))


def test_compressed_fsync_failure_never_publishes(tmp_path, monkeypatch):
    target = tmp_path / 'report.json.gz'
    target.write_bytes(b'old complete report')

    def fail(_fd):
        raise OSError('injected fsync failure')

    monkeypatch.setattr(os, 'fsync', fail)
    with pytest.raises(OSError, match='fsync failure'):
        write_private_report({'safe': True}, target, overwrite=True)
    assert target.read_bytes() == b'old complete report'
    assert not list(tmp_path.glob('.*.tmp'))


def test_row_source_cancellation_does_not_publish_partial_gzip(tmp_path):
    target = tmp_path / 'report.json.gz'

    def cancelled():
        yield '{"evidence_id":"m1_field_0"}\n'
        raise RuntimeError('cancelled')

    with pytest.raises(RuntimeError, match='cancelled'):
        write_private_report({'field_evidence': []}, target,
                             row_sources={'field_evidence': cancelled()})
    assert not target.exists()
    assert not list(tmp_path.glob('.*.tmp'))


def test_cli_compressed_capture_retains_evidence_and_masking(tmp_path):
    from packet_pii.cli import main
    from test_reporting_security import capture

    cap = capture(tmp_path)
    target = tmp_path / 'report.json.gz'
    assert main([str(cap), '-o', str(target)]) == 0
    raw = gzip.decompress(target.read_bytes())
    report = json.loads(raw)
    assert report['summary']['potential_leaks'] == 7
    assert all(report[k] for k in ('packet_evidence', 'stream_evidence', 'http_evidence', 'field_evidence'))
    assert b'student@example.com' not in raw
    assert b'demo-only-secret' not in raw
    import hashlib
    assert report['capture_evidence']['capture_sha256'] == hashlib.sha256(cap.read_bytes()).hexdigest()
    assert report['capture_evidence']['identity_status'] == 'verified_read'
