"""Regression tests for the report/CLI boundary; synthetic captures only."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat

import pytest

from packet_pii.cli import main
from packet_pii.engine import analyze
from packet_pii.reporting import write_private_report

DEMO = Path(__file__).resolve().parents[1] / 'examples' / 'generate_demo.py'
spec = importlib.util.spec_from_file_location('demo_reporting_security', DEMO)
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


def capture(tmp_path):
    target = tmp_path / 'demo.pcap'
    demo.write_pcap(target)
    return target


def test_default_report_no_unkeyed_identifying_fingerprints(tmp_path):
    report = analyze(capture(tmp_path))
    assert report['metadata']['report_schema_version'] == '1.1.0'
    assert report['metadata']['raw_values_included'] is False
    assert report['findings']
    assert all('fingerprint' not in finding for finding in report['findings'])
    assert all(f['detector'] == 'rule' for f in report['findings'])
    assert all(0 <= f['confidence'] <= 1 for f in report['findings'])
    blob = json.dumps(report)
    assert 'demo-only-secret' not in blob
    assert 'student@example.com' not in blob
    assert '0412345678' not in blob


def test_explicit_unmasked_report_still_omits_unkeyed_hash(tmp_path):
    report = analyze(capture(tmp_path), include_values=True)
    assert any(f['value'] == 'student@example.com' for f in report['findings'])
    assert not any('fingerprint' in f for f in report['findings'])


def test_private_report_created_mode_600_and_utf8(tmp_path):
    report_file = tmp_path / 'report.json'
    write_private_report({'value': 'José'}, report_file)
    assert stat.S_IMODE(report_file.stat().st_mode) == 0o600
    assert json.loads(report_file.read_text(encoding='utf-8')) == {'value': 'José'}


def test_existing_report_is_never_silently_overwritten(tmp_path):
    report_file = tmp_path / 'report.json'
    report_file.write_text('original')
    with pytest.raises(FileExistsError):
        write_private_report({'new': True}, report_file)
    assert report_file.read_text() == 'original'
    assert not list(tmp_path.glob('.report.json.*.tmp'))


def test_explicit_overwrite_is_atomic_and_mode_600(tmp_path):
    report_file = tmp_path / 'report.json'
    report_file.write_text('old')
    os.chmod(report_file, 0o644)
    write_private_report({'new': True}, report_file, overwrite=True)
    assert json.loads(report_file.read_text()) == {'new': True}
    assert stat.S_IMODE(report_file.stat().st_mode) == 0o600
    assert not list(tmp_path.glob('.report.json.*.tmp'))


def test_symlink_output_is_not_followed_by_default(tmp_path):
    victim = tmp_path / 'unrelated.txt'
    victim.write_text('must remain unchanged')
    pointer = tmp_path / 'report.json'
    pointer.symlink_to(victim)
    with pytest.raises(FileExistsError):
        write_private_report({'safe': True}, pointer)
    assert victim.read_text() == 'must remain unchanged'
    assert pointer.is_symlink()


def test_explicit_overwrite_replaces_link_not_its_target(tmp_path):
    victim = tmp_path / 'unrelated.txt'
    victim.write_text('must remain unchanged')
    pointer = tmp_path / 'report.json'
    pointer.symlink_to(victim)
    write_private_report({'safe': True}, pointer, overwrite=True)
    assert victim.read_text() == 'must remain unchanged'
    assert not pointer.is_symlink()
    assert json.loads(pointer.read_text()) == {'safe': True}


def test_serialization_error_leaves_no_partial_report(tmp_path):
    report_file = tmp_path / 'report.json'
    with pytest.raises(TypeError):
        write_private_report({'bad': object()}, report_file)
    assert not report_file.exists()
    assert not list(tmp_path.glob('.report.json.*.tmp'))


def test_cli_no_overwrite_and_no_raw_value_printed(tmp_path, capsys):
    cap = capture(tmp_path)
    out = tmp_path / 'report.json'
    assert main([str(cap), '-o', str(out)]) == 0
    assert out.exists()
    assert main([str(cap), '-o', str(out)]) == 1
    captured = capsys.readouterr()
    assert 'student@example.com' not in captured.out + captured.err
    assert 'demo-only-secret' not in captured.out + captured.err
    assert json.loads(out.read_text())['summary']['potential_leaks'] == 7


def test_cli_prevents_overwriting_input_capture(tmp_path, capsys):
    cap = capture(tmp_path)
    original = cap.read_bytes()
    assert main([str(cap), '-o', str(cap), '--overwrite']) == 1
    assert cap.read_bytes() == original
    assert 'must not be the input capture file' in capsys.readouterr().err


def test_cli_overwrite_requires_explicit_flag(tmp_path):
    cap = capture(tmp_path)
    out = tmp_path / 'report.json'
    out.write_text('an old report')
    assert main([str(cap), '-o', str(out), '--overwrite']) == 0
    assert json.loads(out.read_text())['summary']['packets_captured'] == 8


def test_cli_warns_when_raw_values_are_explicitly_included(tmp_path, capsys):
    cap = capture(tmp_path)
    out = tmp_path / 'sensitive.json'
    assert main([str(cap), '-o', str(out), '--include-values']) == 0
    captured = capsys.readouterr()
    assert 'unmasked PII/credentials' in captured.err
    assert 'student@example.com' not in captured.out + captured.err
    assert any(f['value'] == 'student@example.com'
               for f in json.loads(out.read_text())['findings'])


def test_field_location_redacts_untrusted_key_names():
    from packet_pii.engine import safe_field_location
    assert safe_field_location('json_body.customer[0].email') == 'json_body.customer[0].email'
    assert safe_field_location('query_parameter.phone') == 'query_parameter.phone'
    assert safe_field_location('json_body.alice@example.com') == 'json_body.[redacted-key]'
    assert safe_field_location('form.a-secret\r\nHeader') == 'form.[redacted-key]'
    assert safe_field_location('json_body.' + 'A'*100) == 'json_body.[redacted-key]'
    assert safe_field_location('json_body.alice@example.com', include_values=True) == 'json_body.alice@example.com'


def test_report_schema_is_valid_json_and_describes_current_fields(tmp_path):
    schema_path = Path(__file__).resolve().parents[1] / 'schemas' / 'report-v1.schema.json'
    schema = json.loads(schema_path.read_text(encoding='utf-8'))
    report = analyze(capture(tmp_path))
    assert report['metadata']['report_schema_version'] == schema['properties']['metadata']['properties']['report_schema_version']['const']
    assert set(schema['required']).issubset(report)
    for section in ('metadata', 'summary'):
        assert set(schema['properties'][section]['required']).issubset(report[section])
    for obj in report['findings']:
        assert set(schema['$defs']['finding']['required']).issubset(obj)
    for obj in report['flows']:
        assert set(schema['$defs']['flow']['required']).issubset(obj)


def test_untrusted_json_key_does_not_escape_into_default_report(tmp_path):
    import struct
    body = b'{"victim@example.invalid":"target@example.invalid"}'
    request = (b'POST / HTTP/1.1\r\nHost: example.invalid\r\nContent-Type: application/json\r\n'
               b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
    frame = demo.tcp_frame('192.0.2.10', 50123, '198.51.100.20', 80, 100, request)
    pcap = tmp_path / 'key.pcap'
    with pcap.open('wb') as stream:
        stream.write(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1))
        stream.write(struct.pack('<IIII', 12345, 0, len(frame), len(frame)))
        stream.write(frame)
    report = analyze(pcap)
    assert any(f['pii_type'] == 'EMAIL' for f in report['findings'])
    assert 'victim@example.invalid' not in json.dumps(report)
    assert 'target@example.invalid' not in json.dumps(report)
    assert report['findings'][0]['location'] == 'json_body.[redacted-key]'
