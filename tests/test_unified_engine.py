"""Unified retained/streamed hybrid contracts; detectors here are test doubles."""
import importlib.util
import json
from pathlib import Path

import pytest

from packet_pii import engine
from packet_pii.hybrid import infer_http_fields
from packet_pii.ml import EntityLabel, EntitySpan, ScoreType


class Model:
    model_version = 'test-model'

    def __init__(self, predict=True):
        self.calls = []
        self.predict = predict

    def predict_fields(self, fields):
        self.calls.append(fields)
        if not self.predict:
            return []
        result = []
        for field in fields:
            start = field.text.find('Alex Example')
            if start >= 0:
                result.append(EntitySpan(field.field_index, EntityLabel.PERSON_NAME,
                                        start, start + 12, self.model_version,
                                        .91, ScoreType.UNCALIBRATED_MODEL_SCORE))
        return result


@pytest.fixture
def capture(tmp_path):
    script = Path(__file__).resolve().parents[1] / 'examples/generate_demo.py'
    spec = importlib.util.spec_from_file_location('unified_synthetic', script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    path = tmp_path / 'capture.pcap'
    mod.write_pcap(path)
    return path


def test_zero_predictions_records_real_invocation_and_count_identity(capture):
    model = Model(predict=False)
    report = engine.analyze(capture, ml_detector=model)
    s = report['summary']
    assert model.calls and s['ml_invoked']
    assert s['ml_findings'] == 0
    assert s['ml_predictions_by_label'] == {'PERSON_NAME': 0, 'USERNAME': 0}
    assert s['ml_fields_evaluated'] == sum(map(len, model.calls)) > 0
    assert s['fields_extracted'] == (s['ml_fields_eligible'] + s['ml_fields_empty']
                                     + s['ml_fields_excluded_by_policy'])
    assert s['ml_fields_eligible'] == s['ml_fields_evaluated'] + s['ml_fields_skipped']
    assert s['ml_processing_time_seconds'] > 0
    assert not s['ml_inference_failed'] and not s['ml_incomplete']
    assert report['metadata']['ml_model_loaded']
    rules = engine.analyze(capture)
    assert rules['summary']['fields_extracted'] == s['fields_extracted']
    assert not rules['summary']['ml_invoked']
    assert rules['summary']['ml_fields_eligible'] == 0
    assert not rules['metadata']['ml_requested']


def test_policy_empty_bounded_counts_are_disjoint():
    model = Model(False)
    fields = [('header.host', ''), ('json_body.empty', ''),
              ('json_body.name', 'Alex'), ('json_body.other', 'Other'),
              ('json_body.long', 'z' * 65537)]
    result = infer_http_fields(fields, model, max_fields=1)
    assert result.fields_excluded == 1
    assert result.fields_empty == 1
    assert result.fields_evaluated == 1
    assert result.fields_skipped == 2
    assert result.fields_eligible == 3
    assert len(fields) == result.fields_excluded + result.fields_empty + result.fields_eligible
    no_call = infer_http_fields(fields[:2], model)
    assert not no_call.invoked and no_call.processing_time_seconds == 0
    assert len(model.calls) == 1
    bounded = infer_http_fields(fields[2:4], model, max_characters=4)
    assert bounded.fields_evaluated == 1 and bounded.fields_skipped == 1


def test_streamed_hybrid_matches_in_memory_with_private_provenance(capture, tmp_path):
    expected = engine.analyze(capture, ml_detector=Model())
    target = tmp_path / 'hybrid.json'
    events, rows = [], []
    receipt = engine.analyze_to_report(capture, target, ml_detector=Model(),
                                      progress=events.append,
                                      row_observer=lambda kind, row: rows.append((kind, row)))
    actual = json.loads(target.read_text())
    assert actual['findings'] == expected['findings']
    assert actual['flows'] == expected['flows']
    for key, value in expected['summary'].items():
        if key not in ('processing_time_seconds', 'ml_processing_time_seconds'):
            assert actual['summary'][key] == value
    assert receipt['summary'] == actual['summary'] and 'findings' not in receipt
    assert target.stat().st_mode & 0o777 == 0o600
    assert actual['ml_field_coverage'] == expected['ml_field_coverage']
    assert len(rows) == sum(len(actual[key]) for key in ('flows', 'findings', 'ml_field_coverage'))
    assert events[-1]['stage'] == 'complete'
    assert 'Alex Example' not in target.read_text() + json.dumps(events)
    assert not list(tmp_path.glob('.pcap-pii-*'))


def test_scan_wide_ml_bound_marks_partial_analysis(capture, tmp_path, monkeypatch):
    monkeypatch.setattr(engine, 'extract_fields',
                        lambda message: [('json_body.name', 'Alex'), ('json_body.other', 'Pat')])
    model = Model(False)
    result = engine.analyze_to_report(capture, tmp_path / 'bounded.json', ml_detector=model,
                                     ml_work_budget=engine.MLWorkBudget(max_total_fields=1))
    s = result['summary']
    assert s['ml_fields_evaluated'] == 1
    assert s['ml_fields_skipped'] > 0
    assert s['ml_incomplete'] and s['analysis_incomplete']
    assert s['ml_fields_eligible'] == 1 + s['ml_fields_skipped']
    assert sum(map(len, model.calls)) == 1


def test_ml_field_locations_are_masked_and_unicode_offsets_unchanged(capture, monkeypatch):
    monkeypatch.setattr(engine, 'extract_fields',
                        lambda message: [('json_body.alex@example.com', '🙂 Alex Example')])
    result = engine.analyze(capture, ml_detector=Model())
    findings = [f for f in result['findings'] if f['detector'] == 'bilstm']
    assert findings
    for f in findings:
        assert f['location'] == 'json_body.[redacted-key]'
        assert (f['span_start'], f['span_end'], f['field_index']) == (2, 14, 0)
        assert f['confidence'] == .91
        assert f['confidence_type'] == 'uncalibrated_model_score'
        assert f['http_message_id'] and f['flow_id'] and f['timestamp']
    assert 'alex@example.com' not in json.dumps(result)


@pytest.mark.parametrize('failure', ['inference', 'findings', 'observer', 'report'])
def test_streamed_failures_preserve_existing_report_and_remove_spools(capture, tmp_path, failure):
    target = tmp_path / 'existing.json'
    target.write_text('previous report')
    model = Model()
    kwargs = {}
    if failure == 'inference':
        def broken(fields):
            raise RuntimeError('inference failed')
        model.predict_fields = broken
    elif failure == 'findings':
        kwargs['limits'] = engine.AnalysisLimits(max_findings=7)
    elif failure == 'observer':
        def broken_row(kind, row):
            raise RuntimeError('index failed')
        kwargs['row_observer'] = broken_row
    else:
        kwargs['limits'] = engine.AnalysisLimits(max_report_bytes=128)
    with pytest.raises((RuntimeError, engine.AnalysisLimitError)):
        engine.analyze_to_report(capture, target, overwrite=True, ml_detector=model, **kwargs)
    assert target.read_text() == 'previous report'
    assert not list(tmp_path.glob('.pcap-pii-*'))


def test_cli_checkpoint_opt_in_and_failure_is_closed(capture, tmp_path, monkeypatch):
    from packet_pii import cli
    monkeypatch.setattr(cli, 'load_experimental_bilstm', lambda path: Model())
    target = tmp_path / 'cli.json'
    assert cli.main([str(capture), '-o', str(target), '--ml-checkpoint', 'test']) == 0
    assert json.loads(target.read_text())['metadata']['ml_requested']
    def fail(path):
        raise ValueError('missing checkpoint')
    monkeypatch.setattr(cli, 'load_experimental_bilstm', fail)
    target2 = tmp_path / 'missing.json'
    assert cli.main([str(capture), '-o', str(target2), '--ml-checkpoint', 'missing']) == 1
    assert not target2.exists()
