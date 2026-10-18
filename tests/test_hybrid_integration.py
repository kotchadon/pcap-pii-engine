"""Integration tests: no real user traffic or unmasked data is used."""
import importlib.util
import json
from pathlib import Path
import pytest

from packet_pii.engine import analyze
from packet_pii.hybrid import infer_http_fields, load_experimental_bilstm
from packet_pii.ml import EntityLabel, EntitySpan, ScoreType, FieldInput


class StubModel:
    model_version = 'stub-v1'

    def predict_fields(self, fields):
        results = []
        for f in fields:
            start = f.text.find('Alex Example')
            if start >= 0:
                results.append(EntitySpan(f.field_index, EntityLabel.PERSON_NAME,
                                          start, start + len('Alex Example'),
                                          self.model_version, 0.91,
                                          ScoreType.UNCALIBRATED_MODEL_SCORE))
        return results


@pytest.fixture()
def demo(tmp_path):
    script = Path(__file__).resolve().parents[1] / 'examples' / 'generate_demo.py'
    spec = importlib.util.spec_from_file_location('synthetic', script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    path = tmp_path / 'demo.pcap'
    mod.write_pcap(path)
    return path


def test_rules_only_default_contract_unchanged(demo):
    result = analyze(demo)
    assert result['metadata']['detection_method'] == 'rules_only'
    assert result['summary']['potential_leaks'] == 7
    assert result['summary']['ml_findings'] == 0
    assert not any(f['detector'] == 'bilstm' for f in result['findings'])


def test_hybrid_standalone_scores_and_provenance(demo):
    result = analyze(demo, ml_detector=StubModel())
    assert result['metadata']['detection_method'] == 'rules_plus_bilstm'
    assert result['summary']['rules_findings'] == 7
    assert result['summary']['ml_findings'] == 1
    assert result['summary']['potential_leaks'] == 8
    assert result['metadata']['ml_model_version'] == 'stub-v1'
    finding = next(f for f in result['findings'] if f['detector'] == 'bilstm')
    assert finding['pii_type'] == 'PERSON_NAME'
    assert finding['value'] == 'Al***le'
    assert finding['confidence_type'] == 'uncalibrated_model_score'
    assert finding['span_start'] == 0 and finding['span_end'] == 12
    assert finding['location'] == 'json_body.full_name'
    assert finding['flow_id'] == 'flow_0001'
    assert finding['http_message_id'] and finding['timestamp']
    assert 'Alex Example' not in json.dumps(result)
    assert result['summary']['ml_fields_excluded_by_policy'] >= 4


def test_hybrid_repeated_fields_unsafe_field_exclusion_and_skip():
    fields = [
        ('json_body.name', 'Alex Example'),
        ('json_body.name', 'Alex Example'),
        ('json_body.password', 'Alex Example'),
        ('header.authorization', 'Bearer Alex Example'),
        ('json_body.email', 'alex@example.com'),
        ('body.note', 'z' * 65537),
    ]
    result = infer_http_fields(fields, StubModel())
    assert result.fields_evaluated == 2
    assert result.fields_excluded == 3
    assert result.fields_skipped == 1
    assert [f['field_index'] for f in result.findings] == [0, 1]
    assert all(f['value'] == 'Al***le' for f in result.findings)


def test_hybrid_explicit_sensitive_values_only():
    fields = [('json_body.customer', 'Alex Example')]
    masked = infer_http_fields(fields, StubModel())
    raw = infer_http_fields(fields, StubModel(), include_values=True)
    assert masked.findings[0]['value'] == 'Al***le'
    assert raw.findings[0]['value'] == 'Alex Example'


def test_model_validation_failure_fails_analysis_closed(demo):
    class InvalidModel:
        model_version = 'bad-model'
        def predict_fields(self, fields):
            return [EntitySpan(999, EntityLabel.PERSON_NAME, 0, 2, 'bad-model',
                               0.9, ScoreType.UNCALIBRATED_MODEL_SCORE)]
    with pytest.raises(ValueError, match='unknown field_index'):
        analyze(demo, ml_detector=InvalidModel())


def test_real_saved_checkpoint_live_inference(demo):
    pytest.importorskip('torch')
    path = Path(__file__).resolve().parents[1] / 'src/packet_pii/ml/artifacts/bilstm_v1'
    detector = load_experimental_bilstm(str(path))
    report = analyze(demo, ml_detector=detector)
    assert report['summary']['ml_fields_evaluated'] > 0
    assert report['metadata']['ml_model_version'] == detector.model_version
    assert report['summary']['rules_findings'] == 7
    assert report['metadata']['raw_values_included'] is False
    assert 'demo-only-secret' not in json.dumps(report)
    assert all(x['confidence_type'] == 'uncalibrated_model_score'
               for x in report['findings'] if x['detector'] == 'bilstm')
