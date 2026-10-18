"""Resource-bound adapter tests use synthetic fields, independent of checkpoints."""
import json
from pathlib import Path

import pytest

from packet_pii.hybrid import MLWorkBudget, infer_http_fields, iter_http_field_batches
from packet_pii.ml import EntitySpan, EntityLabel, ScoreType


class RecordingDetector:
    model_version = 'scalability-test'

    def __init__(self):
        self.calls = []

    def predict_fields(self, fields):
        self.calls.append([(f.field_index, len(f.text)) for f in fields])
        return [EntitySpan(f.field_index, EntityLabel.USERNAME, 1, len(f.text),
                           self.model_version, 0.8, ScoreType.UNCALIBRATED_MODEL_SCORE)
                for f in fields if len(f.text) > 1]


def collect(fields, detector, budget, **kwargs):
    return list(iter_http_field_batches(fields, detector, work_budget=budget, **kwargs))


@pytest.mark.parametrize('changes', [
    {'max_fields_per_batch': True}, {'max_fields_per_batch': 0},
    {'max_total_fields': -1}, {'max_total_characters': 1.5},
    {'max_field_characters': 65537}, {'max_fields_per_batch': 10001},
    {'max_characters_per_batch': 0}, {'max_total_characters': 200000001},
])
def test_invalid_budget(changes):
    with pytest.raises(ValueError):
        MLWorkBudget(**changes)


def test_presets_keep_higher_coverage_explicit_and_field_safety_fixed():
    normal, high = MLWorkBudget(), MLWorkBudget.for_profile('extended')
    assert (normal.max_total_fields, normal.max_total_characters) == (10000, 2000000)
    assert (high.max_total_fields, high.max_total_characters) == (100000, 20000000)
    assert normal.max_field_characters == high.max_field_characters == 65536


def test_bounded_batches_original_indices_unicode_and_invariance():
    fields = [('body.person', '😀ผู้ใช้') for _ in range(11)]
    small = RecordingDetector()
    batches = collect(fields, small, MLWorkBudget(max_fields_per_batch=3,
                                                max_characters_per_batch=20))
    assert len(small.calls) > 1
    assert all(len(batch) <= 3 and sum(n for _, n in batch) <= 20 for batch in small.calls)
    findings = [f for batch in batches for f in batch.findings]
    large = infer_http_fields(fields, RecordingDetector())
    assert findings == large.findings
    assert [f['field_index'] for f in findings] == list(range(11))
    assert all(f['span_start'] == 1 and f['span_end'] == len(fields[0][1]) for f in findings)
    assert sum(b.fields_evaluated for b in batches) == 11


def test_oversized_paths_fields_and_empty_policy_have_exact_accounting():
    fields = [('json_body.' + 'x' * 1025, 'aa'),
              ('json_body.' + 'x' * 1025, 'bb'),
              ('json_body.' + '.'.join(['nest'] * 300), 'cc'),
              ('body.name', 'x' * 65537), ('body.name', 'ok'),
              ('header.authorization', 'secret'), ('body.note', ''), ('', 'valid')]
    detector = RecordingDetector()
    batches = collect(fields, detector, MLWorkBudget())
    assert [i for call in detector.calls for i, _ in call] == [4]
    assert sum(b.fields_eligible for b in batches) == 6
    assert sum(b.fields_skipped for b in batches) == 5
    reasons = {}
    for batch in batches:
        for reason, count in batch.skip_reasons.items():
            reasons[reason] = reasons.get(reason, 0) + count
    assert reasons == {'ml_field_path_too_long': 3, 'ml_field_too_large': 1,
                       'ml_field_path_invalid': 1}
    assert sum(b.fields_excluded + b.fields_empty + b.fields_eligible for b in batches) == len(fields)


def test_total_and_character_budgets_skip_only_observed_ineligible_work():
    batches = collect([('body.x', 'aa')] * 7, RecordingDetector(),
                      MLWorkBudget(max_fields_per_batch=2, max_total_fields=5,
                                   max_total_characters=8))
    assert sum(b.fields_evaluated for b in batches) == 4
    assert sum(b.fields_skipped for b in batches) == 3
    assert sum(b.skip_reasons.get('ml_character_budget_exceeded', 0) for b in batches) == 3
    batches = collect([('body.x', 'aa')] * 7, RecordingDetector(),
                      MLWorkBudget(max_fields_per_batch=2, max_total_fields=3))
    assert sum(b.fields_evaluated for b in batches) == 3
    assert sum(b.skip_reasons.get('ml_field_budget_exceeded', 0) for b in batches) == 4


def test_iterator_is_lazy_and_cancels_before_next_batch_without_retries():
    detector = RecordingDetector()
    events = []
    def cancel():
        events.append('check')
        if len(events) == 2:
            raise RuntimeError('cancelled')
    results = iter_http_field_batches([('body.x', 'abc')] * 5, detector,
                                     work_budget=MLWorkBudget(max_fields_per_batch=2),
                                     before_batch=cancel)
    assert detector.calls == []
    first = next(results)
    assert first.fields_evaluated == 2
    with pytest.raises(RuntimeError, match='cancelled'):
        next(results)
    assert len(detector.calls) == 1


def test_single_field_over_batch_character_bound_is_reported_without_truncation():
    detector = RecordingDetector()
    result = collect([('body.x', 'abcdefgh'), ('body.y', 'ab')], detector,
                     MLWorkBudget(max_characters_per_batch=4))
    assert detector.calls == [[(1, 2)]]
    assert sum(b.skip_reasons.get('ml_batch_character_budget_exceeded', 0) for b in result) == 1


def json_capture(tmp_path, objects):
    import importlib.util
    import struct
    generator = Path(__file__).resolve().parents[1] / 'examples/generate_demo.py'
    spec = importlib.util.spec_from_file_location('ml_batch_fixture', generator)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = tmp_path / 'ml-fields.pcap'
    with target.open('wb') as stream:
        stream.write(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1))
        seq = 100
        for number, obj in enumerate(objects, 1):
            body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
            raw = (b'POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: '
                   + str(len(body)).encode('ascii') + b'\r\n\r\n' + body)
            for start in range(0, len(raw), 1400):
                payload = raw[start:start + 1400]
                frame = module.tcp_frame('192.0.2.10', 50001, '198.51.100.20', 80,
                                         seq, payload)
                stream.write(struct.pack('<IIII', number, 0, len(frame), len(frame)) + frame)
                seq += len(payload)
    return target


def expand_ranges(ranges):
    return [index for start, end in ranges for index in range(start, end)]


@pytest.mark.parametrize('max_fields,expected_evaluated', [(100, 7), (4, 4), (0, 0)])
def test_engine_scanwide_counts_coverage_trace_and_zero_predictions(tmp_path, max_fields, expected_evaluated):
    from packet_pii.engine import analyze
    class ZeroDetector(RecordingDetector):
        def predict_fields(self, fields):
            super().predict_fields(fields)
            return []
    source = json_capture(tmp_path, [
        {'name': '😀ชื่อ', 'other': 'bb', 'email': 'synthetic@example.invalid', 'blank': ''},
        {'a': 'aa', 'b': 'bb', 'c': 'cc', 'd': 'dd', 'e': 'ee'},
    ])
    detector = ZeroDetector()
    progress = []
    report = analyze(source, ml_detector=detector, progress=progress.append,
                     ml_work_budget=MLWorkBudget(max_fields_per_batch=2, max_total_fields=max_fields))
    summary = report['summary']
    assert summary['ml_fields_eligible'] == 7
    assert summary['ml_fields_evaluated'] == expected_evaluated
    assert summary['ml_fields_skipped'] == 7 - expected_evaluated
    assert summary['fields_extracted'] == (summary['ml_fields_excluded_by_policy'] +
                                          summary['ml_fields_empty'] + 7)
    assert summary['ml_inference_complete'] is (max_fields >= 7)
    assert summary['ml_findings'] == 0
    assert summary['ml_inference_invoked'] is (expected_evaluated > 0)
    assert summary['ml_inference_batches'] == len(detector.calls)
    rows = report['ml_field_coverage']
    assert len(rows) == 2
    statuses = {status: 0 for status in ('evaluated', 'excluded_by_policy', 'empty', 'skipped')}
    for row in rows:
        all_indices = []
        for status, ranges in row['index_ranges_by_status'].items():
            indices = expand_ranges(ranges)
            assert indices == sorted(set(indices))
            statuses[status] += len(indices)
            all_indices.extend(indices)
        assert sorted(all_indices) == list(range(row['fields_extracted']))
        assert row['flow_id'] == 'flow_0001'
        assert row['http_message_id'].startswith('flow_0001_msg_')
        assert sorted(i for ranges in row['skip_reason_index_ranges'].values()
                      for i in expand_ranges(ranges)) == expand_ranges(row['index_ranges_by_status']['skipped'])
    assert statuses['evaluated'] == expected_evaluated
    updates = [event for event in progress if event['stage'] == 'ml_inference']
    assert updates and updates[-1]['ml_fields_evaluated'] == expected_evaluated
    assert [u['ml_inference_batches'] for u in updates] == sorted(u['ml_inference_batches'] for u in updates)


def test_f03_real_json_repeated_long_nested_keys_preserve_rules_and_valid_followups(tmp_path):
    from packet_pii.engine import analyze
    key = 'x' * 1100
    obj = {key: 'synthetic@example.invalid', 'nested': {key: 'private-name'}, 'valid': '😀user'}
    report = analyze(json_capture(tmp_path, [obj, obj]), ml_detector=RecordingDetector())
    summary = report['summary']
    assert summary['ml_fields_skipped'] == 4
    assert summary['ml_skip_reasons'] == {'ml_field_path_too_long': 4}
    assert summary['rules_findings'] == 2
    assert summary['ml_fields_evaluated'] == 2
    assert summary['ml_predictions_by_label'] == {'PERSON_NAME': 0, 'USERNAME': 2}
    assert all(f['field_index'] == 4 for f in report['findings'] if f['detector'] == 'bilstm')
    encoded = json.dumps(report)
    assert key not in encoded and 'synthetic@example.invalid' not in encoded and 'private-name' not in encoded


@pytest.mark.parametrize('failure', ['cancel', 'inference'])
def test_streamed_batch_failure_preserves_atomic_target_and_cleans_spools(tmp_path, failure):
    from packet_pii.engine import analyze_to_report
    from packet_pii.hybrid import InferenceError
    detector = RecordingDetector()
    source = json_capture(tmp_path, [{f'item{i}': 'abc' for i in range(7)}])
    target = tmp_path / 'report.json'
    target.write_text('previous-report')
    before = set(tmp_path.iterdir())
    events = []
    def progress(event):
        events.append(event)
        if failure == 'cancel' and event.get('ml_inference_batches') == 1:
            raise RuntimeError('cancelled')
    if failure == 'inference':
        original = detector.predict_fields
        def broken(fields):
            if detector.calls:
                raise ValueError('private-raw-pii')
            return original(fields)
        detector.predict_fields = broken
    with pytest.raises(InferenceError if failure == 'inference' else RuntimeError) as exc:
        analyze_to_report(source, target, overwrite=True, ml_detector=detector,
                          ml_work_budget=MLWorkBudget(max_fields_per_batch=2), progress=progress)
    assert 'private-raw-pii' not in str(exc.value)
    assert target.read_text() == 'previous-report'
    assert set(tmp_path.iterdir()) == before
    assert not any(event['stage'] == 'complete' for event in events)
    assert len(detector.calls) == 1


def test_streamed_coverage_and_finding_rows_match_memory_report(tmp_path):
    from packet_pii.engine import analyze, analyze_to_report
    source = json_capture(tmp_path, [{'a': '😀ชื่อ', 'b': 'bb', 'c': 'cc'}])
    budget = MLWorkBudget(max_fields_per_batch=1, max_total_fields=2)
    report = analyze(source, ml_detector=RecordingDetector(), ml_work_budget=budget)
    seen = []
    target = tmp_path / 'report.json'
    receipt = analyze_to_report(source, target, ml_detector=RecordingDetector(),
                                ml_work_budget=budget, row_observer=lambda kind, row: seen.append((kind, row)))
    stored = json.loads(target.read_text())
    assert stored['ml_field_coverage'] == report['ml_field_coverage']
    assert stored['findings'] == report['findings']
    assert 'ml_field_coverage' not in receipt
    assert any(kind == 'ml_field_coverage' for kind, _ in seen)
    assert stored['summary']['ml_inference_complete'] is False


def test_authentic_v2_batch_size_invariance_and_full_showcase(tmp_path):
    """Requires authentic committed weights; missing artifacts remain a visible failure."""
    import importlib.util
    pytest.importorskip('torch')
    from packet_pii.engine import analyze
    from packet_pii.hybrid import load_experimental_bilstm
    root = Path(__file__).resolve().parents[1]
    detector = load_experimental_bilstm(str(root / 'src/packet_pii/ml/artifacts/bilstm_v2'))
    fields = [('body.name', 'My name is Alex Example'),
              ('body.user', 'My username is alex_example_42'),
              ('body.name', '😀 My name is Maria Garcia')]
    one = collect(fields, detector, MLWorkBudget(max_fields_per_batch=1))
    many = collect(fields, detector, MLWorkBudget(max_fields_per_batch=32))
    a, b = [f for batch in one for f in batch.findings], [f for batch in many for f in batch.findings]
    # Floating-point matrix kernels can change the last few score bits.
    assert [{k: v for k, v in f.items() if k != 'confidence'} for f in a] == [
        {k: v for k, v in f.items() if k != 'confidence'} for f in b]
    assert [f['confidence'] for f in a] == pytest.approx([f['confidence'] for f in b], abs=1e-6)
    spec = importlib.util.spec_from_file_location('ml_showcase_fixture', root / 'examples/generate_showcase.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / 'showcase.pcap'
    module.write_pcap(source)
    report = analyze(source, ml_detector=detector, ml_work_budget=MLWorkBudget(max_fields_per_batch=2))
    summary = report['summary']
    assert (summary['packets_captured'], summary['flows_processed'], summary['http_messages'],
            summary['rules_findings']) == (95, 12, 24, 19)
    assert summary['ml_inference_complete'] is True
    assert summary['ml_fields_evaluated'] == summary['ml_fields_eligible']
    assert summary['ml_inference_batches'] > 1
    assert report['metadata']['ml_model_version'] == 'bilstm-v2-d1f9e9fb9a2b'
