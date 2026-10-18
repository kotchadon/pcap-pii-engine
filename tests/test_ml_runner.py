"""Bounded chunked ML inference: budgets, coverage states, batching invariance, cancellation and failure handling.

Logic is exercised with deterministic test doubles; two tests run the real V2 ensemble (skipped when unavailable).
"""
import json
import time

import pytest

from packet_pii.engine import analyze, analyze_to_report
from packet_pii.hybrid import InferenceError
from packet_pii.ml import EntityLabel, EntitySpan, ScoreType
from packet_pii.ml_runner import ML_PROFILES, MLBatchRunner, MLWorkBudget
from test_vp_qa_support import build_pcap, conversation, ml_findings, ok_response, post_json, v2_detector, write_pcap


class Stub:
    """Flags any text beginning with ``NAME`` (whole text); records every call."""
    model_version = 'stub-1'

    def __init__(self, fail_on_call=None, delay=0.0):
        self.calls, self.fail_on_call, self.delay = [], fail_on_call, delay

    def predict_fields(self, fields):
        self.calls.append([(f.field_index, f.location, len(f.text)) for f in fields])
        if self.fail_on_call == len(self.calls):
            raise RuntimeError('boom: NAME-secret-text must not leak')
        if self.delay:
            time.sleep(self.delay)
        return [EntitySpan(f.field_index, EntityLabel.PERSON_NAME, 0, len(f.text), self.model_version, .9,
                           ScoreType.UNCALIBRATED_MODEL_SCORE) for f in fields if f.text.startswith('NAME')]


def capture(tmp_path, messages=6, fields=7, prefix='NAME'):
    """``messages`` request/response conversations; every request has ``fields`` eligible string fields."""
    convs = []
    for m in range(messages):
        body = {f'f{i}': (f'{prefix}-{m}-{i}' if i % 2 == 0 else f'plain {m} {i}') for i in range(fields)}
        convs.append(conversation(m, post_json(body), ok_response()))
    return build_pcap(tmp_path / 'c.pcap', convs)


def sig(report):
    return [(f['flow_id'], f['http_message_id'], f['detector'], f['location'], f.get('field_index'), f.get('span_start'), f.get('span_end'))
            for f in report['findings']]


# ------------------------------------------------------------------ budget validation
@pytest.mark.parametrize('kwargs', [
    dict(max_fields=0), dict(max_fields=-1), dict(max_fields=True), dict(max_fields=1.5), dict(max_fields='10'),
    dict(max_characters=0), dict(max_characters=10**12), dict(max_fields=10**9),
    dict(max_seconds=0), dict(max_seconds=-1), dict(max_seconds=10**6), dict(max_seconds='1'),
    dict(batch_fields=0), dict(batch_fields=10_001), dict(batch_characters=0),
    dict(max_field_chars=65_537), dict(max_field_chars=1000, batch_characters=999), dict(name=''), dict(name='x' * 41),
])
def test_invalid_budgets_are_rejected(kwargs):
    with pytest.raises(ValueError):
        MLWorkBudget(**kwargs)


def test_profiles_are_bounded_and_ordered():
    budgets = [MLWorkBudget.for_profile(p) for p in ML_PROFILES]
    assert [b.name for b in budgets] == ['standard', 'extended', 'complete']
    assert budgets[0].max_fields == 10_000 and budgets[0].max_characters == 2_000_000          # the safe default is unchanged
    assert all(a.max_fields < b.max_fields and a.max_seconds < b.max_seconds for a, b in zip(budgets, budgets[1:]))
    assert all(b.max_fields <= MLWorkBudget.CEILING_FIELDS and b.max_seconds <= MLWorkBudget.CEILING_SECONDS for b in budgets)
    with pytest.raises(ValueError):
        MLWorkBudget.for_profile('unlimited')


def test_engine_rejects_a_bad_budget_argument(tmp_path):
    with pytest.raises(ValueError):
        analyze(capture(tmp_path), ml_detector=Stub(), ml_budget='unlimited')
    with pytest.raises(TypeError):
        analyze(capture(tmp_path), ml_detector=Stub(), ml_budget=10_000)


# ------------------------------------------------------------------ coverage states
def test_rules_only_reports_not_requested(tmp_path):
    s = analyze(capture(tmp_path))['summary']
    assert (s['ml_coverage_status'], s['ml_coverage_ratio'], s['ml_batches'], s['ml_invoked']) == ('not_requested', None, 0, False)
    assert analyze(capture(tmp_path))['metadata']['ml_work_limits'] is None


def test_zero_eligible_fields_is_its_own_state_and_never_calls_the_model(tmp_path):
    path = build_pcap(tmp_path / 'h.pcap', [conversation(0, post_json({'email': 'a@example.test', 'password': 'pw-1'}), ok_response())])
    stub = Stub()
    s = analyze(path, ml_detector=stub)['summary']
    assert s['ml_fields_eligible'] == 1                       # only the response's {"ok": true} body value
    only_excluded = build_pcap(tmp_path / 'e.pcap', [conversation(0, b'GET /x HTTP/1.1\r\nHost: h\r\n\r\n', b'')])
    stub2 = Stub()
    s2 = analyze(only_excluded, ml_detector=stub2)['summary']
    assert (s2['ml_coverage_status'], s2['ml_coverage_ratio'], s2['ml_invoked'], s2['ml_batches']) == ('no_eligible_fields', None, False, 0)
    assert stub2.calls == [] and s2['analysis_incomplete'] is False and s2['ml_incomplete'] is False


def test_exactly_at_budget_is_complete_and_one_more_is_partial(tmp_path):
    path = capture(tmp_path, messages=3, fields=4)
    total = analyze(path, ml_detector=Stub())['summary']['ml_fields_eligible']
    at = analyze(path, ml_detector=Stub(), ml_budget=MLWorkBudget(max_fields=total))['summary']
    assert (at['ml_coverage_status'], at['ml_fields_skipped'], at['ml_coverage_ratio'], at['analysis_incomplete']) == ('complete', 0, 1.0, False)
    below = analyze(path, ml_detector=Stub(), ml_budget=MLWorkBudget(max_fields=total - 1))['summary']
    assert below['ml_coverage_status'] == 'partial' and below['ml_fields_skipped'] == 1
    assert below['ml_fields_skipped_by_reason'] == {'field_budget': 1}
    assert below['analysis_incomplete'] is True and below['ml_incomplete'] is True
    assert below['ml_fields_evaluated'] + below['ml_fields_skipped'] == below['ml_fields_eligible'] == total
    assert below['ml_coverage_ratio'] == round((total - 1) / total, 6)


def test_per_field_oversize_and_long_location_are_skipped_with_reasons_not_truncated():
    runner = MLBatchRunner(Stub(), MLWorkBudget(max_field_chars=100, batch_characters=100))
    runner.add(0, [('json_body.big', 'NAME' + 'x' * 200), ('k' * 2000, 'NAME-a'), ('json_body.ok', 'NAME-b')])
    runner.flush()
    assert runner.skip_reasons == {'field_too_large': 1, 'location_too_long': 1}
    assert (runner.eligible, runner.evaluated, runner.skipped, runner.status) == (3, 1, 2, 'partial')
    (_, findings), = runner.take_ready()
    assert [f['location'] for f in findings] == ['json_body.ok'] and (findings[0]['span_start'], findings[0]['span_end']) == (0, 6)


def test_character_budget_skips_what_does_not_fit_but_keeps_later_small_fields():
    runner = MLBatchRunner(Stub(), MLWorkBudget(max_characters=30))
    runner.add(0, [('a', 'NAME-' + 'a' * 10), ('b', 'NAME-' + 'b' * 40), ('c', 'NAME-' + 'c' * 5)])   # 15, 45 (does not fit), 10
    runner.flush()
    assert runner.skip_reasons == {'character_budget': 1} and runner.evaluated == 2 and runner.characters == 25
    assert [f['location'] for f in runner.take_ready()[0][1]] == ['a', 'c']


def test_time_budget_stops_admission_after_it_is_spent():
    stub = Stub(delay=0.02)
    runner = MLBatchRunner(stub, MLWorkBudget(max_seconds=0.005, batch_fields=2))
    runner.add(0, [('a', 'NAME-1'), ('b', 'NAME-2')])          # fills a batch and runs it
    runner.add(1, [('c', 'NAME-3')])
    runner.flush()
    assert runner.skip_reasons == {'time_budget': 1} and runner.status == 'partial' and len(stub.calls) == 1


# ------------------------------------------------------------------ batching
def test_many_messages_are_batched_across_message_boundaries(tmp_path):
    path = capture(tmp_path, messages=6, fields=7)            # 6 requests x 7 fields + 6 responses x 1 field
    stub = Stub()
    s = analyze(path, ml_detector=stub, ml_budget=MLWorkBudget(batch_fields=10))['summary']
    assert s['ml_fields_evaluated'] == 48 and s['ml_coverage_status'] == 'complete'
    assert s['ml_batches'] == len(stub.calls) == 5 and max(len(c) for c in stub.calls) <= 10
    assert len(stub.calls) < s['http_messages']                 # fewer detector calls than messages: batching works across messages


def test_batch_character_bound_is_respected():
    stub = Stub()
    runner = MLBatchRunner(stub, MLWorkBudget(max_field_chars=50, batch_characters=100, batch_fields=1000))
    runner.add(0, [(f'f{i}', 'NAME' + 'x' * 36) for i in range(9)])      # 40 chars each
    runner.flush()
    assert all(sum(n for _, _, n in call) <= 100 for call in stub.calls) and len(stub.calls) == 5


@pytest.mark.parametrize('batch_fields', [1, 3, 7, 256])
def test_results_ordering_and_provenance_do_not_depend_on_batch_size(tmp_path, batch_fields):
    path = capture(tmp_path, messages=5, fields=6)
    reference = analyze(path, ml_detector=Stub(), ml_budget=MLWorkBudget(batch_fields=256))
    r = analyze(path, ml_detector=Stub(), ml_budget=MLWorkBudget(batch_fields=batch_fields))
    assert r['findings'] == reference['findings'] and r['flows'] == reference['flows']
    for key, value in reference['summary'].items():
        if key not in ('processing_time_seconds', 'ml_processing_time_seconds', 'ml_batches'):
            assert r['summary'][key] == value, key


def test_findings_are_traceable_to_the_right_flow_message_and_field(tmp_path):
    path = capture(tmp_path, messages=5, fields=6)
    r = analyze(path, ml_detector=Stub(), ml_budget=MLWorkBudget(batch_fields=4), include_values=True)
    by_flow = {}
    for f in ml_findings(r):
        by_flow.setdefault(f['flow_id'], []).append(f)
    assert len(by_flow) == 5
    for flow_id, found in by_flow.items():
        messages = {f['http_message_id'] for f in found}
        assert len(messages) == 1 and next(iter(messages)).startswith(flow_id)
        assert {f['http_message_type'] for f in found} == {'request'}
        assert [f['location'] for f in found] == ['json_body.f0', 'json_body.f2', 'json_body.f4']
        assert len({f['value'].split('-')[1] for f in found}) == 1               # all values come from the same conversation
        assert all(f['field_index'] == i for f, i in zip(found, sorted(f['field_index'] for f in found)))


def test_repeated_field_names_keep_distinct_message_local_field_indices():
    runner = MLBatchRunner(Stub(), MLWorkBudget(batch_fields=2))
    for key in range(3):
        runner.add(key, [('json_body.name', f'NAME-{key}-a'), ('json_body.name', f'NAME-{key}-b')])
    runner.flush()
    ready = runner.take_ready()
    assert [k for k, _ in ready] == [0, 1, 2]
    assert all([f['field_index'] for f in findings] == [0, 1] for _, findings in ready)


def test_unicode_offsets_are_code_points_across_batches():
    class Emoji(Stub):
        def predict_fields(self, fields):
            return [EntitySpan(f.field_index, EntityLabel.PERSON_NAME, f.text.index('Alex'), f.text.index('Alex') + 4,
                               self.model_version, .8, ScoreType.UNCALIBRATED_MODEL_SCORE) for f in fields]
    runner = MLBatchRunner(Emoji(), MLWorkBudget(batch_fields=1), include_values=True)
    runner.add(0, [('a', '🙂🙂 Alex'), ('b', 'é Alex Ünal')])
    runner.flush()
    (_, findings), = runner.take_ready()
    assert [(f['span_start'], f['span_end'], f['value']) for f in findings] == [(3, 7, 'Alex'), (2, 6, 'Alex')]


def test_messages_without_model_fields_behind_a_pending_one_do_not_accumulate():
    stub = Stub()
    runner = MLBatchRunner(stub, MLWorkBudget(batch_fields=256), max_pending_messages=100)
    runner.add(0, [('json_body.a', 'NAME-x')])
    for key in range(1, 100):
        runner.add(key, [('header.host', 'h')])                  # excluded by policy: nothing for the model
    assert len(stub.calls) == 1                                  # the bound forced the queued field through the model
    assert [k for k, _ in runner.take_ready()] == list(range(100))


# ------------------------------------------------------------------ cancellation and failure
def test_cancellation_stops_before_further_batches_and_publishes_nothing(tmp_path):
    path = capture(tmp_path, messages=6, fields=7)
    stub = Stub()

    class Cancelled(Exception):
        pass

    seen = []

    def progress(event):
        seen.append(event['stage'])
        if event['stage'] == 'ml_inference' and seen.count('ml_inference') >= 3:
            raise Cancelled()

    target = tmp_path / 'out.json'
    with pytest.raises(Cancelled):
        analyze_to_report(path, target, ml_detector=stub, ml_budget=MLWorkBudget(batch_fields=4), progress=progress)
    assert len(stub.calls) < 12 and not target.exists()
    assert not [p for p in tmp_path.iterdir() if p.name.startswith('.pcap-pii')]


def test_mid_scan_inference_failure_is_never_published_as_a_result(tmp_path):
    path = capture(tmp_path, messages=6, fields=7)
    target = tmp_path / 'out.json'
    with pytest.raises(InferenceError) as info:
        analyze_to_report(path, target, ml_detector=Stub(fail_on_call=3), ml_budget=MLWorkBudget(batch_fields=8))
    assert info.value.ml_inference_failed is True
    assert 'NAME-secret' not in str(info.value)                       # the sanitized error never carries detector/field text
    assert not target.exists() and not [p for p in tmp_path.iterdir() if p.name.startswith('.pcap-pii')]
    with pytest.raises(InferenceError):
        analyze(path, ml_detector=Stub(fail_on_call=1))


def test_detector_contract_violations_fail_the_scan():
    class WrongVersion(Stub):
        def predict_fields(self, fields):
            return [EntitySpan(fields[0].field_index, EntityLabel.PERSON_NAME, 0, 1, 'other-model', .9, ScoreType.UNCALIBRATED_MODEL_SCORE)]
    runner = MLBatchRunner(WrongVersion(), MLWorkBudget())
    runner.add(0, [('a', 'NAME-1')])
    with pytest.raises(Exception) as info:
        runner.flush()
    assert info.value.ml_inference_failed is True


# ------------------------------------------------------------------ streamed report
def test_full_streamed_report_is_complete_and_equal_to_the_in_memory_report(tmp_path):
    path = capture(tmp_path, messages=8, fields=9)
    expected = analyze(path, ml_detector=Stub(), ml_budget=MLWorkBudget(batch_fields=5))
    target = tmp_path / 'full.json'
    rows = []
    receipt = analyze_to_report(path, target, ml_detector=Stub(), ml_budget=MLWorkBudget(batch_fields=5),
                                row_observer=lambda kind, row: rows.append(kind))
    published = json.loads(target.read_text())
    assert published['findings'] == expected['findings'] and published['flows'] == expected['flows']
    s = published['summary']
    assert (s['ml_coverage_status'], s['ml_fields_skipped'], s['analysis_incomplete']) == ('complete', 0, False)
    assert s['ml_fields_evaluated'] == s['ml_fields_eligible'] and receipt['summary'] == s
    assert rows.count('findings') == len(published['findings']) and rows.count('flows') == len(published['flows'])
    assert published['metadata']['ml_work_limits'] == MLWorkBudget(batch_fields=5).public()


def test_partial_streamed_report_is_labelled_incomplete(tmp_path):
    path = capture(tmp_path, messages=8, fields=9)
    target = tmp_path / 'part.json'
    analyze_to_report(path, target, ml_detector=Stub(), ml_budget=MLWorkBudget(max_fields=20, batch_fields=6))
    s = json.loads(target.read_text())['summary']
    assert s['ml_coverage_status'] == 'partial' and s['ml_fields_evaluated'] == 20 and s['analysis_incomplete'] is True
    assert s['ml_fields_skipped'] == s['ml_fields_eligible'] - 20


def test_rules_findings_are_identical_with_and_without_the_model(tmp_path):
    path = capture(tmp_path, messages=4, fields=5)
    rules = analyze(path)
    hybrid = analyze(path, ml_detector=Stub(), ml_budget=MLWorkBudget(batch_fields=3))
    assert [f for f in hybrid['findings'] if f['detector'] == 'rule'] == rules['findings']


# ------------------------------------------------------------------ real V2
def _many_field_capture(tmp_path, messages=4, fields=1200):
    names = ['Priyanka Venkataraman', 'Henrik Larsson', 'Ingrid Solberg', 'Fatima Khan', 'Maria Gonzalez']
    convs = []
    for c in range(messages):
        obj = {}
        for i in range(fields):
            obj[f'item_{i}'] = {0: names[(i + c) % 5], 1: f'user_{c}_{i}_x', 2: f'Order shipped to warehouse number {i}',
                                3: f'2025-01-{i % 28 + 1:02d}', 4: 'pending'}[i % 5]
        convs.append(conversation(c, post_json(obj), ok_response()))
    return build_pcap(tmp_path / 'many.pcap', convs)


def test_real_v2_is_batch_invariant_and_complete_beyond_the_standard_budget(tmp_path):
    det = v2_detector()
    path = _many_field_capture(tmp_path)
    small = MLWorkBudget(max_fields=1000, batch_fields=64)
    capped = analyze(path, ml_detector=det, ml_budget=small)['summary']
    assert capped['ml_coverage_status'] == 'partial' and capped['ml_fields_evaluated'] == 1000 and capped['analysis_incomplete'] is True
    a = analyze(path, ml_detector=det, ml_budget=MLWorkBudget(batch_fields=16))
    b = analyze(path, ml_detector=det, ml_budget=MLWorkBudget(batch_fields=512, batch_characters=1_000_000))
    assert a['summary']['ml_coverage_status'] == b['summary']['ml_coverage_status'] == 'complete'
    assert a['summary']['ml_fields_evaluated'] == b['summary']['ml_fields_evaluated'] > 4000
    assert a['summary']['ml_batches'] > b['summary']['ml_batches']
    fa, fb = ml_findings(a), ml_findings(b)
    assert [(f['http_message_id'], f['location'], f['pii_type'], f['span_start'], f['span_end']) for f in fa] == \
           [(f['http_message_id'], f['location'], f['pii_type'], f['span_start'], f['span_end']) for f in fb]
    assert max(abs(x['confidence'] - y['confidence']) for x, y in zip(fa, fb)) < 1e-4
    assert len(fa) > 0 and len(fa) == len(fb)


# ------------------------------------------------------------------ dashboard jobs
def _job(s, request_id, ml_coverage=None, mode='hybrid'):
    from test_dashboard_jobs import request
    headers = {'X-Dashboard-Token': s.token, 'X-Request-ID': request_id, 'X-Detection-Mode': mode, 'X-Analysis-Profile': 'standard'}
    if ml_coverage is not None:
        headers['X-ML-Coverage'] = ml_coverage
    return request(s, 'POST', '/api/jobs/showcase', headers=headers)


def test_jobs_accept_only_known_ml_coverage_profiles_and_report_the_selection():
    from test_dashboard_jobs import finish, server
    with server(Stub()) as s:
        assert _job(s, 'ml-profile-bad-0001', 'unlimited')[0] == 400
        code, body, _ = _job(s, 'ml-profile-ext-0001', 'extended')
        assert code == 202
        done = finish(s, json.loads(body)['job_id'])
        assert done['status'] == 'completed' and done['ml_profile'] == 'extended'
        summary = done['report']['summary']
        assert summary['ml_coverage_status'] in ('complete', 'no_eligible_fields') and 'ml_coverage_ratio' in summary
        assert done['report']['metadata']['ml_work_limits']['profile'] == 'extended'
        code, body, _ = _job(s, 'ml-profile-rules-0001', 'complete', mode='rules')
        rules = finish(s, json.loads(body)['job_id'])
        assert rules['ml_profile'] is None and rules['report']['summary']['ml_coverage_status'] == 'not_requested'


def test_every_field_gets_exactly_one_disposition():
    seen = []
    runner = MLBatchRunner(Stub(), MLWorkBudget(max_fields=2, max_field_chars=50, batch_characters=50),
                           disposition=lambda ticket, index, status: seen.append((ticket, index, status)))
    runner.add('m', [('header.host', 'h'), ('json_body.empty', ''), ('json_body.a', 'NAME-1'), ('json_body.big', 'N' * 80),
                     ('json_body.b', 'NAME-2'), ('json_body.c', 'NAME-3'), ('json_body.garbage', '��� x')])
    assert [s for _, _, s in seen] == ['excluded_by_policy', 'empty', 'evaluated', 'skipped:field_too_large', 'evaluated',
                                      'skipped:field_budget', 'excluded_by_policy']
    assert [i for _, i, _ in seen] == list(range(7)) and {t for t, _, _ in seen} == {'m'}
