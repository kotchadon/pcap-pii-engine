"""Automated context-matched probe assessment: independence, privacy, metrics, bounds, lifecycle."""
import gzip
import json
import re
import sys
import threading
import time
from pathlib import Path

import pytest

from packet_pii import quality
from packet_pii.engine import analyze
from packet_pii.ml import EntityLabel, EntitySpan, ScoreType
from packet_pii.quality import (AssessmentBudget, AssessmentCancelled, ContextSampler, assess_summary, classify_location, generate_suite,
                                select_strata)
from test_vp_qa_support import build_pcap, conversation, ok_response, post_json, v2_detector

ROOT = Path(__file__).resolve().parents[1]


class Detector:
    """Test double with scripted behaviour; ``mode`` decides what it predicts for a (location, text) probe."""
    model_version = 'probe-double-1'

    def __init__(self, mode='gold', delay=0.0):
        self.mode, self.delay, self.calls = mode, delay, 0

    def predict_fields(self, fields):
        self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        out = []
        for f in fields:
            gold = GOLD.get((f.location, f.text))
            if self.mode == 'gold' and gold:
                out += [EntitySpan(f.field_index, EntityLabel(l), a, b, self.model_version, .9, ScoreType.UNCALIBRATED_MODEL_SCORE) for a, b, l in gold]
            elif self.mode == 'person_only' and gold:
                out += [EntitySpan(f.field_index, EntityLabel(l), a, b, self.model_version, .9, ScoreType.UNCALIBRATED_MODEL_SCORE)
                        for a, b, l in gold if l == 'PERSON_NAME']
            elif self.mode == 'shifted' and gold:
                out += [EntitySpan(f.field_index, EntityLabel(l), a + 1, b, self.model_version, .9, ScoreType.UNCALIBRATED_MODEL_SCORE) for a, b, l in gold]
            elif self.mode == 'flag_negatives' and not gold:
                out.append(EntitySpan(f.field_index, EntityLabel.PERSON_NAME, 0, 1, self.model_version, .9, ScoreType.UNCALIBRATED_MODEL_SCORE))
        return out


GOLD: dict = {}


def fields_of(i):
    return (i.location, i.text)


def summary_for(*messages, method='POST', ctype='application/json'):
    sampler = ContextSampler()
    for fields in messages:
        sampler.observe_message({'message_type': 'request', 'fields': fields,
                                 'http': {'method': method, 'content_type': ctype, 'content_encoding': None, 'transfer_encoding': None}})
    return sampler.summary()


BASE = summary_for([('json_body.author', 'Aa Bb'), ('json_body.profile.bio', 'x y z w q r s'), ('form.username', 'aaaa_bb11')],
                   [('json_body.profile.name', 'Cc Dd')])


@pytest.fixture
def small():
    budget = AssessmentBudget(max_strata=2, stability_probes=0)
    suite = generate_suite(BASE, budget)
    GOLD.clear()
    GOLD.update({fields_of(i): list(i.spans) for i in suite.items if i.spans})
    return suite, budget


# ------------------------------------------------------------------ generator independence
def test_suite_is_deterministic_and_seed_sensitive():
    budget = AssessmentBudget()
    a, b, c = generate_suite(BASE, budget, 7), generate_suite(BASE, budget, 7), generate_suite(BASE, budget, 8)
    assert a.items == b.items and a.hash == b.hash and a.meta == b.meta
    assert a.hash != c.hash
    assert (a.meta['generator_version'], a.meta['template_version'], a.meta['seed']) == (quality.GENERATOR_VERSION, quality.TEMPLATE_VERSION, 7)


def test_gold_labels_do_not_depend_on_any_detector(small):
    suite, budget = small
    results = {}
    for mode in ('gold', 'person_only', 'shifted', 'flag_negatives'):
        result = assess_summary(Detector(mode), BASE, budget)
        results[mode] = result
        assert result['suite']['probe_set_hash'] == suite.hash                # same frozen suite whatever the detector predicts
    gold_support = {m: r['per_label'] for m, r in results.items()}
    assert len({json.dumps({l: v['support'] for l, v in g.items()}) for g in gold_support.values()}) == 1
    assert generate_suite(BASE, budget).items == suite.items


def test_generator_never_receives_a_detector_or_predictions():
    import inspect
    assert 'detector' not in inspect.signature(generate_suite).parameters
    source = inspect.getsource(quality.generate_suite) + inspect.getsource(quality._cases) + inspect.getsource(quality.select_strata)
    assert not re.search(r'\b(predict\w*|detector|confidence|score|detect_fields)\b', source)


def test_spans_are_constructed_in_bounds_and_hold_only_pool_values(small):
    suite, _ = small
    assert suite.items and all(0 <= a < b <= len(i.text) for i in suite.items for a, b, _ in i.spans)
    names = set(quality.FIRST) | set(quality.UNICODE_NAMES) | {f'{f} {l}' for f in quality.FIRST for l in quality.LAST + quality.HYPHEN_LAST}
    for i in suite.items:
        for a, b, label in i.spans:
            value = i.text[a:b]
            if label == 'PERSON_NAME':
                assert value in names, value
            else:
                assert re.fullmatch(r'[a-z]+(_[a-z]+\d\d|\.[a-z]+-\d\d)', value), value


def test_pools_do_not_overlap_v2_training_or_challenge_gold_strings():
    paths = [ROOT / f'src/packet_pii/ml/datasets/v2/{n}.jsonl.gz' for n in ('train', 'val', 'calib')] + [ROOT / 'src/packet_pii/ml/datasets/challenge_v1.jsonl.gz']
    if not all(p.is_file() for p in paths):
        pytest.skip('datasets not present')
    known = set()
    for path in paths:
        with gzip.open(path, 'rt', encoding='utf-8') as handle:
            for line in handle:
                row = json.loads(line)
                known |= {row['text'][a:b].casefold() for a, b, _ in row['spans']}
    candidates = set(quality.FIRST) | set(quality.UNICODE_NAMES) | {f'{f} {l}' for f in quality.FIRST for l in quality.LAST + quality.HYPHEN_LAST}
    candidates |= {f'{a}_{b}{n}' for a in quality.WORDS_A for b in quality.WORDS_B for n in range(10, 100)}
    candidates |= {f'{a}.{b}-{n}' for a in quality.WORDS_A for b in quality.WORDS_B for n in range(10, 100)}
    assert sorted(c for c in candidates if c.casefold() in known) == []


def capture_with(tmp_path, name, values):
    body = {'author': values[0], 'profile': {'name': values[1], 'bio': values[2]}, 'username': values[3], 'email': values[4]}
    path = build_pcap(tmp_path / f'{name}.pcap', [conversation(0, post_json(body), ok_response())])
    sampler = ContextSampler()
    analyze(path, field_observer=sampler.observe_message)
    return sampler.summary()


def test_equivalent_structure_with_different_values_gives_identical_probes(tmp_path):
    a = capture_with(tmp_path, 'a', ['Jane Roe', 'Mary Poe', 'hello big wide world again', 'jane_roe_77', 'a@example.test'])
    b = capture_with(tmp_path, 'b', ['Omar Wix', 'Lena Cox', 'other words go here now', 'omar_wix_41', 'z@example.test'])
    assert a == b and a['summary_hash'] == b['summary_hash']
    assert generate_suite(a, AssessmentBudget()).items == generate_suite(b, AssessmentBudget()).items


def test_no_capture_value_or_field_name_reaches_summary_or_probes(tmp_path):
    canary = ['CANARYNAME Zebra', 'zebra_canary_99', '10.77.88.99', 'sk_live_CANARYTOKEN']
    body = {'canary_zebra_secret_key': canary[0], 'nested': {'canary_zebra_handle': canary[1], 'ip': canary[2]}, 'token': canary[3],
            'canary_zebra_note': 'CANARYNAME met zebra_canary_99 at 10.77.88.99'}
    path = build_pcap(tmp_path / 'c.pcap', [conversation(0, post_json(body, path='/x?canary_zebra_q=CANARYNAME'), ok_response())])
    sampler = ContextSampler()
    analyze(path, field_observer=sampler.observe_message)
    summary = sampler.summary()
    suite = generate_suite(summary, AssessmentBudget())
    blob = json.dumps(summary) + json.dumps([[i.location, i.text, i.case_id] for i in suite.items]) + json.dumps(suite.meta)
    assert 'canary' not in blob.lower() and 'zebra' not in blob.lower() and '10.77' not in blob and 'sk_live' not in blob
    allowed = {'json_body', 'query_parameter', 'form', 'body', 'text', quality.OTHER_LEAF, *quality.PREFIX_CHAIN}
    allowed |= {w for _, words in quality.NAME_CLASSES for w in words}
    for i in suite.items:
        assert set(re.split(r'[.]', i.location)) <= allowed, i.location


def test_location_classification_uses_only_allowlisted_words():
    assert classify_location('json_body.user.profile.displayName') == ('json', 'person_like', 'name', 3)
    assert classify_location('json_body.a.b[3].authorName') == ('json', 'person_like', 'name', 3)        # last allowlisted token wins
    assert classify_location('json_body.a.b[3].author') == ('json', 'actor_like', 'author', 3)
    assert classify_location('query_parameter.zzTop') == ('query', 'other', 'value', 1)
    assert classify_location('form.user_name') == ('form', 'username_like', 'user', 1)
    assert classify_location('body.text') == ('text', 'free_text', 'text', 1)


def test_sampling_is_a_defined_stratified_rule_not_prediction_based():
    rows = [{'category': c, 'name_class': n, 'depth': 1, 'direction': 'request', 'method': 'POST', 'encoding': 'json', 'count': k}
            for c, n, k in (('json', 'other', 900), ('json', 'person_like', 50), ('query', 'username_like', 5), ('form', 'username_like', 3))]
    summary = {'schema_version': quality.SUMMARY_SCHEMA, 'strata': rows}
    chosen = select_strata(summary, 3)
    assert [(r['category'], r['name_class']) for r in chosen] == [('form', 'username_like'), ('json', 'other'), ('query', 'username_like')]
    assert select_strata(summary, 3) == chosen


# ------------------------------------------------------------------ metrics
def test_exact_gold_detector_scores_perfectly_and_person_only_is_hand_computed(small):
    suite, budget = small
    perfect = assess_summary(Detector('gold'), BASE, budget)
    assert perfect['status'] == 'complete' and perfect['headline']['value'] == 1.0 and perfect['headline']['name'] == 'Context-matched synthetic probe F1'
    assert perfect['micro']['fp'] == 0 and perfect['micro']['fn'] == 0 and perfect['negatives']['with_false_positive'] == 0
    people = sum(1 for i in suite.items for s in i.spans if s[2] == 'PERSON_NAME')
    users = sum(1 for i in suite.items for s in i.spans if s[2] == 'USERNAME')
    partial = assess_summary(Detector('person_only'), BASE, budget)
    assert (partial['micro']['tp'], partial['micro']['fp'], partial['micro']['fn']) == (people, 0, users)
    assert partial['per_label']['USERNAME']['precision'] is None and partial['per_label']['USERNAME']['recall'] == 0.0
    assert partial['per_label']['USERNAME']['f1'] is None


def test_near_misses_are_shown_separately_and_get_no_credit(small):
    suite, budget = small
    result = assess_summary(Detector('shifted'), BASE, budget)
    positives = sum(len(i.spans) for i in suite.items)
    assert result['micro']['tp'] == 0 and result['micro']['fn'] == positives and result['micro']['fp'] == positives
    assert result['boundary']['near_miss_false_negatives'] == positives and result['boundary']['near_miss_false_positives'] == positives
    assert result['errors']['false_positive'] == {'boundary_mismatch': positives}
    assert result['headline']['value'] == 0.0


def test_negative_probes_count_as_false_positives(small):
    suite, budget = small
    result = assess_summary(Detector('flag_negatives'), BASE, budget)
    negatives = sum(1 for i in suite.items if not i.spans)
    assert result['negatives']['evaluated'] == negatives and result['negatives']['with_false_positive'] == negatives
    assert result['micro']['fp'] == negatives and result['micro']['tp'] == 0 and result['negatives']['false_positive_rate'] == 1.0
    assert result['micro']['precision'] == 0.0 and result['micro']['recall'] == 0.0


def test_a_silent_model_has_undefined_precision_and_f1_not_zero_or_one(small):
    result = assess_summary(Detector('none'), BASE, small[1])
    assert result['micro']['precision'] is None and result['micro']['recall'] == 0.0 and result['micro']['f1'] is None
    assert result['headline']['value'] is None and result['micro']['undefined']


def test_partial_probe_runs_are_labelled_partial_and_report_unscored_counts(small):
    suite, _ = small
    slow = Detector('gold', delay=0.02)
    budget = AssessmentBudget(max_strata=2, stability_probes=0, max_seconds=0.001, batch_fields=8)
    result = assess_summary(slow, BASE, budget)
    assert result['status'] == 'partial' and result['probes']['unscored'] > 0 and result['probes']['skipped'] > 0
    assert result['probes']['evaluated'] + result['probes']['unscored'] == result['probes']['generated'] == len(suite.items)
    assert result['probes']['evaluated'] < len(suite.items)


def test_policy_excluded_probes_are_reported_not_scored():
    summary = {'schema_version': quality.SUMMARY_SCHEMA, 'summary_hash': 'x' * 64, 'fields_total': 10, 'fields_eligible': 10,
               'fields_excluded_by_policy': 0, 'strata': [{'category': 'json', 'name_class': 'other', 'depth': 1, 'direction': 'request',
                                                           'method': 'POST', 'encoding': 'json', 'count': 10, 'leaf': {'password': 10}}]}
    GOLD.clear()
    result = assess_summary(Detector('gold'), summary, AssessmentBudget(stability_probes=0))
    assert result['status'] == 'failed' and result['unscored_probes']['excluded_by_policy'] == result['suite']['probes']
    assert 'headline' not in result


def test_truncation_by_budget_makes_the_suite_partial():
    budget = AssessmentBudget(max_probes=10, stability_probes=0)
    suite = generate_suite(BASE, budget)
    assert suite.meta['probes'] == 10 and suite.meta['truncated_by_budget'] is True
    GOLD.clear()
    GOLD.update({fields_of(i): list(i.spans) for i in suite.items if i.spans})
    assert assess_summary(Detector('gold'), BASE, budget)['status'] == 'partial'
    assert generate_suite(BASE, AssessmentBudget(max_characters=100)).meta['characters'] <= 100


def test_stability_and_independent_detector_diagnostics_are_reported_not_scored_as_accuracy(small):
    suite, _ = small
    detector = Detector('gold')
    result = assess_summary(detector, BASE, AssessmentBudget(max_strata=2, stability_probes=10))
    assert result['workload']['batches'] == detector.calls
    assert result['workload']['stability_batches'] > 0
    assert result['workload']['model_seconds'] >= result['workload']['stability_model_seconds']
    assert set(result['stability']) == {'trailing_period', 'label_prefix', 'quoted'}
    assert all(v['probes'] > 0 for v in result['stability'].values())
    detector = result['independent_detector']
    assert detector['available'] and 'ground truth' in detector['note'] and sum(detector['counts'].values()) == len(suite.items)
    assert result['applicability']['status'] in ('ok', 'limited') and 'coverage_of_eligible_fields' in result['applicability']


def test_empty_summary_is_unavailable_with_no_metrics():
    result = assess_summary(Detector('gold'), summary_for([('header.host', 'x')]))
    assert result['status'] == 'unavailable' and 'headline' not in result and result['disclosure'] == quality.DISCLOSURE


# ------------------------------------------------------------------ resource safety
@pytest.mark.parametrize('kwargs', [dict(max_probes=0), dict(max_probes=True), dict(max_probes=10**6), dict(max_seconds=0), dict(max_seconds=500),
                                    dict(batch_fields=0), dict(max_strata=0), dict(stability_probes=-1), dict(stability_probes=10**4),
                                    dict(max_characters=10**9), dict(bootstrap_rounds=10**6), dict(max_output_bytes=-5)])
def test_invalid_assessment_budgets_are_rejected(kwargs):
    with pytest.raises(ValueError):
        AssessmentBudget(**kwargs)


def test_cancellation_between_detector_calls_raises_and_returns_no_metrics(small):
    def checkpoint(_):
        raise AssessmentCancelled()
    with pytest.raises(AssessmentCancelled):
        assess_summary(Detector('gold'), BASE, small[1], checkpoint=checkpoint)


def test_large_capture_summary_and_assessment_stay_bounded(tmp_path):
    convs = []
    for c in range(8):
        obj = {f'key_{i}': f'value {c} {i}' for i in range(3000)}
        obj.update({f'name_{i}': f'Aa Bb{i}' for i in range(3000)})
        convs.append(conversation(c, post_json(obj), ok_response()))
    path = build_pcap(tmp_path / 'stress.pcap', convs)
    sampler, detector = ContextSampler(), Detector('none')
    report = analyze(path, field_observer=sampler.observe_message)
    summary = sampler.summary()
    assert summary['fields_eligible'] > 40_000 and len(json.dumps(summary)) < 30_000          # summary does not grow with the capture
    budget = AssessmentBudget()
    result = assess_summary(detector, summary, budget)
    assert result['suite']['probes'] <= budget.max_probes and detector.calls <= 12
    again = analyze(path)
    assert {k: v for k, v in report['summary'].items() if 'time' not in k} == {k: v for k, v in again['summary'].items() if 'time' not in k}


def test_observer_does_not_change_scan_results(tmp_path):
    path = build_pcap(tmp_path / 'p.pcap', [conversation(0, post_json({'author': 'Aa Bb', 'x': 'y z'}), ok_response())])
    plain, observed = analyze(path), analyze(path, field_observer=ContextSampler().observe_message)
    strip = lambda r: {k: v for k, v in r['summary'].items() if 'time' not in k}
    assert strip(plain) == strip(observed) and plain['findings'] == observed['findings']


# ------------------------------------------------------------------ real V2 on the fictional reproduction case
def test_reproduction_suite_is_deterministic_and_matches_committed_metadata(tmp_path):
    sys.path.insert(0, str(ROOT / 'scripts' / 'probe'))
    import reproduce
    summary = reproduce.reproduction_summary()
    assert summary == json.loads((ROOT / 'examples/probe/reproduction_summary.json').read_text())
    suite = generate_suite(summary, AssessmentBudget(), quality.DEFAULT_SEED)
    committed = json.loads((ROOT / 'examples/probe/reproduction_suite_meta.json').read_text())
    assert {k: v for k, v in committed.items() if k != 'budget'} == suite.meta


def test_real_v2_reproduces_the_committed_probe_result():
    sys.path.insert(0, str(ROOT / 'scripts' / 'probe'))
    import reproduce
    committed = json.loads((ROOT / 'docs/ml/results/probe_reproduction_v2.json').read_text())
    result = assess_summary(v2_detector(), reproduce.reproduction_summary(), AssessmentBudget())
    assert result['status'] == committed['status'] == 'complete' and result['model_version'] == committed['model_version']
    assert result['suite']['probe_set_hash'] == committed['suite']['probe_set_hash']
    for key in ('tp', 'fp', 'fn'):
        assert abs(result['micro'][key] - committed['micro'][key]) <= 2, key           # tolerate borderline spans across platforms
    assert abs(result['headline']['value'] - committed['headline']['value']) < 0.03
    assert result['probes']['unscored'] == 0 and result['probes']['generated'] == 188
