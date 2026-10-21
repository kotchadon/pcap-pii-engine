"""Output-preserving V2 inference acceleration: length-aware batching and the scan-local prediction cache.

Real-model tests compare the accelerated path with the legacy path (``length_bucketing=False``, prediction cache off) on
fixed fictional inputs and skip, never fake, when PyTorch or the V2 artifact is unavailable. Cache logic is also covered
with deterministic test doubles.
"""
import json
import sys
from pathlib import Path

import pytest

from packet_pii.engine import analyze, analyze_to_report
from packet_pii.hybrid import InferenceError
from packet_pii.ml import EntityLabel, EntitySpan, ScoreType
from packet_pii import ml_runner
from packet_pii.ml_runner import MLBatchRunner, MLWorkBudget
from test_vp_qa_support import V2_DIR, build_pcap, conversation, ok_response, post_json

ROOT = Path(__file__).resolve().parents[1]
SCORE_TOLERANCE = 1e-5  # float32 batch-shape rounding; observed max is ~2e-7

# Fixed, fictional inputs covering the documented risk areas. Never derived from model output.
LONG = ' '.join(f'Contact {n} {s} about order {i}.' for i, (n, s) in
                enumerate([('Ana', 'Garcia'), ('Wei', 'Chen'), ('Priya', 'Patel'), ('Lucas', 'Silva')] * 30))
FIXED_INPUTS = [
    ('json_body.full_name', 'Alex Example'),
    ('json_body.user.name', 'Mary-Jane Watson-Parker'),           # hyphenated
    ('json_body.customer', "Siobhán O'Connor"),                  # Unicode + apostrophe
    ('json_body.name', 'Zoë Ångström'),
    ('json_body.name', '王小明'),
    ('json_body.username', 'jessica_smith88'),
    ('form.login', 'mr.john-doe'),
    ('query_parameter.q', 'Ana Garcia 27'),
    ('json_body.comment', 'Please call Priya Patel tomorrow, thanks!'),
    ('json_body.note', LONG),                                    # > max_seq tokens: several chunks
    ('json_body.items[0].name', 'Item 42 blue'),
    ('json_body.status', 'ok'),
    ('json_body.blob', 'A�B�� name'),             # malformed / replacement characters
    ('json_body.text', '   '),
    ('json_body.x', '\u0000\u0001 control'),
    ('json_body.emoji', 'Ana 👋 Garcia'),
    ('json_body.full_name', 'Alex Example'),                     # exact repeat
    ('json_body.other_name', 'Alex Example'),                    # same text, different location
]


@pytest.fixture(scope='module')
def predictors():
    pytest.importorskip('torch')
    if not (V2_DIR / 'ensemble.json').is_file():
        pytest.skip('V2 checkpoint not present')
    from packet_pii.ml.bilstm import load_predictor
    legacy, meta = load_predictor(str(V2_DIR), 64, length_bucketing=False)
    return legacy, meta, load_predictor


def _labels(result):
    return [[(s, e, label) for s, e, label, _ in spans] for spans in result]


def _included(result, threshold):
    return [[(s, e, label) for s, e, label, score in spans if score >= threshold] for spans in result]


# ------------------------------------------------------------------ predictor: batching equivalence
@pytest.mark.parametrize('batch_size,max_tokens', [(64, None), (128, None), (256, None), (512, None), (3, 192), (512, 400)])
def test_length_bucketed_predictions_match_the_legacy_path(predictors, batch_size, max_tokens):
    legacy, meta, load = predictors
    fast, _ = load(str(V2_DIR), batch_size, max_batch_tokens=max_tokens)
    old, new = legacy.predict_pairs(FIXED_INPUTS), fast.predict_pairs(FIXED_INPUTS)
    assert _labels(new) == _labels(old)                                  # labels, exact spans, field association
    assert _included(new, meta['min_score']) == _included(old, meta['min_score'])
    diffs = [abs(a[3] - b[3]) for x, y in zip(old, new) for a, b in zip(x, y)]
    assert diffs and max(diffs) <= SCORE_TOLERANCE
    assert len(fast.models) == 3 == len(legacy.models)                   # every ensemble member still averaged


def test_long_text_is_chunked_and_reassembled_in_order(predictors):
    legacy, _, load = predictors
    fast, _ = load(str(V2_DIR), 512)
    jobs_before = [(i, p) for i, p in enumerate(FIXED_INPUTS)]
    spans = fast.predict_pairs([('json_body.note', LONG)])[0]
    starts = [s for s, *_ in spans]
    assert len(spans) > 4 and starts == sorted(starts) and max(starts) > 1000   # spans from later chunks, original offsets
    assert all(LONG[s:e].strip() == LONG[s:e] for s, e, *_ in spans)
    assert jobs_before == list(enumerate(FIXED_INPUTS))                  # inputs are not mutated


def test_batches_are_a_bounded_permutation(predictors):
    _, _, load = predictors
    fast, _ = load(str(V2_DIR), 4, max_batch_tokens=200)
    jobs = [(i, list(range(n))) for i, n in enumerate([5, 1, 50, 192, 3, 3, 120, 7, 80, 2])]  # objects with len()
    batches = fast._batches(jobs)
    flat = [j for b in batches for j in b]
    assert sorted(flat) == list(range(len(jobs)))
    for b in batches:
        assert len(b) <= 4 and (len(b) == 1 or len(b) * max(len(jobs[j][1]) for j in b) <= 200)
    fast.length_bucketing = False
    assert [j for b in fast._batches(jobs) for j in b] == list(range(len(jobs)))


def test_invalid_batching_options_are_rejected(predictors):
    _, _, load = predictors
    with pytest.raises(ValueError):
        load(str(V2_DIR), 0)
    with pytest.raises(ValueError):
        load(str(V2_DIR), 64, max_batch_tokens=10)


def test_detector_attribution_and_threshold_unchanged(predictors):
    from packet_pii.ml.infer import BiLSTMDetector
    from packet_pii.ml import FieldInput
    fields = [FieldInput(i, loc, text) for i, (loc, text) in enumerate(FIXED_INPUTS)]
    old = BiLSTMDetector(str(V2_DIR), length_bucketing=False).predict_fields(fields)
    new = BiLSTMDetector(str(V2_DIR)).predict_fields(fields)
    assert [(s.field_index, s.label, s.start, s.end, s.model_version, s.score_type) for s in new] == \
           [(s.field_index, s.label, s.start, s.end, s.model_version, s.score_type) for s in old]
    assert BiLSTMDetector(str(V2_DIR)).min_score == 0.35


def test_near_threshold_spans_keep_their_inclusion_on_frozen_inputs(predictors):
    import gzip
    legacy, meta, load = predictors
    with gzip.open(ROOT / 'src/packet_pii/ml/datasets/v2/val.jsonl.gz', 'rt', encoding='utf-8') as fh:   # read-only
        pairs = [(row['location'], row['text']) for row in map(json.loads, fh)][:800]
    threshold, old = meta['min_score'], legacy.predict_pairs(pairs)
    near = [(i, span) for i, spans in enumerate(old) for span in spans if abs(span[3] - threshold) < 0.05]
    assert len(near) >= 3 and any(span[3] < threshold for _, span in near)  # the check is not vacuous
    for batch_size in (64, 512):
        new = load(str(V2_DIR), batch_size)[0].predict_pairs(pairs)
        assert _labels(new) == _labels(old) and _included(new, threshold) == _included(old, threshold)
        for i, span in near:
            twin = next(x for x in new[i] if x[:3] == span[:3])
            assert (twin[3] >= threshold) == (span[3] >= threshold) and abs(twin[3] - span[3]) <= SCORE_TOLERANCE


def test_real_model_cache_with_quality_flags_and_eviction(predictors):
    from packet_pii.ml.infer import BiLSTMDetector
    messages = [(f'm{i}', [('json_body.full_name', name), ('json_body.comment', f'Please call {name} tomorrow'),
                           ('json_body.username', 'jessica_smith88'), ('json_body.note', LONG if i == 3 else 'ok')], flags)
                for i, (name, flags) in enumerate([('Priya Patel', {}), ('Priya Patel', {'truncated': 'true'}),
                                                   ("Siobhán O'Connor", {'stream_gap': 'true'}), ('Priya Patel', {}),
                                                   ('Mary-Jane Watson-Parker', {}), ('Priya Patel', {'capture_incomplete': 'true'})])]
    fast, out = _run(BiLSTMDetector(str(V2_DIR)), messages, MLWorkBudget(batch_fields=4), prediction_cache_entries=2)
    slow, ref = _run(_NoCache(BiLSTMDetector(str(V2_DIR), length_bucketing=False)), messages, MLWorkBudget(batch_fields=4))
    strip = lambda rows: [(k, [{x: y for x, y in f.items() if x != 'confidence'} for f in fs]) for k, fs in rows]  # noqa: E731
    assert strip(out) == strip(ref) and out
    diffs = [abs(a['confidence'] - b['confidence']) for (_, x), (_, y) in zip(out, ref) for a, b in zip(x, y)]
    assert max(diffs) <= SCORE_TOLERANCE
    flags = {key: sorted({tuple(f.get('input_quality', ())) for f in fs}) for key, fs in out}
    assert flags['m1'] == [('truncated',)] and flags['m5'] == [('capture_incomplete',)] and flags['m0'] == [()]
    assert fast.cache_hits > 0 and fast.cache_evictions > 0 and fast.evaluated == slow.evaluated


# ------------------------------------------------------------------ runner: prediction cache (test doubles)
class CacheableStub:
    """Flags text beginning with ``NAME``; records every field it is asked to infer."""
    model_version = 'stub-cache-1'
    prediction_cache_safe = True

    def __init__(self, fail_on_call=None):
        self.seen, self.calls, self.fail_on_call = [], 0, fail_on_call

    def predict_fields(self, fields):
        self.calls += 1
        if self.calls == self.fail_on_call:
            raise RuntimeError('boom')
        self.seen.extend((f.location, f.text) for f in fields)
        return [EntitySpan(f.field_index, EntityLabel.PERSON_NAME, 0, 4, self.model_version, .9,
                           ScoreType.UNCALIBRATED_MODEL_SCORE) for f in fields if f.text.startswith('NAME')]


class PlainStub(CacheableStub):
    prediction_cache_safe = False


def _run(detector, messages, budget=None, **kw):
    runner = MLBatchRunner(detector, budget or MLWorkBudget(batch_fields=3), **kw)
    for key, fields, quality in messages:
        runner.add(key, fields, quality)
    runner.flush()
    return runner, runner.take_ready()


MESSAGES = [
    ('m0', [('json_body.name', 'NAME Ana'), ('json_body.note', 'plain'), ('json_body.name', 'NAME Ana')], {}),
    ('m1', [('json_body.name', 'NAME Ana'), ('json_body.other', 'NAME Wei')], {'truncated': 'true'}),
    ('m2', [('json_body.note', 'plain'), ('json_body.name', 'NAME Ana'), ('json_body.name', 'NAME Zed')], {'stream_gap': 'true'}),
]


def test_cache_reuses_only_predictions_and_keeps_every_occurrence():
    cached_stub, plain_stub = CacheableStub(), CacheableStub()
    cached, out = _run(cached_stub, MESSAGES)
    plain, ref = _run(plain_stub, MESSAGES, prediction_cache=False)
    assert out == ref                                    # identical findings, order, field indices, quality flags
    assert [f['field_index'] for _, fs in out for f in fs] == [0, 2, 0, 1, 1, 2]
    assert [f.get('input_quality') for _, fs in out for f in fs][2:] == [['truncated']] * 2 + [['stream_gap']] * 2
    assert len(cached_stub.seen) == len(set(cached_stub.seen)) == 4      # each unique (location, text) inferred once
    assert len(plain_stub.seen) == 8
    assert cached.evaluated == plain.evaluated == 8 == cached.model_evaluations + cached.cache_hits
    assert (cached.model_evaluations, cached.cache_hits) == (4, 4) and (plain.model_evaluations, plain.cache_hits) == (8, 0)
    assert cached.characters == plain.characters and cached.labels == plain.labels
    assert cached.prediction_cache_enabled and not plain.prediction_cache_enabled


def test_field_and_character_budgets_still_count_cache_hits():
    fields = [('json_body.name', 'NAME Ana')] * 6
    cached, _ = _run(CacheableStub(), [('m', fields, {})], MLWorkBudget(max_fields=4, batch_fields=2))
    plain, _ = _run(CacheableStub(), [('m', fields, {})], MLWorkBudget(max_fields=4, batch_fields=2), prediction_cache=False)
    for runner in (cached, plain):
        assert (runner.evaluated, runner.skipped, dict(runner.skip_reasons)) == (4, 2, {'field_budget': 2})
    assert (cached.model_evaluations, cached.cache_hits) == (1, 3)


def test_detectors_must_opt_in_to_caching():
    runner, _ = _run(PlainStub(), MESSAGES)
    assert not runner.prediction_cache_enabled and runner.cache_hits == 0 and runner.model_evaluations == 8


def test_cache_is_bounded_and_skips_long_fields(monkeypatch):
    monkeypatch.setattr(ml_runner, 'PREDICTION_CACHE_MAX_ENTRIES', 3)
    monkeypatch.setattr(ml_runner, 'PREDICTION_CACHE_MAX_FIELD_CHARS', 20)
    stub = CacheableStub()
    fields = [('json_body.v', f'NAME {i}') for i in range(10)] + [('json_body.v', 'NAME ' + 'x' * 30)] * 2
    runner, out = _run(stub, [('m', fields, {})], MLWorkBudget(batch_fields=1))
    assert len(runner._cache) == 3                                       # LRU bound
    assert list(runner._cache) == [ml_runner._cache_key('json_body.v', f'NAME {i}') for i in (7, 8, 9)]
    assert runner.cache_hits == 0 and len(out[0][1]) == 12 and len(stub.seen) == 12  # long repeat re-inferred, never cached


def test_cache_retains_no_field_text_or_locations():
    runner, _ = _run(CacheableStub(), MESSAGES)
    assert runner._cache and all(type(k) is bytes and len(k) == 16 for k in runner._cache)
    for spans in runner._cache.values():
        for start, end, label, score, score_type, version in spans:
            assert type(start) is int and type(end) is int and label in ('PERSON_NAME', 'USERNAME')
    assert ml_runner._cache_key('ab', 'c') != ml_runner._cache_key('a', 'bc')  # location/text boundary is unambiguous
    assert ml_runner._cache_key('loc', '\ud800 lone surrogate')               # never raises on odd input


def test_detector_failure_is_not_cached_and_still_fails_closed():
    stub = CacheableStub(fail_on_call=2)
    runner = MLBatchRunner(stub, MLWorkBudget(batch_fields=2))
    with pytest.raises(InferenceError):  # add() runs full batches itself
        runner.add('m', [('json_body.a', 'NAME 1'), ('json_body.b', 'NAME 2'), ('json_body.c', 'NAME 3'), ('json_body.d', 'NAME 4')])
        runner.flush()
    assert set(runner._cache) == {ml_runner._cache_key('json_body.a', 'NAME 1'), ml_runner._cache_key('json_body.b', 'NAME 2')}


# ------------------------------------------------------------------ engine: real V2 end to end
class _NoCache:
    """Proxy that hides ``prediction_cache_safe`` so the engine runs the legacy, uncached path."""

    def __init__(self, inner):
        self._inner = inner
        self.model_version = inner.model_version

    def predict_fields(self, fields):
        return self._inner.predict_fields(fields)


def _repeated_capture(tmp_path):
    convs = []
    for m in range(12):
        body = {'full_name': ['Alex Example', 'Mary-Jane Watson', "Siobhán O'Connor"][m % 3], 'comment': f'Order {m % 4} for Priya Patel',
                'username': 'jessica_smith88', 'note': LONG if m % 6 == 0 else 'ok', 'blob': 'A�B name'}
        convs.append(conversation(m, post_json(body), ok_response()))
    return build_pcap(tmp_path / 'repeated.pcap', convs)


def test_engine_report_is_identical_with_and_without_acceleration(tmp_path, predictors):
    from packet_pii.ml.infer import BiLSTMDetector
    path = _repeated_capture(tmp_path)
    fast = analyze(path, ml_detector=BiLSTMDetector(str(V2_DIR)), ml_budget=MLWorkBudget(batch_fields=8))
    slow = analyze(path, ml_detector=_NoCache(BiLSTMDetector(str(V2_DIR), length_bucketing=False)),
                   ml_budget=MLWorkBudget(batch_fields=8))

    def strip(report):
        return [{k: v for k, v in f.items() if k != 'confidence'} for f in report['findings']]
    assert strip(fast) == strip(slow)
    scores = [abs(a['confidence'] - b['confidence']) for a, b in zip(fast['findings'], slow['findings']) if a['detector'] == 'bilstm']
    assert scores and max(scores) <= SCORE_TOLERANCE
    a, b = fast['summary'], slow['summary']
    for key in ('ml_fields_eligible', 'ml_fields_evaluated', 'ml_fields_skipped', 'ml_characters_evaluated'
                if 'ml_characters_evaluated' in a else 'ml_fields_empty', 'ml_predictions_by_label', 'ml_coverage_status',
                'ml_coverage_ratio', 'ml_fields_excluded_by_policy', 'rules_findings', 'ml_findings'):
        assert a[key] == b[key], key
    assert a['ml_fields_evaluated'] == a['ml_fields_model_inferred'] + a['ml_prediction_cache_hits']
    assert a['ml_prediction_cache_enabled'] and a['ml_prediction_cache_hits'] > 0
    assert (b['ml_prediction_cache_enabled'], b['ml_prediction_cache_hits'], b['ml_fields_model_inferred']) == (False, 0, b['ml_fields_evaluated'])
    assert json.dumps(fast).count('Alex Example') == 0                   # masked by default; cache never serialised
    assert fast['metadata']['ml_model_version'] == slow['metadata']['ml_model_version']


def test_partial_coverage_and_cancellation_with_the_real_model(tmp_path, predictors):
    from packet_pii.ml.infer import BiLSTMDetector
    path = _repeated_capture(tmp_path)
    budget = MLWorkBudget(max_fields=20, batch_fields=4)
    fast = analyze(path, ml_detector=BiLSTMDetector(str(V2_DIR)), ml_budget=budget)
    slow = analyze(path, ml_detector=_NoCache(BiLSTMDetector(str(V2_DIR), length_bucketing=False)), ml_budget=budget)
    assert fast['summary']['ml_coverage_status'] == slow['summary']['ml_coverage_status'] == 'partial'
    assert fast['summary']['ml_fields_skipped_by_reason'] == slow['summary']['ml_fields_skipped_by_reason']
    assert [f['location'] for f in fast['findings']] == [f['location'] for f in slow['findings']]

    class Cancelled(Exception):
        pass

    def progress(event):
        if event['stage'] == 'ml_inference':
            raise Cancelled()
    target = tmp_path / 'out.json'
    with pytest.raises(Cancelled):
        analyze_to_report(path, target, ml_detector=BiLSTMDetector(str(V2_DIR)), ml_budget=MLWorkBudget(batch_fields=2),
                          progress=progress)
    assert not target.exists()


def test_ground_truth_evaluation_is_identical(tmp_path, predictors):
    from packet_pii.groundtruth import evaluate_capture, load_manifest
    from packet_pii.ml.infer import BiLSTMDetector
    sys.path.insert(0, str(ROOT / 'examples'))
    import generate_groundtruth_fixture
    pcap, manifest_path = generate_groundtruth_fixture.generate(tmp_path)
    manifest = load_manifest(manifest_path)
    assert manifest_path.read_bytes() == (ROOT / 'examples/groundtruth/controlled_fixture_v1.manifest.json').read_bytes()
    fast = evaluate_capture(pcap, manifest, detector=BiLSTMDetector(str(V2_DIR)))
    slow = evaluate_capture(pcap, manifest, detector=_NoCache(BiLSTMDetector(str(V2_DIR), length_bucketing=False)))
    assert fast['status'] == slow['status'] == 'complete'
    for name in ('rules_only', 'model_only', 'rules_plus_model'):
        for key in ('tp', 'fp', 'fn'):
            assert fast['systems'][name]['micro'][key] == slow['systems'][name]['micro'][key], (name, key)


# ------------------------------------------------------------------ integration guard: PR #28 SharedDetector wrapper
def test_shared_detector_wrapper_keeps_prediction_caching():
    """Skips on trees without ``SharedDetector``; after integration it fails loudly if the wrapper hides the opt-in."""
    shared = getattr(ml_runner, 'shared', None)
    if shared is None:
        pytest.skip('SharedDetector not present in this tree (PR #28 not integrated)')
    inner = CacheableStub()
    wrapped = shared(inner)
    assert wrapped is not inner and shared(wrapped) is wrapped
    assert getattr(wrapped, 'prediction_cache_safe', False) is True, 'SharedDetector must forward prediction_cache_safe'
    assert getattr(shared(PlainStub()), 'prediction_cache_safe', False) is False
    runner, out = _run(wrapped, MESSAGES, prediction_cache=True)
    _, ref = _run(CacheableStub(), MESSAGES, prediction_cache=False)
    assert runner.prediction_cache_enabled and out == ref
    assert (runner.model_evaluations, runner.cache_hits) == (4, 4) and len(inner.seen) == 4


def test_model_time_excludes_cache_only_batches():
    detector = CacheableStub()
    runner = MLBatchRunner(detector, MLWorkBudget(batch_fields=1))
    runner.add('first', [('json_body.person', 'NAME Maya')])
    recorded_model_seconds = runner.seconds
    assert runner.model_evaluations == 1 and recorded_model_seconds >= 0
    runner.add('second', [('json_body.person', 'NAME Maya')])
    runner.flush()
    assert runner.model_evaluations == 1 and runner.cache_hits == 1
    assert runner.seconds == recorded_model_seconds
