"""Memory/latency contracts without requiring an installed checkpoint."""
import sys
from collections import OrderedDict

import pytest

from packet_pii import ml_runner
from packet_pii.ml_runner import MLBatchRunner, MLWorkBudget
from test_ml_inference_acceleration import CacheableStub, MESSAGES, _run


def test_time_budget_is_rechecked_inside_a_many_field_message(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(ml_runner.time, 'perf_counter', lambda: clock[0])

    class Slow(CacheableStub):
        def predict_fields(self, fields):
            clock[0] += 2.0
            return super().predict_fields(fields)

    dispositions = []
    runner = MLBatchRunner(Slow(), MLWorkBudget(max_seconds=1, batch_fields=2),
                           disposition=lambda key, index, status: dispositions.append((index, status)))
    runner.add('one', [('json_body.name', f'NAME {i}') for i in range(7)])
    runner.flush()
    assert runner.batches == 1
    assert (runner.evaluated, runner.skipped, runner.eligible) == (2, 5, 7)
    assert runner.skip_reasons == {'time_budget': 5}
    assert dispositions == [(0, 'evaluated'), (1, 'evaluated')] + [(i, 'skipped:time_budget') for i in range(2, 7)]
    assert [f['field_index'] for _, fs in runner.take_ready() for f in fs] == [0, 1]
    assert runner.time_budget_overshoot_seconds == 1.0


def test_character_batch_flush_precedes_admitting_the_next_field(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(ml_runner.time, 'perf_counter', lambda: clock[0])

    class Slow(CacheableStub):
        def predict_fields(self, fields):
            clock[0] += 2.0
            return super().predict_fields(fields)

    runner = MLBatchRunner(Slow(), MLWorkBudget(max_seconds=1, batch_fields=10,
                                              max_field_chars=10, batch_characters=10))
    runner.add('one', [('json_body.name', 'NAME aa')] * 4)
    runner.flush()
    assert runner.evaluated == 1 and runner.skipped == 3 and runner.batches == 1
    assert runner.characters == 7 and runner.inferred == 1


def test_cache_byte_bound_accounts_for_retained_python_objects(monkeypatch):
    monkeypatch.setattr(ml_runner, 'PREDICTION_CACHE_MAX_BYTES', 8_192, raising=False)
    runner, out = _run(CacheableStub(), [('one', [('json_body.name', f'NAME {i}') for i in range(100)], {})],
                       MLWorkBudget(batch_fields=3))
    measured = sys.getsizeof(runner._cache)
    for key, spans in runner._cache.items():
        measured += sys.getsizeof(key) + sys.getsizeof(spans)
        for span in spans:
            measured += sys.getsizeof(span) + sum(sys.getsizeof(value) for value in span)
    assert measured <= 8_192
    assert measured <= runner.cache_bytes <= 8_192
    assert runner.cache_evictions > 0 and len(out[0][1]) == 100


def test_cache_oversized_entry_is_not_retained(monkeypatch):
    monkeypatch.setattr(ml_runner, 'PREDICTION_CACHE_MAX_BYTES', 256, raising=False)
    runner, out = _run(CacheableStub(), MESSAGES)
    _, reference = _run(CacheableStub(), MESSAGES, prediction_cache=False)
    assert out == reference and len(runner._cache) == 0
    assert runner.cache_bytes == sys.getsizeof(OrderedDict())


def test_primary_digest_collision_does_not_reuse_another_fields_predictions(monkeypatch):
    class Collision:
        def update(self, value):
            pass

        def digest(self):
            return b'x' * 16

    monkeypatch.setattr(ml_runner.hashlib, 'blake2b', lambda **kw: Collision())
    messages = [('one', [('json_body.name', 'NAME Ana'), ('json_body.name', 'plain')], {}),
                ('two', [('json_body.name', 'plain'), ('json_body.name', 'NAME Ana')], {})]
    cached, out = _run(CacheableStub(), messages, MLWorkBudget(batch_fields=2))
    _, reference = _run(CacheableStub(), messages, MLWorkBudget(batch_fields=2), prediction_cache=False)
    assert out == reference
    assert cached.model_evaluations == 2 and cached.cache_hits == 2


def test_checkpoint_cannot_release_a_partially_admitted_message():
    ready = []
    runner = MLBatchRunner(CacheableStub(), MLWorkBudget(batch_fields=2),
                           checkpoint=lambda event: ready.extend((key, list(findings)) for key, findings in runner.take_ready()))
    runner.add('one', [('json_body.name', f'NAME {i}') for i in range(5)])
    runner.flush()
    ready.extend(runner.take_ready())
    assert len(ready) == 1
    assert [finding['field_index'] for finding in ready[0][1]] == [0, 1, 2, 3, 4]
    assert runner.inferred == runner.evaluated == 5
