# V2 inference acceleration (output-preserving)

Status: draft milestone. The V2 checkpoint, the three ensemble members, probability averaging, BIO decoding, the
operating threshold (`min_score` 0.35), frozen datasets and committed benchmark results are **unchanged**. Only *how*
inputs are batched and whether an identical input is re-run changed.

## What changed

| Area | Change | Output effect |
|---|---|---|
| `ml/bilstm.py` `SpanPredictor.predict_pairs` | Encoded chunks are sorted by sequence length (stable) and batched by `batch_size` **and** `max_batch_tokens` (rows × longest chunk; default 64 × `max_seq` = the legacy worst case). Spans are decoded per chunk and reassembled in the original `(field, chunk)` order. `length_bucketing=False` reproduces legacy batching exactly. | Identical labels, spans, field association and threshold inclusion. Raw scores differ by float32 rounding only (≤ 3.5e-7 measured). |
| `ml/infer.py` `BiLSTMDetector` | Forwards `batch_size`, `max_batch_tokens`, `length_bucketing`; declares `prediction_cache_safe = True` (output depends only on location + text). Default `batch_size` stays 64 (see sweep). | None. |
| `ml_runner.py` `MLBatchRunner` | Scan-local prediction cache keyed on `(location, text)`, opt-in per detector, bounded LRU (65,536 entries / 8,000,000 key chars / fields > 4,096 chars never cached). Reuses only neural predictions; every occurrence gets its own finding, message provenance, field index and quality flags. | Identical findings. A reused score is the earlier evaluation's score (same rounding caveat). |
| `engine.py` summary | Additive: `ml_fields_model_inferred`, `ml_prediction_cache_hits`, `ml_prediction_cache_enabled`. | Schema-compatible (summary allows extra keys). |

Budget semantics are unchanged: a cache hit is an *evaluated* field and consumes the field and character budgets as
before; `ml_fields_evaluated = ml_fields_model_inferred + ml_prediction_cache_hits`. Time budget measures model time,
so cache hits leave more time for real inference (fewer `time_budget` skips is the intended effect). Detector failure
still fails the scan closed; failed batches are never cached. The cache dies with the runner (one scan), is never
logged or serialised, and is disabled for any detector that does not opt in (e.g. PR #23's `SharedDetector` wrapper does
not forward the attribute, so caching is simply off there).

## Validation

* `tests/test_ml_inference_acceleration.py` (18 tests): accelerated vs. legacy path on fixed fictional inputs (Unicode,
  hyphenated and apostrophe names, emoji, control characters, replacement characters, a > `max_seq` text split into
  several chunks, exact and cross-location repeats) for batch sizes 64/128/256/512 and tiny token caps; batching is a
  bounded permutation; detector attribution/threshold unchanged; cache reuses only predictions, keeps per-occurrence
  quality flags and field indices, counts against budgets, is opt-in, bounded, not polluted by failures; real-V2 engine
  reports identical with/without acceleration (findings, coverage counters, partial coverage, cancellation);
  ground-truth evaluation of the controlled fixture gives identical TP/FP/FN for rules-only, model-only and
  rules+model.
* `scripts/ml/bench_v2_inference.py`: runs the **original `origin/main` source tree** (exported with `git archive`) as
  the baseline, each configuration in its own process with a fixed thread count.

## Results — Linux x86-64 CPU, 4 threads (NOT the M3 MacBook Air)

These numbers come from the cloud sandbox CPU. **Mac verification is still required**:
`python scripts/ml/bench_v2_inference.py --out mac.json --threads 4` and
`python scripts/ml/bench_v2_inference.py --out mac52.json --skip-model --scan-mib 52 --scan-profile large`.

### Model only (`predict_pairs`, best of 3, baseline = original code at batch 64)

| Input set | Baseline | Batch 64 | Batch 128 | Batch 256 | Batch 512 |
|---|---|---|---|---|---|
| Frozen V2 val + challenge (4,058 fields) | 7.54 s | 3.83 s (1.97×) | 3.85 s (1.96×) | 3.75 s (2.01×) | 3.79 s (1.99×) |
| Synthetic HTTP fields (6,000; 4,645 unique) | 41.70 s | 16.61 s (2.51×) | 15.56 s (2.68×) | 14.10 s (2.96×) | 16.04 s (2.60×) |
| Peak RSS, frozen set | 617 MiB | 629 MiB | 667 MiB | 754 MiB | 744 MiB |

Output comparison, every batch size: **0** fields with a span/label difference, **0** threshold-inclusion differences,
**0** scores within 1e-4 of the threshold; max |Δscore| 1.8e-7 (frozen) / 3.5e-7 (synthetic); 89–99 % (frozen) and
~61 % (synthetic) of raw scores are bitwise identical. Scores are therefore **not** claimed bitwise identical.

### Scan path batch-size sweep (2 MiB synthetic capture, prediction cache on)

| Predictor batch | 64 | 128 | 256 | 512 | 64 + runner `batch_fields=1024` |
|---|---|---|---|---|---|
| Model time | 21.5 s | 22.0 s | 21.5 s | 23.0 s | **10.7 s** |

In real scans the runner hands the predictor at most `batch_fields` (default 256) fields per call, so the predictor
batch size barely matters and 64 is kept (lowest memory). The dominant remaining lever is the **existing** runner knob
`--ml-batch-fields` (more fields per call → better length grouping): 1024 halved model time again with identical
coverage. Its default is deliberately not changed in this PR (it alters the reported `ml_work_limits`).

### Full scan, 2 MiB synthetic capture (22,088 eligible fields)

| Run | Wall | Model | Peak RSS | Model-inferred / cache hits | Findings vs baseline |
|---|---|---|---|---|---|
| Baseline (`main`) | 45.2 s | 42.8 s | 685 MiB | 22,088 / – | – |
| Candidate, no cache | 28.4 s (1.59×) | 25.9 s (1.65×) | 652 MiB | 22,088 / 0 | identical except confidence (max Δ 1e-6 = report rounding step) |
| Candidate, cache | 23.3 s (1.94×) | 20.8 s (2.06×) | 680 MiB | 5,717 / 16,371 | identical except confidence (max Δ 1e-6) |

STRESS52_PLACEHOLDER

## Why the cache helps less than its hit rate

Repeated fields are mostly short (names, usernames, statuses); the expensive model work is long, unique free text
(comments, notes). A 74–79 % hit rate therefore saved ~15–20 % of model time. Gains depend on the traffic.

## Deferred (feasibility only — not implemented here)

| Option | Feasibility | Evidence / risk |
|---|---|---|
| Multiprocessing (N single-thread workers) | High. Earlier measurement: 1 thread did the same work in 5.6 s vs 4.5 s with 4 threads, so 4 single-thread workers should give ~2.5–3× aggregate on 4 cores. | Each worker loads torch + 3 members (~600 MiB RSS each → ~2.4 GiB on 4 workers; fine on 16 GB). Needs ordered result merge (runner tickets already preserve order), cancellation propagation, and a decision on whether the time budget is wall or summed CPU time. macOS uses `spawn` (slower start). |
| ONNX Runtime | Medium. Typically 1.5–2× for small LSTMs on CPU. | `pack_padded_sequence` does not export cleanly; would need exact-length buckets or a masked unidirectional rewrite; scores will drift (~1e-6), so this PR's equivalence suite is the gate. |
| int8 dynamic quantisation | Low value. Measured: no speed-up over length bucketing and 23/4,000 chunks changed argmax. | Not recommended for V2. |
| Distillation into one student | Highest ceiling (~3× model time) but a **new model (V3)**. Measured: dropping to 1 ensemble member changed 788/4,000 chunk tag paths. | Needs training, a full re-evaluation and new frozen results; V2 results stay untouched. |
| Apple GPU (MPS) | Unlikely to help a 1-layer, hidden-96 LSTM with short sequences (kernel-launch bound). Benchmark on the M3 before considering it. | – |
