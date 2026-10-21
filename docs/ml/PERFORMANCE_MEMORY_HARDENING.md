# Performance & memory hardening — root-cause investigation and changes

Branch `feature/trace-performance-memory-hardening`, based on `main` `a74dfcb8819758dfecb7a73a5d4b47272bb5b88e`.
Original performance baseline: `11d41e8c583231edd86b621d96cc037fe676108f`.
**All measurements in this document are Linux x86-64 (4 CPUs, 4 PyTorch threads, CPython 3.13.16, PyTorch 2.14.1 CPU).
No M3 measurement was made or is implied.** Machine-readable results and summaries: `docs/performance/results/hardening_*`.

## 1. Reported problem (user-supplied M3 data)

On the deterministic 2 MiB synthetic workload, the original baseline completed under the Standard profile (61.23 s,
656.7 MiB peak), while the accelerated candidate failed the Standard 1 GiB memory guard with the cache on or off and
completed under Large at 1209.4 MiB. Baseline and candidate used different profiles, so this was strong evidence of a
problem but not a controlled attribution.

## 2. Reproduction on Linux

Same capture (sha256 `1b3b62a5…`, seed 52), Standard profile, fresh process per run, own-process peak (`VmHWM`):

| Code | Wall | Model | Peak RSS |
|---|---|---|---|
| `11d41e8` baseline | 45.4 s | 43.0 s | 689 MiB |
| `main` `a74dfcb` (accelerated, cache on, token cap 12,288, batch_fields 256) | 27.7 s | 19.7 s | 753 MiB |

`main` **did not** exceed 1 GiB on Linux, so the M3 failure is not reproduced here. A stage-attributed RSS/allocator
timeline (50 ms sampling, glibc `mallinfo2`) located the peak in the `ml_inference` stage, ≈190–240 MiB above the
≈515 MiB process size after model load. Python-level allocations at the peak were only ≈87 MiB (`tracemalloc`; mostly
in-memory evidence objects), so the remainder is native (PyTorch tensors and allocator retention).

Forcing PyTorch's generic convolution path (oneDNN disabled — the path builds without oneDNN take) raised the peak
markedly: baseline 862 MiB, `main` 912 MiB.

## 3. Root causes found

### 3.1 Inference working set (code; confirmed by measurement)

Every large inference temporary — char-embedding copies, convolution output/workspace, activation copies, LSTM input
projections — scales with the padded positions of a batch (rows × longest chunk). Length bucketing groups long chunks
together, so the accelerated path runs **many** batches at the token cap, whereas legacy input-order batches usually
had short padded lengths. The cap was 64 × 192 = 12,288 positions. Per-op profiling of one full-cap forward pass
showed ≈75 MB `empty_like`, ≈73 MB `clone`, ≈45 MB convolution and up to ≈72 MB `addmm` (generic path) per member.

Token-cap sweep on the full 2 MiB scan (Standard, cache on, `main`):

| Cap | oneDNN: wall / model / peak | generic conv: wall / model / peak |
|---|---|---|
| 12,288 (old) | 31.7 s / 22.9 s / 725 MiB | 60.8 s / 52.6 s / 912 MiB |
| 6,144 | 23.3 s / 14.5 s / 668 MiB | 36.6 s / 28.2 s / 752 MiB |
| **4,096 (new default)** | 23.2 s / 14.3 s / 657 MiB | 35.2 s / 27.3 s / 716 MiB |
| 2,048 | 22.1 s / 14.1 s / 649 MiB | 35.4 s / 27.3 s / 680 MiB |

Smaller caps were **both faster and lighter** in real scans (cache-friendlier tensors). 4,096 was chosen over 2,048
because model-only throughput at 2,048 was 12–20 % lower. Spans were identical at every cap.

### 3.2 Memory guard contract (code; confirmed by reproduction)

`_check_memory` compared the process-lifetime `ru_maxrss` with the budget at every stage. `ru_maxrss` never decreases
and, on Linux, is inherited across fork+exec. Consequently any earlier peak — model loading, an earlier scan in the
same dashboard process (scans run as threads), or a large parent process — failed every later analysis immediately.
Reproduced on `main`: after a freed 1.2 GiB allocation, an 8-packet Standard scan raised `AnalysisLimitError`.

### 3.3 Benchmark instrumentation (tooling; confirmed)

The same inheritance made the earlier benchmark report each child's peak as at least the parent's RSS (the parent
held prior runs' findings). That produced the apparent "+600 MiB per cache size" regression in an earlier matrix; it
was a measurement artefact, fixed in the benchmark (own-process `VmHWM`, parent holds no findings and never imports
torch).

### 3.4 Unresolved for M3

Why the M3 candidate peaked ≈550 MiB above the baseline cannot be established on Linux. The leading hypothesis is
the combination of (a) repeated full-cap inference temporaries (3.1) and (b) macOS's allocator retaining freed large
blocks of varying sizes, which a high-water mark counts. (a) is fixed and measured; (b) is not verified. One targeted
M3 run (below) is required for acceptance.

## 4. Changes

| Area | Change | Output effect |
|---|---|---|
| `ml/bilstm.py` | `SpanPredictor.DEFAULT_MAX_BATCH_TOKENS = 4096` | none (spans identical; scores within float32 rounding, max 3.5e-7) |
| `ml_runner.py` | `MLWorkBudget.batch_fields` 256 → 1024 | none (runner output is batch-size invariant, tested) |
| `ml_runner.py` | prediction cache: 16,384 entries **and** 16 MiB estimated-byte bound; oversized entries not cached; estimate pinned against `sys.getsizeof` | none |
| `ml_runner.py`, `engine.py` | `ml_time_budget_overshoot_seconds` (additive) | reporting only |
| `engine.py` | `_MemoryGuard`: analysis-attributable rule; diagnostics with MiB, budget, stage | see safety analysis |
| `capture.py`, `engine.py` | no address re-parsing; C-speed RFC 1071 checksum; no `dataclasses.replace` per packet; real endpoint interning; slotted `TcpPacket`/`PacketSourceRange` | none (full reports byte-identical) |
| `reporting.py`, `http_evidence.py`, `engine.py` | reused JSON encoders; direct decoding of escape-free JSON keys; `evidence` stage timer | none (byte-identical) |
| `scripts/ml/bench_v2_inference.py` | regression gate, phase timings, Markdown summary, generic-conv emulation, schema-additive comparison | tooling |

### Memory guard — safety analysis

* If the process started the analysis within budget (CLI, fresh worker, benchmark), any breach must raise the lifetime
  peak during the analysis, which fails exactly as before. **Identical behaviour; not weaker.**
* If the lifetime peak was already over budget, the analysis fails if it raises the peak further, or if current RSS
  (Linux `/proc/self/statm`, macOS `task_info`) exceeds the budget at any check. The only case no longer failed is a
  transient spike between checks that stays below the process's own earlier peak.
* If current RSS cannot be read, it fails closed (old behaviour). A guard-less `_check_memory(budget)` keeps the strict
  old rule. Concurrent scans in one process can only make the guard stricter (a new peak set by another scan fails
  this one).

## 5. Results (Linux; JSON + Markdown in `docs/performance/results/`)

**2 MiB, Standard profile, in-memory report, vs `11d41e8`** (`hardening_2mib_standard_vs_11d41e8`): baseline 45.4 s /
43.0 s model / 689 MiB → cache off 24.3 s / 17.7 s / 648 MiB (1.87× wall, 2.43× model) → cache on 16.1 s / 9.3 s /
654 MiB (2.83×, 4.63×). Findings identical on every baseline field; candidate adds the `evidence` key (schema change
from PR #25), reported explicitly. Gate PASS.

**Same vs `main`** (`hardening_2mib_standard_vs_main`): `main` 27.7 s / 19.7 s / 753 MiB → branch 18.1 s / 10.7 s /
652 MiB (**−101 MiB**, 1.53× wall). Findings strictly identical (no schema difference). Gate PASS.

**Generic convolution path, vs `11d41e8`**: 109.4 s / 106.9 s / 860 MiB → 27.3 s / 19.3 s / 718 MiB (4.0×, 5.5×,
−143 MiB). Gate PASS.

**52 MiB, Large profile, disk-backed report with evidence, `SharedDetector`**: `11d41e8` 1,149 s / 1,094 s model /
793 MiB; `main` 677 s / 535 s / 928 MiB; branch 379 s / 247 s / 807 MiB — 3.03× wall and 4.43× model vs `11d41e8`,
1.79× and −121 MiB vs `main`. 570,424/570,424 eligible fields evaluated in all runs; 79 % prediction-cache hits.
Non-model time is higher than on `11d41e8` (≈132 s vs 55 s) because `11d41e8` predates evidence generation; vs `main`
it is ≈142 → 132 s.

**Model only** (`hardening_model_only_vs_11d41e8`): frozen V2 val+challenge 2.06× (batch 64), synthetic HTTP 2.36×;
0 span, label or threshold-inclusion differences at batch 64–512; max |Δscore| 1.8e-7 / 3.5e-7 (not bitwise).

**Non-model pipeline** (rules only, best of 3 alternating, vs `main`): read/decode/group 8.24 → 5.50 s (12 MiB
field-heavy), 1.48 → 0.95 s (8 MiB segmented); full reports byte-identical on six captures. Buffered-packet memory
814 → 657 B/packet (12 MiB) and 1,590 → 1,360 B/packet (8 MiB).

## 6. Tests

Full suite on this branch: **1,030 passed, 2 failed, 2 skipped**. The 2 failures
(`test_vp_qa_adversarial::test_http2_prior_knowledge_preface_is_not_parsed_and_is_disclosed`,
`test_vp_qa_live_showcase::test_provenance_fields_and_detector_separation`) fail identically on unmodified `main`
(expectations predate HTTP/2 support and the `evidence` finding key). The 2 skips are Playwright UI tests (Playwright
not installed). Genuine V2 weights were used by every real-model test (PyTorch installed). `main` with the same
environment: 1,007 passed, same 2 failed, 2 skipped.

New: `tests/test_memory_guard.py` (9, incl. a real-process transient-spike reproduction), `tests/test_packet_memory.py`
(4), `tests/test_bench_gate.py` (5), cache byte-bound/defaults/overshoot tests in
`tests/test_ml_inference_acceleration.py` (5). `test_memory_budget_failure_is_clean` now simulates genuine excess
(peak **and** current RSS over budget); its assertions are unchanged.

## 7. Required M3 acceptance run (one command)

```
python scripts/ml/bench_v2_inference.py --out m3_hardening.json --summary-md m3_hardening.md \
  --baseline-ref 11d41e8 --skip-model --scan-mib 2 --scan-profile standard \
  --scan-modes baseline,cache=0,cache=16384 --gate
```

Pass criteria are printed and recorded (`[gate] PASS/FAIL`); a failed run is shown as `FAILED`, never as a speed-up.
On macOS the peak is `ru_maxrss` of the worker (no `VmHWM`); the benchmark parent no longer imports torch or holds
findings, so inheritance is minimised.
