# Frozen V2 CPU throughput — 29 October 2026

**NOT READY — CORRECTNESS OR RESOURCE GATE FAILED.**

The ML performance/equivalence gates passed, but exact-head Chromium acceptance has two unresolved mobile Inspector failures. The draft PR is blocked; this does not assert a model-output regression.

Starting remote main: `c17abe7f176116629d726a982f49df1f30b052bc`, tree `3c1045cb6e767ede5373ea90cf2a336bbe8b0c31`. Branch: `perf/astra-v2-inference-throughput`. Initial genuine diagnostic commit: `d63695a91457307287418f14a1e54bdf8e54f884`. The PR records the final immutable commit and CI results. Local snapshot commits have different identities; the base **tree**, every restored source blob and restored binary blob were verified against GitHub. Model comparison JSON records exact inference-source SHA-256 hashes.

## Outcome and scope

Only two production functions changed: `collate()` constructs six dense tensors per batch instead of crossing the Python/PyTorch boundary for each token; `viterbi_decode()` reuses immutable predecessor groups and one score row while retaining backtracking, strict first-tag tie selection and identical additions. The six-tensor path also preserves training dropout RNG draw order and independent storage. There is no model, vocabulary, tokenization, ensemble, threshold, batching, cache, rules, HTTP, Inspector, masking, provenance or coverage policy change.

The frozen ensemble remains `bilstm-v2-d1f9e9fb9a2b`, threshold **0.35**. Scores remain uncalibrated mean chosen-tag probabilities, not probabilities of correctness. No training was performed. Frozen datasets and independent ground truth were not modified. Existing bucketing, character CNN compaction, inference mode and cache bounds are baseline features, not new work.

Genuine checkpoint access was initially blocked by text-only connector endpoints. A one-day private repository Actions artifact supplied existing V1/V2 binaries and training data; all blob hashes were checked before use. The final workflow uploads diagnostic JSON only. No private capture, recovered credential or real-traffic report was uploaded. All workload fields are fictional or existing frozen project data.

## Measurements

Local environment: Linux x86-64, Python 3.12.14, PyTorch 2.6.0+cpu, two PyTorch threads unless explicitly noted. These are shared-environment observations, **not M3 results**. Initial GitHub profiling used PyTorch 2.15.0+cpu; its numbers must not be pooled with local measurements.

| Workload | Baseline | Candidate | Reduction | Correctness evidence |
|---|---:|---:|---:|---|
| Model only: 3,000 validation + 1,058 challenge + 256 fictional fields, median of three warm calls | 2.8633 s | 2.6413 s | 7.75% | All 4,175 unthresholded spans and every raw score identical |
| Indexed Hybrid 2 MiB | 10.9545 s | 10.5585 s | 3.61% | Entire ordered report digest equal, excluding only three clocks |
| Indexed Hybrid 8 MiB | 41.7314 s | 38.1277 s | 8.64% | Entire ordered report digest equal, excluding only three clocks |

The capture results are **one isolated before/after pair per size**, not a statistical performance guarantee. The 8 MiB pair ran candidate first to avoid always favoring the second implementation. They use the deterministic `bench_v2_inference.generate_capture` fixture, **not the owner's 110 MiB capture**. Source, inputs and output equivalence are evidenced in the accompanying JSON. Timing excludes model loading, initial fixture copy, post-scan integrity hashing and private-directory cleanup; it includes capture processing, inference, SQLite indexing and atomic report publication.

Model-only cold calls: 3.1958 → 2.7616 s. Peak RSS over those model calls: 301.3 → 316.0 MiB; neither grew after its last two warm iterations. This small fixture does not prove absence of long-session growth. Indexed scan peaks were 275.80 → 276.19 MiB (2 MiB) and 317.18 → 318.13 MiB (8 MiB). RSS and resource high-water observations are reported separately; neither is an Apple unified-memory measurement.

| Indexed workload | Eligible / evaluated | Skipped | Actual model evaluations | Cache hits | Evictions | Final conservatively accounted cache bytes |
|---|---:|---:|---:|---:|---:|---:|
| 2 MiB, both versions | 22,088 / 22,088 | 0 | 5,717 | 16,371 | 0 | 4,279,009 |
| 8 MiB, both versions | 88,037 / 88,037 | 0 | 19,132 | 68,905 | 0 | 15,139,785 |

Cache bytes are retained-object accounting, **not RSS**. The 16 MiB/65,536-entry bounds and digest-only keys remain unchanged. These repetitive fixtures have substantial reuse; they do not establish throughput for mostly unique traffic. Existing genuine eviction and occurrence-quality tests remain in the suite.

Candidate 8 MiB stage observations: reading/decoding/grouping 1.859 s, segmentation 0.089 s, reconstruction 1.235 s, HTTP parsing 0.156 s, field extraction 0.291 s, field/evidence processing 4.117 s, rules 0.702 s, actual detector work 24.666 s, result aggregation 2.006 s, final report write 0.437 s. Index observer time, 3.873 s, is nested in other stages; do **not** add it again. Raw cache lookup and finding reconstruction are not separately isolated by this harness. Reports were approximately 41.35 and 165.57 MB; this PR does not optimize report storage.

## Profile and intervention evidence

A genuine 256-field baseline timed invocation measured 0.457 s: tokenization 0.0116, encoding (including vocabulary/context) 0.0221, collation 0.0707, model forwards 0.2872, Viterbi 0.0535 and span reconstruction 0.00174 s. This is a diagnostic snapshot, not a stable stage percentage. Python work was material; tensor forwards still dominated. Batching used 10,843 real / 14,182 padded positions in six calls.

Bounded `torch.profiler` ran only 32 fields. Leading native operators were `addmm`, packed `lstm`, `tanh`, convolution and multiplication. JSON preserves self CPU time and allocator memory observations. Those operator allocations are not peak RSS. cProfile includes tokenization, context/vocabulary helpers, encoding, tensor construction, list conversion and decoding. Embedding/CNN/LSTM operators and ensemble operations appear in the tensor profile; the tooling does not claim a complete non-overlapping allocation of every pipeline microstage.

The separate genuine-output microbenchmark alternated baseline/candidate order and retained all three samples:

| Operation | Calls per sample | Baseline median | Candidate median |
|---|---:|---:|---:|
| Collation | 6 | 0.08546 s | 0.01598 s |
| BIO decoding | 287 | 0.05549 s | 0.01024 s |

One candidate collation sample was 0.09296 s; it is retained, not discarded. Scheduler/allocator/GC attribution was not established. This variability is why the end-to-end results, not an isolated best time, govern the conclusion.

## Bounded CPU configuration experiments

Same 256 fictional fields, isolated processes, three warm calls per configuration, candidate source. These configurations were **not promoted to production**.

| Threads | Token cap | Median seconds | Peak RSS MiB |
|---:|---:|---:|---:|
| 1 | 4,096 | 0.4731 | 262.2 |
| 2 | 4,096 | 0.4135 | 264.5 |
| 4 | 4,096 | 0.3942 | 262.2 |
| 6 | 4,096 | 0.4043 | 263.8 |
| 8 | 4,096 | 0.4372 | 267.8 |
| 2 | 2,048 | 0.5724 | 252.8 |
| 2 | 6,144 | 0.4683 | 276.9 |
| 2 | 8,192 | 0.4494 | 286.2 |

Every tested configuration preserved labels, spans, field order and threshold decisions on this fixture. Nondefault batching/thread configurations had maximum raw-score drift up to **2.11244e-7**, consistent with float32 arithmetic ordering; that observation is not a guarantee for every possible field. The actual production change at fixed configuration had **zero** raw-score drift across all 4,314 comparison fields. Small thread differences and slower/larger token-cap results do not justify changing the default 64-chunk/4,096-position bounds or selecting M3 threads using Linux evidence.

MPS: **blocked/unexecuted**, no Apple hardware available. CPU loading is preserved; packed-sequence compatibility, fallback behavior, transfers, unified-memory use and MPS numerical drift are not established. No GPU default was enabled. Compilation, quantization and backend replacement were deferred; none is presented as a measured failure or speedup.

## Verification and remaining gates

- New tests first exposed 517 tensor constructions, repeated BIO transition checking, unsupported Stress/timeout/hash controls and successful exit after a failed scan. Reference tensors, dropout state, BIO ties/unreachable states and genuine scores now pass.
- Local complete suite before the final two harness safety guards: **1,104 passed / 16 skipped / 0 failed**. All skips were Playwright/browser availability. See `local-full-pytest.log`.
- After review, focused tests for inference and the harness: **24 passed / 0 skipped / 0 failed**. New race and digest-failure tests first failed, then passed after fixes. Capture identity is rechecked against the report receipt; a verification subprocess failure cleans its private indexed job and returns failure.
- One read-only Astra review found no production blocker. Its threshold-equality observation was addressed explicitly in the comparison gate. Cancellation remains cooperative inside existing engine batches; no cancellation or resource limits were weakened.
- Final remote CI runs the full core and genuine ML suites, actual Chromium journeys, Nishant's authenticated packet/HTTP/Inspector demonstration, indexed genuine-V2 smoke, and complete frozen-field baseline comparison. Check the PR's exact-head checks for executed counts; this document does not label pending jobs passed.
- Model assets and frozen dataset hashes remain unchanged. Whole-report digests preserve field identity, source intervals, completeness flags, masking, rules, model findings and counters. Unicode field offsets remain Unicode offsets; no packet-byte reinterpretation was added.
- No full 110 MiB M3 scan, M3 thread sweep, MPS comparison or 1 GiB scan was executed. Linux 2/8 MiB results cannot satisfy those gates.

## M3 target arithmetic

Owner baseline: 683.834 s total, 518.58 s model, leaving 165.254 s elsewhere. Holding non-model work fixed, ≤512.88 s requires model time ≤347.626 s (32.97% less); ≤478.68 s requires ≤313.426 s (39.56% less). Five and four minutes require model time ≤134.746 and ≤74.746 s. Three minutes leaves only 14.746 s for inference. Two minutes cannot be reached solely by eliminating model time under that fixed-cost assumption. These are budgets, not predictions.

A 1 GiB/120–180 s objective requires 5.69–8.53 MiB/s end-to-end. No measurement here establishes that throughput, and linear scaling from a smaller synthetic capture is not an M3 prediction. Full eligible coverage, field density, cache reuse, evidence volume and peak unified memory remain workload-dependent. Candidate filtering or smaller work budgets would be explicitly partial coverage and are outside this change.

## Reproduction and exact-M3 acceptance

Install the project's existing ML dependencies plus benchmark-only `ijson` and `psutil`. Use the same Python/PyTorch environment for both source trees. Preserve the owner capture; do not generate a replacement under its filename.

```sh
git worktree add --detach ../trace-v2-baseline c17abe7f176116629d726a982f49df1f30b052bc
python -m pip install ijson psutil
python scripts/validation/compare_frozen_v2.py --baseline-root ../trace-v2-baseline --include-frozen --output frozen-equivalence.json
python scripts/validation/bench_v2_preparation.py --baseline-root ../trace-v2-baseline --output preparation.json
```

On the actual M3, first run the bounded model comparison with `--threads 1`, `2`, `4`, `6`, `8` and distinct output files. Do this on external power with stable thermal conditions. The owner's historical thread/PyTorch configuration was not supplied: preserve it if known, and record any difference. Do not present a newly chosen configuration as an exact reproduction of the historical 683.834 s timing.

The following acceptance command runs two balanced-order pairs, each in an isolated process, verifies the exact owner capture, requires complete analysis, compares every report event and checks the published counters. It does not upload anything. Set the two environment variables first; `TRACE_THREADS` defaults to the benchmark's existing two-thread configuration. Expect a sustained workload; this is the final hardware gate, not an iteration command.

```sh
export TRACE_CAPTURE='/absolute/path/trace_synthetic_110MiB.pcap'
export TRACE_THREADS=2
python - <<'PY'
import json, os, platform, statistics, subprocess, sys
from pathlib import Path
assert platform.system() == 'Darwin' and platform.machine() == 'arm64', 'M3 acceptance requires Apple hardware'
brand = subprocess.check_output(['sysctl','-n','machdep.cpu.brand_string'], text=True).strip()
memory = int(subprocess.check_output(['sysctl','-n','hw.memsize'], text=True))
assert brand == 'Apple M3' and memory == 16 * 2**30, (brand, memory)
root = Path.cwd(); base = (root / '../trace-v2-baseline').resolve()
assert subprocess.check_output(['git','-C',str(base),'rev-parse','HEAD'],text=True).strip() == 'c17abe7f176116629d726a982f49df1f30b052bc'
assert not subprocess.check_output(['git','-C',str(base),'status','--porcelain','--untracked-files=no'],text=True).strip()
assert not subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],text=True).strip()
head = subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
capture = Path(os.environ['TRACE_CAPTURE']).resolve(); threads = int(os.environ.get('TRACE_THREADS','2'))
out = root / 'm3-110mib-acceptance'; out.mkdir(exist_ok=False)
sha = '42e52f7ebb470d45e3d883ba6c800a11fce17357cf0edad417fefb8ca059c9ce'
runs = {'baseline':[], 'candidate':[]}
expected = {'packets_captured':361389, 'http_messages':120462, 'fields_extracted':2349009,
            'ml_fields_eligible':1927392, 'ml_fields_evaluated':1927392, 'ml_fields_skipped':0,
            'rules_findings':244046, 'ml_findings':180694}
for repetition in range(2):
    order = ['baseline','candidate'] if repetition == 0 else ['candidate','baseline']
    for label in order:
        result = out / f'{label}-{repetition}.json'
        command = [sys.executable, str(root/'scripts/validation/bench_performance_memory.py'),
                   '--source-root',str(base if label == 'baseline' else root), '--capture',str(capture),
                   '--expected-capture-sha256',sha, '--output',str(result), '--profile','stress',
                   '--ml-profile','high_capacity','--checkpoint',str(root/'src/packet_pii/ml/artifacts/bilstm_v2'),
                   '--indexed','--stream-digest','--require-complete','--worker-timeout','3600','--threads',str(threads)]
        subprocess.run(command, check=True, timeout=7300)
        data = json.loads(result.read_text()); run = data['runs'][0]
        assert data['model_version'] == 'bilstm-v2-d1f9e9fb9a2b' and data['min_score'] == .35
        assert run['status'] == 'completed' and not run['summary']['analysis_incomplete']
        assert all(run['summary'][k] == v for k,v in expected.items()), run['summary']
        assert run['verified_capture_evidence']['capture_sha256'] == sha
        assert run['lifetime_peak_rss'] < data['memory_budget_bytes']
        runs[label].append(run)
all_runs = runs['baseline'] + runs['candidate']
assert len({r['canonical_report_sha256'] for r in all_runs}) == 1, 'findings/provenance/counters differ'
assert {r['report_digest_method'] for r in all_runs} == {'ordered-json-events-v1'}
med = {k:statistics.median(r['seconds'] for r in values) for k,values in runs.items()}
peaks = {k:max(r['lifetime_peak_rss'] for r in values) for k,values in runs.items()}
result = {'candidate_sha':head, 'hardware':brand, 'unified_memory_bytes':memory, 'threads':threads,
          'median_seconds':med, 'peak_rss_bytes':peaks, 'reduction_percent':100*(1-med['candidate']/med['baseline']),
          'historical_minimum_time_met':med['candidate']<=512.88,
          'historical_primary_time_met':med['candidate']<=478.68,
          'review_required':'Inspect thermal stability and unexplained RSS changes before accepting performance.'}
(out/'comparison.json').write_text(json.dumps(result,indent=2)+'\n'); print(json.dumps(result,indent=2))
PY
```

A report hash mismatch is a failed correctness gate, not permission to relax score or provenance comparison. An unchanged report schema needs no migration: integrate through the existing `BiLSTMDetector`/`MLBatchRunner` interface after review. No merge or model reconfiguration is part of this delivery.


## Final exact-code CI disposition

Tested code commit: `0dae8900c7145ce6bd594f3880b8ef98913fa3f4`. The final documentation-only commit changes no executable code, tests, dependencies or workflow configuration; `[skip ci]` avoids rerunning those unchanged jobs. Check results remain explicitly tied to the tested code commit, not presented as a new-head run.

| Gate | Executed result |
|---|---|
| Full core suite | 888 passed / 175 optional-dependency skips / 0 failed |
| Full ML suite | 1,102 passed / 20 skipped / 0 failed |
| Real Chromium | **15 passed / 0 skipped / 2 failed** |
| Frozen 4,314-field comparison, PyTorch 2.15 CPU | Passed; all 4,175 spans/raw scores identical; thresholds and weight identity equal |
| Genuine indexed 2 MiB smoke | Passed; 22,088 evaluated, zero skipped, complete analysis |
| Nishant authenticated packet/HTTP/Inspector demonstration | Required assertions passed; optional TShark cross-check blocked (not installed) |

ML-job skips comprise 16 browser-availability cases and four h11-dependent cases; the separate browser and mentor jobs install those dependencies. Local full tests exercised the h11 cases. Do not combine test totals across overlapping jobs into a unique-test count.

The failures are both `tests/test_experience_journeys.py::test_journey_b_drawer_and_sheet_open_in_place_and_return`, parameters `[390-844-sheet]` and `[375-667-sheet]`, at line 174. Opening the mobile Inspector changes `scrollY` from 260 to 0. These UI/test files are unchanged by this PR. The initial diagnostic-base browser run passed 17 tests on the same Playwright 1.64.1 / Chromium 156.0.8078.4 versions; this is not proof of the failure's cause. No rerun or assertion weakening was used to hide the failures, and the separate Inspector workstream was not modified. Resolve or reproducibly explain this gate before accepting integration.

Evidence: [exact-code test run](https://github.com/kotchadon/pcap-pii-engine/actions/runs/40892544246), [failed Chromium job](https://github.com/kotchadon/pcap-pii-engine/actions/runs/40892544246/job/123512957626), [genuine profile/equivalence run](https://github.com/kotchadon/pcap-pii-engine/actions/runs/40892535636), [initial diagnostic-base run](https://github.com/kotchadon/pcap-pii-engine/actions/runs/40886770808). The CI model-only single warm comparison measured 19.0% less time, but is not promoted over the three-repeat local result or described as end-to-end/M3 acceptance.
