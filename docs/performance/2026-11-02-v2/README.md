# Frozen V2 throughput: measured improvement, M3 target unverified

**Status: draft; the 30% end-to-end target is not demonstrated.** No native M3, full 110 MiB, 150 MiB or 500 MiB acceptance run occurred in this Linux environment. No merge, training, checkpoint change or private traffic upload occurred.

## Revisions and ownership

- Inspected main: `50c3a1251995d7063f3b49a9354c71d4ff429504`.
- Inspected PR46: `0bd72c93b6e3c3a171584e6bcb1445fbf3f65d01`, still draft/unmerged.
- Main already includes capacity PR52 and Inspector test PR51. Their definitions, selector, frontend and backend behavior are preserved.
- Isolated branch: `perf/astra-v2-throughput-next`; [draft PR54](https://github.com/kotchadon/pcap-pii-engine/pull/54), continuation of PR46 and issue45.
- `4e73649a49972dbc66172cb31be774043917a9b2`: current main plus PR46; incremental comparison baseline.
- `135452854b78bb2d2b94d7327fdf58015ba65ce5`: measured production implementation and diagnostics.
- `7e4fd27b940f92d7c68bff86a128a655fc694b2a`: acceptance-only guard binding the owner's capture to its known packet/field/finding counts. Production code is unchanged from `1354528`.

The final documentation commit does not change executable code. Local restored snapshots initially contained a transport-added final newline in some unchanged text files; this was normalized to exact Git blobs. No executable statement differed. `restoration-integrity.json` records this distinction; changed model files and binary assets were verified separately. Remote commits preserve unchanged Git objects directly.

## Retained implementation

PR46's bulk tensor construction and BIO decoder improvements remain. The additional production change is entirely in `ml/bilstm.py`:

1. Build one batch-local index plan using complete padded character-ID rows.
2. Each ensemble member independently runs its own embedding/CNN on distinct nonempty rows.
3. Gather pooled character features back into their original token positions before the unchanged key context and packed BiLSTM calculation.

No learned features cross ensemble members. No state survives across calls or scans. Lowercased word IDs are **not** the identity: case, unknown-character mappings and character truncation retain exactly the existing model semantics. Token offsets, field identities, masking and network provenance are unchanged. Gradient-enabled training retains the original dense character path. There is no new worker or persistent cache.

Production bounds remain 256 outer fields, 262,144 outer characters, 64 internal chunks and 4,096 padded positions per forward batch, with the existing per-field/sequence/character-width bounds. The temporary numeric row/index structures scale with that batch, not 15 million admitted fields. Custom legacy benchmark batching retains its existing limits.

## Measurements

Local measurements: Linux x86-64, Python 3.12, PyTorch 2.6.0+cpu, two threads. CI uses PyTorch 2.15.0+cpu; its times are not pooled with local results. Shared-host variability remains. These are fictional fixtures, not the owner's 110 MiB capture.

| Comparison | Before | After | Reduction | Peak RSS before → after |
|---|---:|---:|---:|---:|
| 4,314 fields, model-only warm median, incremental over PR46 | 2.3018 s | 1.8430 s | 19.9% | 311.77 → 280.24 MiB |
| 2 MiB indexed Hybrid, three isolated scans each, incremental over PR46 | 10.7818 s median | 10.3900 s median | 3.6% | 277.29 → 271.67 MiB maximum |
| 8 MiB indexed Hybrid, one isolated pair, **combined change versus main** | 42.2585 s | 38.3165 s | 9.3% | 318.56 → 301.75 MiB |

The 2 MiB sequence alternated A/B, B/A, A/B. Individual baseline times: 9.9105, 10.9270, 10.7818 s; candidate: 9.7403, 10.4522, 10.3900 s. The 8 MiB candidate ran first. One 8 MiB pair is not a statistical guarantee. Peak figures are process lifetime RSS; raw files also retain current RSS and CPU time. The 8 MiB scans averaged 1.61 versus 1.57 CPU cores consumed.

Scan wall time includes parsing, reconstruction, extraction, detection, SQLite indexing and atomic report publication. It excludes checkpoint loading, fixture generation/copy, post-scan report hashing and cleanup. Each indexed measurement used a fresh process/model. The separate model-only records distinguish first-call and three warm-call timings.

All accepted pairs preserve every ordered report event except exactly three clock fields: `metadata.generated_at`, `summary.processing_time_seconds`, `summary.ml_processing_time_seconds`. Confidence, findings, packet links, offsets, quality flags, coverage and capture identity remain in the comparison.

Eligible-field coverage is not proof of complete captured TCP sessions: the fixture's existing `tcp_capture_completeness: unknown` remains truthful and unchanged. Unicode field offsets are not reinterpreted as packet byte offsets.

| Fixture | Eligible / evaluated | Skipped | Actual model fields | Cache hits | Cache evictions |
|---|---:|---:|---:|---:|---:|
| 2 MiB | 22,088 / 22,088 | 0 | 5,717 | 16,371 | 0 |
| 8 MiB | 88,037 / 88,037 | 0 | 19,132 | 68,905 | 0 |

The 8 MiB report is 165,571,298 bytes and its SQLite index 277,028,864 bytes. Accounted prediction cache size is 15,139,785 bytes; that is not a process-RSS estimate. Its report digest is `712791cd7000346474852b3f1ba0851a12873c4b082062daf35fff4d2cca2b86`. Full capture identities and all repetitions are in the accompanying JSON. Cache reuse is workload-specific; no general cache speed multiplier is claimed.

## Where the work goes

Uninstrumented engine stage clocks from the 8 MiB pair, seconds:

| Stage | Main | Candidate |
|---|---:|---:|
| Packet read/decode/group | 1.881 | 2.036 |
| Session segmentation + TCP reconstruction | 1.361 | 1.368 |
| HTTP parsing + field extraction | 0.482 | 0.461 |
| Field-to-HTTP evidence | 4.080 | 4.603 |
| Rules | 0.734 | 0.712 |
| Model processing | 28.244 | 23.851 |
| Result aggregation | 2.076 | 2.153 |
| Final report write | 0.381 | 0.433 |
| SQLite observer, **already included in other stages** | 3.971 | 4.153 |

Stages do not partition all wall time and must not be summed with nested observers. Candidate runner bookkeeping, including cache operations **and finding reconstruction**, was 0.464 s; this is not pure cache latency.

The separate 256-field diagnostic found 10,843 nonempty character rows but only 409 distinct rows across six batches; 14,182 padded positions were allocated. Convolution module time fell from 34.2 to 4.0 ms, with 5.1 ms for the shared index plan. LSTM remained dominant: 212.2 versus 187.2 ms, without an LSTM implementation change. Single instrumented stage times are noisy (candidate tokenization had an outlier) and are not independent throughput estimates. Raw module timings, cProfile and bounded torch-profiler operator summaries are included.

The pipeline already reuses encoded JSON between spool and index, streams final output and commits index writes in groups of 1,000. This work does not rewrite those paths. Evidence generation and index insertion remain significant; their optimization requires separate provenance-equivalent validation. No evidence was omitted to obtain these numbers.

## Rejected/experimental paths

`exploratory-results.json` retains unsuccessful and preliminary results, not just winners.

- Per-member `torch.unique` sorting preserved scores but regressed 2 MiB scan median from 10.716 to 11.320 s. It was replaced with one shared batch-local hash/index plan.
- Equal-length dense LSTM: model-only improvement on the small probe, but raw-score drift up to `2.28e-7` and changed full report bytes in the scan. Not enabled.
- Splitting all batches into exact lengths plus dense LSTM: 11.413 s scan and about 350.6 MiB peak RSS; worse than the packed reference. Not enabled.
- Dynamic INT8: about 20.2% model-only reduction on the probe, **changed labels and threshold decisions**. Disqualified.
- `torch.compile(fullgraph=True)`: failed with `Unsupported`; no compilation performance result. This does not establish that every partial-compilation strategy is impossible.
- MPS: unavailable in this Linux build; no MPS or macOS result. CPU thread defaults were not retuned from Linux observations.

`experiment_v2_backends.py` is explicitly opt-in and never changes production settings or saves transformed checkpoints. Its exit status describes execution, while its JSON equivalence flags determine whether predictions changed. It is not an acceptance shortcut.

## Correctness and tests

The complete frozen validation/challenge sets plus fictional stress fields total 4,314 fields and 4,175 unthresholded spans. Local and CI comparisons have identical labels, spans, field order, configured threshold and **raw scores: maximum difference 0.0**. This is equivalence evidence, not uploaded-capture accuracy. Scores remain uncalibrated model scores. Frozen ground-truth annotations and the genuine evaluator were not changed.

Targeted tests cover exact row identity and inverse placement, odd/even convolution widths, empty rows, genuine model comparisons, untouched training gradients, no retained features after weight changes, one index plan per ensemble batch, SHA binding, full report identity, failure cleanup and rejection of incomplete coverage. The historical 110 MiB acceptance guard was observed failing when both supposedly complete runs agreed on the wrong eligible count, then passed after binding the known counters.

CI details and final exact tested SHA are recorded in `ci-verification.json`. The implementation commit's full core/ML, real Chromium, mentor evidence and genuine Hybrid jobs passed. Optional dependency skips are reported separately; optional TShark verification is blocked because it is not installed. The native M3 runner correctly refuses this Linux host before scanning.

Final [CI at `7e4fd27`](https://github.com/kotchadon/pcap-pii-engine/actions/runs/41431610468): core **919 passed / 177 skipped / 0 failed**; ML **1,137 passed / 21 skipped / 0 failed**; Chromium **18 passed / 0 skipped / 0 failed**; required mentor APIs and genuine V2 Hybrid smoke passed. The ML skips are 17 browser-dependency and four h11-dependency cases. Chromium uses actual browser journeys with synthetic fixtures; genuine model behavior is additionally checked in the separate ML and Hybrid jobs. Counts overlap across jobs and should not be added as unique tests.

## M3 feasibility and next gate

Owner baseline: 683.834 s total, 518.58 s model, leaving 165.254 s elsewhere. Holding that non-model cost fixed gives **budgets**, not predictions:

| Goal | Total budget | Required model budget | Model-time reduction required |
|---|---:|---:|---:|
| 30% faster | 478.684 s | 313.430 s | 39.56% |
| Five minutes | 300 s | 134.746 s | 74.02% |

The 150 MiB/300 s and 500 MiB/480 s goals require 0.50 and 1.04 MiB/s respectively, but file bytes do not determine inference work. No time extrapolation from these Linux fixtures is valid. Process parallelism has not been demonstrated beneficial or safe on the M3, so no extra workers were introduced.

The 500 MiB input fits only within the existing 512 MiB Stress input ceiling; it may still exceed 2 million packets, 300,000 flows, 480 MiB retained TCP payload, 2 GiB report, 4 million findings, 4 GiB process RSS or the job's disk admission budget. The much larger evidence/index footprint already measured on 8 MiB prevents any claim that 500 MiB is automatically feasible. The 15M profile increases permitted work, not these independent limits. No 5M–15M run or unified-memory/thermal acceptance was performed.

Before target approval, run on the actual MacBook Air M3 16 GB with both checkouts using the **same Python/PyTorch environment and two CPU threads**. Historical thread/PyTorch configuration was not independently supplied; establish a fresh paired baseline. Record power/thermal conditions and close competing workloads. The runner records chip, machine model, physical memory, versions, exact resource limits and checkpoint hashes.

```bash
git fetch origin pull/54/head:review/astra-v2-throughput-next
git worktree add ../trace-v2-before 50c3a1251995d7063f3b49a9354c71d4ff429504
git worktree add ../trace-v2-after review/astra-v2-throughput-next
cd ../trace-v2-after
# Use the project's existing Python environment with torch, psutil and ijson.
python scripts/validation/accept_apple_silicon.py --require-m3
python scripts/validation/accept_v2_m3_pair.py \
  --baseline-root ../trace-v2-before \
  --capture /absolute/path/trace_synthetic_110MiB.pcap \
  --expected-capture-sha256 42e52f7ebb470d45e3d883ba6c800a11fce17357cf0edad417fefb8ca059c9ce \
  --output-dir /absolute/path/trace-m3-paired-results \
  --threads 2 --repetitions 2 --ml-profile high_capacity
```

The paired command performs **four full scans**, alternating order. Run it only after bounded native acceptance succeeds. It rejects differing checkpoints/settings/reports, incomplete coverage and excessive RSS, and requires the historical capture's known counters, including 1,927,392 evaluated/eligible fields, zero skipped, 180,694 model findings and 244,046 rules findings. Output remains local. Exit zero means the comparison's correctness gates passed; inspect the explicit performance-target booleans before claiming the latency goal.

No changes to main or consumer UI are required to review this module. Keep PR54 draft until native correctness/resource/performance evidence is reviewed. Do not combine or merge PR46 and PR54 blindly: PR54 already contains PR46's implementation.
