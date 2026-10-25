# TRACE performance and memory engineering — 25 October 2026

**NOT READY TO MERGE.** Linux implementation and scoped evidence are available;
frozen-model and native Apple Silicon acceptance remain gates. No M3 result,
accuracy claim, or 1 GiB latency promise follows from these measurements.

## A. Baseline and diagnosis

- Integrated main inspected and rechecked: `4c9ac080e309ccc21a127c3e1e5e1422ccc4fa1c`;
  tree `39fa0d6f470719fc29f0fffd5266d0698ff8fdba`.
- PR #32 reference: `79995e65a4006fd680a2a00d43fc4126dda7a068`.
- Branch: `feature/trace-astra-performance-memory-v3`. No changes to main,
  PR #32, earlier HTTP branches, frontend, frozen weights, datasets or thresholds.
- Confirmed: main checks process-lifetime `ru_maxrss` alone. A released 128 MiB
  mmap allocation followed by a 2 MiB Rules scan under an explicit 96 MiB test
  limit failed on main; candidate completed with current RSS 27.4 MiB despite
  the 145.6 MiB historical peak. This lower test limit reproduces the mechanism;
  ordinary Standard scans still use the unchanged 1 GiB limit.
- Confirmed: outer ML admission could enqueue a whole message and drain several
  batches without rechecking elapsed model time. One synthetic slow call now
  stops later admission with explicit `time_budget` dispositions.
- Confirmed: entry-count-only cache bounds do not bound retained prediction size.
- Confirmed: padded character rows and copied convolution intermediates add
  avoidable tensor work. Random-network measurements below isolate this effect.
- Confirmed: each indexed row was JSON-encoded twice, once by the spool and once
  by SQLite insertion. Reusing the first encoding removes redundant work.
- Profiling a fictional 2 MiB Rules scan attributed 5.41 instrumented seconds to
  field source evidence, 4.36 to spooling, 3.17 to packet ingestion, and 1.30 to
  dataclass replacement (overlapping cumulative times, **not additive**).
  cProfile + tracemalloc raised wall time from 1.71 to 29.64 seconds; that run is
  diagnostic only. The recorded Python-heap peak also includes post-scan JSON
  comparison, so it is not a scan-only allocation bound.
- Still unproven: the owner's macOS 1,209 MiB incident may also involve native
  tensor/allocator retention or concurrency. Correct accounting does not make
  genuine retained RSS disappear. No claim that this incident is fully resolved.

## B. Implementation and tradeoffs

`memory.py` declares Mach's packed 48-byte `MACH_TASK_BASIC_INFO` layout,
12 32-bit words, fixed-width ctypes arguments and checked return/count fields.
Linux reads `/proc/self/statm`. `engine.py` checks current process RSS and new
lifetime peaks relative to scan entry. Unreadable current RSS with an excessive
historical peak fails closed; when the lifetime peak is below budget it remains
a conservative fallback. Guards also run after in-memory report traversal and
immediately before atomic disk publication.

This measures absolute process RSS, including loaded models and other threads;
it is neither scan-attributable memory nor macOS physical footprint. It is a
sampled guard, not an OS reservation. A transient spike below a previous lifetime
maximum may escape between samples. Dashboard jobs retain their existing scan
lock; unrelated concurrent activity may still cause a legitimate rejection.

`ml/bilstm.py` bounds default padded work at 4,096 positions, retains outer
256-field batches, and uses the unchanged dense character calculation when
gradients are enabled. Inference omits empty character rows and avoids two
intermediate copies. The dense probe trades 1.7% runtime for about 30% less peak
memory. No MPS/backend/thread default or model training change is made.

`ml_runner.py` admits at most one bounded batch before checking elapsed time;
a sentinel prevents premature publication of a partially admitted message.
The LRU has a 16 MiB conservative retained-Python-object cap plus its existing
entry cap. This is not allocator/RSS accounting. Keys combine BLAKE2b and an
independent SHA-256 verifier, retaining no raw input. A forced primary collision
is tested; dual cryptographic collision remains theoretically possible. Cache
lifetime remains one runner with one fixed detector configuration; per-occurrence
field IDs, quality flags and evidence are reconstructed normally. Mutating a
detector's configuration during a scan is unsupported.

Selectively adapted from PR #32: slotted packet/source records, direct immutable
clones, combined source clipping/rebasing, folded checksum arithmetic, raw address
reuse, a JSON-key fast path and a reusable spool encoder. Pair interning now uses
the retained canonical pair. Tests compare every copied field and independently
fold checksum words, including zero, odd-length and maximum-size inputs.

The independent indexed-report optimization adds optional
`encoded_row_observer(kind, row, json_text)` to `analyze_to_report`/`ReportSpool`.
`jobs.py` inserts that exact validated JSON into SQLite. Existing `row_observer`
callbacks still work. Observers must not mutate rows. All byte limits, private
temporary-file handling, cancellation propagation and atomic publication remain.
No evidence suppression, report schema migration or report-size reduction is
claimed. HTTP field Unicode offsets are still distinct from source byte ranges.

## C. Controlled measurements

Linux x86_64, Python 3.12.14, torch 2.6.0+cpu where used. Fresh worker processes;
2 MiB repeated scans run twice in the same worker. Rules include full observed
field/evidence coverage; ML is explicitly **not requested** in those rows.
All captures are deterministic fictional inputs. Times include final atomic
report writing; indexed rows also include the actual JobManager and SQLite.
Single-run differences are evidence for these fixtures, not population estimates.

| Workload | Main seconds | Candidate seconds | Change | Current RSS MiB main→candidate | Peak RSS MiB main→candidate |
|---|---:|---:|---:|---:|---:|
| 2 MiB Standard Rules, cold | 1.670 | 1.510 | 9.6% faster | 29.8→28.0 | 29.6→27.9 |
| Same process, second Rules scan | 1.742 | 1.615 | 7.3% faster | 30.2→28.4 | 30.0→28.4 |
| 8 MiB Standard Rules | 6.508 | 5.992 | 7.9% faster | 64.8→54.1 | 67.5→54.0 |
| 2 MiB Standard Rules + SQLite | 2.628 | 2.240 | 14.8% faster | 35.7→31.3 | 35.5→31.0 |
| Random weights, one V2 member's dimensions, dense forward median | 0.14130 | 0.14364 | 1.7% slower | 339.2→240.3 | 428.9→301.2 |

Rules model time is zero. The last row is **not genuine V2 inference** and has
no detection-accuracy interpretation. A separate three-kernel random network
showed 1.263× dense and 8.339× highly padded forward speedups; its padding-heavy
case is not a capture-throughput estimate. Maximum logit drift was zero there
and `5.96e-08` for the V2-dimension random probe. Existing real-model tests use
`1e-5` score tolerance while separately requiring exact labels, spans, field
association and threshold inclusion; this tolerance is not permission for
semantic changes. The new real-weight test also selects the preserved dense
character path, rather than comparing two optimized forwards.

The first indexed candidate, before encoding reuse, took 2.659 seconds (1.2%
slower than main). That unsuccessful intermediate result is retained in the
artifact. Reuse reduced index-observer time from main's 0.904 to 0.664 seconds.
Observer time overlaps other stages and must not be summed again. SQLite bytes
remained 50,294,784. Report size remained about 30.2 MB for 2 MiB and 120.8 MB
for 8 MiB; one-byte variations are elapsed-time formatting only.

8 MiB candidate stage seconds: read/decode/group 1.261; session split 0.078;
reassembly 0.605; HTTP parse 0.120; field extraction 0.238; field/HTTP evidence
1.851; rules 0.656; aggregation 0.319; final write 0.264. Other evidence/spooling
and orchestration explain the remaining wall time. Reading/decoding/grouping
are combined counters; genuine model loading/tokenization/forward/postprocessing
remain unmeasured locally. No 52 MiB rerun was justified without actual weights.

## D. Correctness and privacy evidence

Full parsed reports match after removing **only** `metadata.generated_at` and
the two summary elapsed-time fields. The 2 MiB canonical digest is
`000c5bb388c8432a0154cec7bbd6a5118e93037e371d2823ea0d135c6812be0b`;
the 8 MiB digest is
`d082a564c4aab8170507b254a5f8fd043580be897aedf38d7cad9e1ede614147`.
This compares ordered findings, all evidence arrays, capture SHA-256, linkage,
quality/completeness and counts, not merely finding totals. At 8 MiB both scans
decoded 53,099 packets, extracted 114,341 fields and emitted 17,536 rule findings.
The frozen ground-truth capture was regenerated with its committed manifest and
SHA verified byte-for-byte; labels and evaluator were not modified.

The benchmark initially loaded comparison JSON inside its worker, inflating
post-scan RSS. Controlled/repeated results use a separate digest subprocess.
Do not interpret the original diagnostic heap/post-comparison RSS as retention
by the engine. In this runtime PID namespaces also differ: `os.getpid()` did not
identify `/proc/self`; psutil therefore read another Linux process. Linux
measurements use `/proc/self`, cross-checked with `/proc/self/status` instead.

## E. Validation and reproducibility

Executed before publication: 125 focused tests passed (one genuine-V2 test
deselected and disclosed); after the indexing change, 54 targeted integration
tests passed. The final new memory/tensor/cache/packet/spool set passed 24 tests.
These sets overlap and **must not be added**.

The initial complete configured suite executed with torch: **951 passed,
16 skipped, 22 failed, 92 errors** in 67.9 seconds. All 114 unsuccessful cases
were traced to unavailable binary artifacts: 112 checkpoint dependencies and
2 compressed frozen dataset dependencies. No failing test was removed or
reclassified as passed. The final committed-SHA suite/CI result is recorded in
the PR; this initial run is not a substitute for that gate. Browser engine tests
remain blocked by the unavailable working browser runtime. Native acceptance
was invoked here and correctly exited nonzero for non-arm64-macOS.

Reproduce from separate main/candidate checkouts with installed core dependencies:

```sh
python scripts/validation/bench_performance_memory.py --source-root /path/to/main --capture /tmp/fictional2.pcap --output /tmp/main2.json --repeat 2
python scripts/validation/bench_performance_memory.py --source-root . --capture /tmp/fictional2.pcap --output /tmp/candidate2.json --repeat 2
# Add --indexed for real SQLite job handling; --mib 8 with a new capture for medium Rules.
# Add --historical-peak for the explicit 96 MiB historical-peak reproduction.
# Genuine Hybrid: --checkpoint src/packet_pii/ml/artifacts/bilstm_v2 [--no-cache]
OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 python -m pytest -q
```

Outputs must not already exist. The benchmark records failed scans rather than
treating their runtime as success; inspect `runs[].status` and completeness.
Random probes run with `PYTHONPATH=/path/to/checkout/src` from that checkout;
`ml_v2_config_probe.py /tmp/random-logits` emits a comparison tensor and JSON
to stdout. It does not write into any checkpoint directory. Machine-readable
inputs, measurements and diagnostic profiles are in
`2026-10-25-measurements.json` beside this report.

## F. Platform gates

Linux algorithm/core results are measured; native Mach/MPS and exact M3 are not.
Apple's ABI reference is `apple-oss-distributions/xnu`,
`osfmk/mach/task_info.h` (`#pragma pack(push,4)`, flavor 20). Struct/mock tests
do not replace native verification. The manual `apple-memory.yml` job uses
`macos-14` ARM/M1, not M3. GitHub's runner/billing documentation was checked:
standard private macOS ARM runners have 3 M1 cores/7 GB; published standard
macOS pricing was $0.062/min after applicable allowance. This repository's
remaining allowance is unknown. **No macOS run was dispatched.** The workflow
requires an explicit cost acknowledgement and has a 20-minute timeout.

```sh
python -m pip install -e '.[ml,http2]' pytest psutil
python scripts/validation/accept_apple_silicon.py --require-m3
```

The script checks platform, independent RSS, frozen weights/threshold, actual
V2 equivalence tests, cancellation/source integration, repeated Standard Rules
and Hybrid scans with/without cache, and historical-peak recovery. Missing
requirements, test skips, failed/partial scans or resource violations exit
nonzero. It is scoped acceptance, not a worst-case guarantee. MPS remains
unevaluated and is not enabled.

## G–I. Feasibility, remaining gates and recommendation

1 GiB in 120–180 seconds requires 8.53–5.69 MiB/s including requested inference
and reporting. The 8 MiB Rules engine result is about 1.34 MiB/s (4.3–6.4× below
that target), excluding SQLite and all ML. The 2 MiB indexed Rules result is
0.893 MiB/s (6.4–9.6× below target). These are Linux fixture ratios, **not linear
M3 predictions**. Earlier supplied 52 MiB cached Linux Hybrid numbers were about
0.089 MiB/s, roughly 64–96× below target; no direct speedup comparison is valid
across those environments/coverage configurations.

For a hypothetical fixture with the observed 14.4× report amplification,
1 GiB would imply about 14.4 GiB of JSON before indexes/spools. This is an I/O
planning scenario, not a measured 1 GiB report. Existing disk/report/capture
limits may reject it before completion. Existing lossless gzip helps storage,
but does not remove parse/index cost or enlarge permitted report budgets.

Process isolation is deferred: it can reclaim native allocations at exit, but
model load, spawn/IPC, private-file cleanup and cancellation need real platform
measurement. Multiple processes can multiply the three-model working set and
packet/index buffers. Sixteen GB unified memory must also serve macOS and other
applications; available bytes cannot be inferred from nominal capacity.
Flow-oriented processing needs invariants for retransmissions, session splitting,
late packets and source identity before a rewrite. No candidate filtering was
introduced. Any future filtering must report explicit partial ML coverage.

Outstanding acceptance gates: final full-suite/remote ML CI evidence with all
artifacts; actual V2 labels/spans/threshold equivalence and cache workload timing;
native Mach/Apple Silicon execution; exact M3 cold/warm/retained-memory behavior;
browser integration execution. Remaining source/API functionality is preserved,
but these unexecuted gates prohibit production acceptance. Publish as a draft,
retain the worktree, do not merge.

Workflow rulings: the owner's explicit draft-PR authorization supersedes the
Superpowers completion menu; report environmental failures instead of waiting
for approval to prepare a reviewable draft. Full suites run at significant
milestones/final committed source, not after every tiny edit. Reviewer found one
in-memory report guard gap; its red→green regression and fix are included.

## CI follow-up on initial published commit 25f39d8

GitHub executed the complete suite with genuine repository weights and datasets:
core **859 passed / 170 skipped**; ML **1,060 passed / 22 skipped / 2 failed**.
The newly added dense-versus-compacted real-V2 equivalence test passed. The two
failures were stale integration assertions, independently reproduced on unchanged
main: a valid HTTP/2 control-only connection is supported when HPACK is present,
and finding records now require the existing `evidence` member. Production
outputs were not changed to satisfy those assertions.

The follow-up tests preserve exact top-level finding keys, additionally verify
field-ID/message joins and decoded-versus-raw span semantics, and cover HTTP/2
with and without HPACK in Rules and genuine Hybrid modes. An independent Rules
provenance test runs without ML. Local available paths:3 passed,2 genuine-weight
skips,72 deselected. Astra reviewed this delta and found no weakened coverage.
The final PR status records the subsequent complete-suite result.

CI now installs CPU-only torch (the first ML run unnecessarily downloaded CUDA
packages), reports skip reasons, and coalesces push/PR runs for the same branch.
The original failed run is retained as evidence; it was not relabelled a pass.
