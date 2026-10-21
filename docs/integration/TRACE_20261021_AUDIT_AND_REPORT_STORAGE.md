# TRACE integration audit and lossless report storage — 21 October 2026

Status: independent draft change; **not approval of PR #28 + #29**. No model,
threshold, dataset, evaluator, reconstruction or inference implementation changed.

## Exact scope and source provenance

| Inspected remote | Commit |
|---|---|
| main | `11d41e8c583231edd86b621d96cc037fe676108f` |
| PR #28 `feature/trace-final-integration-20261021` | `5d792bd95ee998039a7651fda5ea6fec081a24c2` |
| PR #29 `feature/trace-v2-inference-acceleration` | `88c9ceaba346b8d589339ccff843acfb7f37271b` |

This branch starts at the exact PR #28 commit, tree
`a13991cf4adfcf7a2c3239aead7949be692dc9d0`. Every fetched changed blob and the
assembled base tree matched GitHub hashes. All ten PR #29 patches passed a
combined `git apply --check` against that tree. This establishes textual
compatibility, not runtime qualification. PR #29 was not applied to this branch.

Remote #29 already contains the SharedDetector regression guard, real-V2
duplicate-quality/eviction test, and report-to-disk/SharedDetector benchmark
modes. PR #28's `ml_runner.SharedDetector` still does not forward the cache
opt-in; #29 does not supply that forwarding fix. This is **Claude-owned**, not a
new finding or a fix in this PR. His memory matrix was not repeated.

The committed 52 MiB benchmark records candidate
`193cfed9c34d23432f2ecc9455709c34712dde10`, not the inspected #29 head. Its measured
numbers must retain that attribution; they do not certify the current combined
tree. No assertion is made about unpushed local commits.

## Additional audit findings

1. **Assessment workload is underreported.** In PR #28 `quality.py`, stability
   evaluation at line 528 discards its runner; lines 577–578 report only the
   main-probe runner. A checkpoint-free empty detector made **2 calls, while
   workload.batches reported 1** (16 main probes + 9 variants). The second
   `_predict` also receives a fresh full time allowance. Correct by accounting
   for both runners and passing a remaining allowance; `_predict` currently
   treats a zero allowance as a request for the default through `or`. The time
   allowance issue is source-verified, not a measured timeout overrun. No fix to
   this separately owned assessment module is included.
2. **PR #29 changes time-budget semantics.** Its `_run` timer includes hashing,
   cache lookup and validation even for cache-only batches, whereas
   `MLWorkBudget.max_seconds` promises cumulative model time. Field/character
   admission limits remain unchanged. Separate model-call time and runner time,
   or explicitly revise the accounting contract before acceptance. The engine
   comment “unique neural evaluations” is also inaccurate: eviction can cause
   the same input to be inferred again; the counter measures executions.

Reproduce finding 1 on PR #28 without a checkpoint:

```python
from packet_pii.quality import AssessmentBudget, ContextSampler, assess_summary
class Detector:
    model_version = 'audit-empty-stub'
    calls = 0
    def predict_fields(self, fields):
        self.calls += 1
        return []
s = ContextSampler()
s.observe_message({'message_type': 'request',
                   'fields': [('json_body.author', 'Aa Bb')],
                   'http': {'method': 'POST', 'content_type': 'application/json',
                            'content_encoding': None, 'transfer_encoding': None}})
d = Detector()
r = assess_summary(d, s.summary(), AssessmentBudget(
    max_strata=1, stability_probes=3, bootstrap_rounds=1))
print(d.calls, r['workload']['batches'])  # 2 1; a stub accounting check, not accuracy
```

By code inspection, cache state belongs to each runner; cached spans are rebound
to each occurrence's ticket, field index, text and quality flags. Admission still
charges repeated fields and characters. Fresh results are validated before
findings are appended, and checkpoints bracket cache-only as well as model
batches. Failed analysis does not reach report publication. No additional cache
provenance defect was confirmed. Cancellation remains cooperative at batch
boundaries, not a hard interrupt of a running model call or lock wait.

Bucketed float32 computations can differ slightly. Existing tests distinguish
exact labels, spans, association and threshold inclusion from tolerated score
rounding. This is empirical equivalence on tested inputs, not a universal proof
at decoding ties/thresholds. Cached results retain the first threshold decision.
Genuine V2 tests are present remotely but **blocked locally by missing weights**;
stub checks and synthetic probe F1 are not capture ground-truth accuracy.

## Storage bottleneck and implemented change

The earlier 110 MiB rules-only measurement produced 1,524,402,434 report bytes
in 138.979 s, versus the older findings-only 124,633,629 bytes in 43.994 s.
It contains 2,349,009 field evidence rows. Repeated JSON keys, field/message/stream
IDs and source descriptors dominate storage. An earlier medium breakdown put
field evidence at approximately 56% of the output. Source intervals are already
separate stream rows, but transformed field dependencies remain repeated.

This change adds **opt-in `.json.gz` output**, using streaming gzip level 1 with
no timestamp or filename in the gzip header. Expanded JSON and its schema remain
unchanged; no IDs, intervals, limitations or evidence arrays are removed. The
default `.json` path is unchanged. Only `reporting.py` and CLI help change in
production code. Existing authenticated Inspector/SQLite paths remain unchanged.

`max_report_bytes` still bounds **expanded UTF-8 JSON**, including existing
spool accounting. Compression does not authorize a larger analysis. Private
0600 temporary files, exclusive publication, symlink handling, explicit atomic
replacement and cleanup remain. The gzip trailer is closed and the raw file
flushed/fsynced before publication. `receipt.output_bytes` is the physical file
size. Compression is not encryption; existing include-values/masking behavior
still governs privacy. Plain JSON consumers must explicitly decompress gzip.

### Measured small experiment

One fresh Linux process per format; rules only; synthetic input 5,414,662 bytes,
SHA-256 `5fb4520536b296204b2090aef13c2d3d2b3129ecba1133773eec9b9333c9f882`.
Machine details, source hashes, stages and full counters are in
[`results/report_storage_20261021.json`](results/report_storage_20261021.json).

| Metric | JSON | JSON + gzip level 1 |
|---|---:|---:|
| Report bytes | 25,520,541 | 1,863,791 |
| End-to-end seconds | 3.625 | 6.979 |
| Final report write seconds | 0.111 | 0.175 |
| Peak process RSS MiB | 30.344 | 30.355 |

**92.697% smaller physical report; no demonstrated runtime or memory improvement.**
The unmodified read/reconstruction/rule stages also ran slower in the second
process, so this uncontrolled pair cannot isolate compression's end-to-end cost.
No timing repetitions or large competing benchmark were run.

Streaming comparison hashes every ordered JSON event, excluding only
`summary.processing_time_seconds`. Both hashes are
`aff83b814bde5482a1f81f25ec2860be4189a428a56c1dae7cbd176b9036e7e0`.
All 368 flows, 1,986 findings, 7,822 packet rows, 6,166 stream rows, 7,944 HTTP
rows and 33,762 field rows match, as do all remaining non-runtime content.
No evidence identity, linkage, completeness statement or offset changed.

This does **not** reduce the expanded temporary JSONL spool, per-row encoding,
SQLite copy or indexes, and does not solve PR #29 RSS. Follow-on design options:

- Add a versioned relational evidence codec that interns identical immutable
  source descriptors, while retaining each occurrence ID and field index. Use
  full equality to resolve hash collisions and bounded/disk-backed tables.
  Expand through a common reader before existing consumers; verify ordered
  round trips including exact, transformed, partial and unknown ranges.
- Let the private index reuse the already serialized spool row via an internal
  observer protocol. Today `jobs.py` encodes the same row again, and expression
  indexes parse it again. Coordinate this change with the integration owner.
- An offset index into one canonical evidence store could avoid the second full
  SQLite JSON copy, but requires coordinated reader/authentication and atomic
  lifecycle changes. Gzip itself does not provide efficient random row lookup.

These are proposals, not implemented or benchmarked savings. Decoded Unicode
character offsets must never become inferred original packet byte offsets.

## 1 GiB on MacBook Air M3 / 16 GB

**Currently unsupported by configuration:** PR #28 caps capture size at 512 MiB,
TCP retained payload at 512 MiB, reports at 2 GiB and ML eligible fields at five
million. No ceiling was changed. Raising only the input limit would be unsafe.

The target is 1024/180–1024/120 = **5.689–8.533 MiB/s**. The cited Linux cached
52 MiB run delivered 0.0890 MiB/s: a **63.9–95.9× throughput gap**, not a Mac
prediction. Its 522.85 s reported model/runner time and 61.29 s other time are
from a different workload/path than the comprehensive 110 MiB evidence scan;
those measurements cannot be added together to predict M3 runtime.

| Component | Available evidence | What is still needed |
|---|---|---|
| Parsing, TCP grouping/reassembly | Earlier 110 MiB Linux: read/decode/group 25.119 s, session 1.065 s, reassembly 10.723 s | M3 measurement; read phase already includes packet evidence work |
| HTTP extraction + rules | Same run: HTTP 2.101 s, extraction 5.331 s, rules 17.701 s | Same-capture M3 rules baseline and attribution |
| Genuine V2 | 52 MiB Linux: baseline 1052.57 s model time, bucketed 612.48 s, cached 522.85 s reported model/runner time | Exact integrated head, checkpoint hashes, cache safety, output and threshold comparisons on M3 |
| Evidence/serialization | 110 MiB final write 9.687 s; 59.491 s outside listed stage timers | Separate evidence construction, encoding, spool and SQLite timers; no attribution of all residual time to one cause |
| Memory | Linux cached peak 1918.5 MiB, unresolved growth; comprehensive rules run 414.1 MiB | M3 process and whole-system peak/unified-memory pressure under integrated full report path |

Conditional workload-density calculations expose capacity constraints, not
runtime predictions. At 52 MiB's 570,424 eligible fields, 1 GiB would contain
about 11.23 million: the named complete profile's one-million-field budget would
admit at most 8.9%, and the five-million absolute ceiling at most 44.5%, before
time/character limits. “Complete” profile naming does not prove complete coverage.
At the 110 MiB evidence density, expanded output would be about 13.22 GiB for a
1 GiB input, beyond the 2 GiB report ceiling. The medium gzip ratio cannot be
assumed for that different workload or used to bypass the logical byte limit.

Process parallelism needs independent flow/session ownership, globally stable
IDs, bounded queues, deterministic merging and atomic publication. It also
duplicates model/cache/interpreter state; four copies of the observed 1918.5 MiB
Linux peak alone would be about 7.5 GiB, before coordinator, OS, browser and other
unified-memory consumers. That is a cautionary arithmetic example, not an M3
memory forecast. Benchmark a small worker count with thread oversubscription
controlled; no parallel speedup is established here. Bucketing already has
Linux evidence, but cache RSS remains unresolved. Candidate filtering must
record policy exclusions and skips and be labelled partial ML coverage; it
cannot substantiate a full-analysis 2–3-minute claim.

## Reproduction and acceptance gates

Use the existing generator with `--size-mib 5 --seed 20261014` and verify the
input SHA above. Run each output in a fresh process and directory:

```sh
python scripts/validation/benchmark_engine.py moderate.pcap medium.json > plain-measurement.json
python scripts/validation/benchmark_engine.py moderate.pcap medium.json.gz > gzip-measurement.json
# Install ijson in the local validation environment if absent; never upload captures.
python scripts/validation/compare_report_storage.py medium.json medium.json.gz
python -m pytest -q tests/test_report_compression.py tests/test_reporting_security.py tests/test_network_evidence_integration.py tests/test_evidence_inspector_ui.py
```

CLI integration: `python -m packet_pii.cli capture.pcap -o report.json.gz`.
Python integration: existing `analyze_to_report(capture, 'report.json.gz', ...)`.
Read with `gzip.open(path, 'rt', encoding='utf-8')`; use streaming parsing for
large reports. Dashboard reports remain plain JSON with authenticated indexed
lookups. No frontend or job-index migration is required.

Targeted result: **37 passed in 1.24 s**. Tests cover lossless UTF-8/unknown-range
storage, deterministic headers, masking, capture SHA verification, private
permissions, logical limits, serialization/trailer/fsync failure, symlinks,
cancelled row sources, existing provenance integration and Inspector contracts.
This is not a full-suite or browser acceptance claim. Frozen ground truth,
checkpoint, thresholds and genuine evaluator were not edited.

Before approving integration: publish/verify Claude's forwarding fix; resolve
and measure cache memory growth; repair assessment accounting and settle runner
time semantics; run genuine V2 + frozen independent ground-truth gates at the
exact combined head; perform M3 integrated report/Inspector validation. The
512 MiB input ceiling and larger-workload evidence/ML capacity need a separate
bounded architecture change before any 1 GiB performance commitment.
