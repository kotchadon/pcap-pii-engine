# Bounded large-capture rules analysis

Base: `19af7a5668e4b20ebd6cff1dfc87234bb2a58615` (main, including M3C and ML V2).
Scope: engine/CLI/reporting plus performance tests and validation tooling. The
capture decoder, HTTP parser, rules detector, ML artifacts, dashboard and hybrid
integration are unchanged. The engine now uses existing M3C session splitting
and safe-prefix reconstruction APIs; ambiguous overlaps are not exported as
complete HTTP evidence.

Measured results and evidence: [RESULTS.md](RESULTS.md). Dashboard integration:
[DASHBOARD_HANDOFF.md](DASHBOARD_HANDOFF.md).

## Profiles and limits

| Budget | Standard (default) | Large | Stress |
|---|---:|---:|---:|
| Capture MiB | 128 | 256 | 512 |
| Packets | 100,000 | 500,000 | 2,000,000 |
| Endpoint pairs and total sessions | 20,000 | 100,000 | 300,000 |
| Retained TCP payload MiB | 64 | 192 | 480 |
| Report MiB | 512 | 1,024 | 2,048 |
| Findings | 500,000 | 2,000,000 | 4,000,000 |
| Sampled process peak RSS MiB | 1,024 | 3,072 | 4,096 |

All limits must be positive integers. Overrides take precedence over the
selected profile. Configuration ceilings are 512 MiB capture/payload, 2 million
packets, 300,000 sessions, 2 GiB report, 4 million findings and 6 GiB sampled RSS.
There is no unlimited mode. File size alone does not predict whether a workload
fits: the generated ~256 MiB benchmark needs an explicit 240 MiB payload budget.
Standard's original four limits remain unchanged.

The capture guard uses file size; payload budget counts captured TCP payload,
including retransmissions. Endpoint-pair and session budgets both apply. Finding
and report limits fail explicitly instead of dropping rows. Existing HTTP field,
message and detection caps are surfaced as failures when their returned bounds
indicate possible truncation. Other unsupported/malformed HTTP parsing behavior
is unchanged; this does not certify all traffic as inspectable.

RSS is a sampled process-lifetime high-water guard (macOS bytes, Linux KiB), not a
hard allocation ceiling. Overshoot is possible between checks or inside one
parser/reassembly call. Run one scan per process for meaningful accounting. The
implementation targets POSIX macOS/Linux; native Windows is not validated.

## Implementation and tradeoffs

Packet metadata is stored as compact direction/time/sequence/flags/payload tuples;
endpoint strings are shared per pair. All records remain buffered until EOF,
then each endpoint group's retained data is released after it can be safely
sessionized. This avoids unsafe early flushing, but memory still grows with
capture payload/packet count under explicit budgets. There is no disk-backed TCP
reassembly, multiprocessing, GPU dependency or unbounded parallelism.

`analyze_to_report()` spools findings and flow summaries into private temporary
JSONL files, then incrementally writes the complete JSON report. Byte accounting
bounds both spools and final output. Atomic publication preserves the existing
report on failure, with no partial-success result. The compatible `analyze()` API
still returns lists and checks complete encoded output size; its memory use is
larger and its encoding budget does not predict a later caller's pretty-printing.
Use the streamed API for large inputs. CLI uses it automatically.

CPU profiling on a small sample identified rules detection as the largest cost;
that component is outside this change. The measured optimization reduces memory
and report bytes, with a modest runtime cost from spooling, guards and safe
session processing. `report_write` measures final JSON assembly; spool writes
are included in `result_aggregation`. Stage timings omit some orchestration and
provenance work; use wall time for end-to-end comparisons.

## Reproduce on an M3 Mac

Run from this branch using Python 3.10+; rules analysis needs no ML dependencies.
Use a private writable output directory and distinct filenames for each run.
No cloud service or paid training is involved.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e . pytest
mkdir -p local-performance

/usr/bin/time -l python scripts/validation/benchmark_engine.py \
  /path/to/trace_synthetic_110MiB.pcap local-performance/report-110.json \
  --profile large > local-performance/benchmark-110.json
python scripts/validation/verify_report.py local-performance/report-110.json \
  > local-performance/verification-110.json

# Direct CLI alternative (uses a different output name):
pcap-pii /path/to/trace_synthetic_110MiB.pcap --profile large \
  -o local-performance/cli-110.json

# Independent network-only measurement; rules/report/ML are excluded:
python scripts/validation/benchmark_capture.py \
  /path/to/trace_synthetic_110MiB.pcap --max-capture-mib 256 \
  --max-packets 500000 --max-flows 100000 --max-tcp-mib 192 \
  > local-performance/network-110.json
```

Only after the 110 MiB run completes within local memory/disk/time budgets:

```bash
python scripts/validation/generate_captures.py local-performance/generated-256.pcap \
  --size-mib 255.75 > local-performance/manifest-256.json
/usr/bin/time -l python scripts/validation/benchmark_engine.py \
  local-performance/generated-256.pcap local-performance/report-256.json \
  --profile large --max-tcp-mib 240 > local-performance/benchmark-256.json
python scripts/validation/verify_report.py local-performance/report-256.json \
  > local-performance/verification-256.json

# Optional next stage, only after the previous stage is safe:
python scripts/validation/generate_captures.py local-performance/generated-512.pcap \
  --size-mib 511.75 > local-performance/manifest-512.json
/usr/bin/time -l python scripts/validation/benchmark_engine.py \
  local-performance/generated-512.pcap local-performance/report-512.json \
  --profile stress > local-performance/benchmark-512.json
python scripts/validation/verify_report.py local-performance/report-512.json \
  > local-performance/verification-512.json
```

The generator completes a batch of 16 conversations, so output can slightly
exceed requested size. These targets leave headroom below hard 256/512 MiB
capture limits. Inspect manifest actual sizes, not filename labels. Generator
version/seed/wire algorithm are unchanged; only its maximum requested size was
raised from 300 to 512 MiB. Generated addresses and payloads are fictional.

The benchmark prints aggregate JSON only and includes rules and report writing.
Run verification separately: it loads complete JSON and its RSS must not be
attributed to the engine. Its masking checks cover structured finding values,
not a general proof of anonymization. Use valid JSON, accounting, expected
fixture counts, memory and wall time together; speed alone is insufficient.

## Validation and known blockers

Final full suite: **278 passed, 9 failed in 34.13 seconds**. Baseline: **257 passed,
9 failed in 26.66 seconds**. All 21 new performance tests pass. The same nine
pre-existing failures depend on unavailable `model.pt` artifacts or
`ml/datasets/v2/train.jsonl.gz`; the connector cannot materialize these binaries
in this environment. Their Git tree entries are preserved and no ML data/model
is regenerated, modified or claimed to have been evaluated here. See
`results/test-summary.json` for exact failing node IDs. Optional ML V2 inference,
full hybrid latency and GPU/MPS execution were **not measured**.

Tests cover profile validation/override precedence, old packet/flow boundaries,
report accounting, private permissions, explicit finding/output/RSS failure,
atomic preservation under callback cancellation and disk failure, reused tuples,
unsafe overlap, malformed records and unchanged decompression bounds. A mocked
129 MiB stat tests the former input-size boundary without a large allocation;
actual ~256/~512 MiB captures separately exercise real file processing. The
memory-failure test injects a measured high-water reading; it does not induce an
OS OOM. Review found two issues (full materialized report-byte accounting and
post-publication callback errors); both are fixed with regression tests and the
reviewer confirmed the fixes.

Re-run the relevant suite on a complete checkout, including authentic binaries:

```bash
python -m pip install pytest
python -m pytest -q tests/test_large_capture_performance.py
# With the project's ML dependencies and checked-in artifacts available:
python -m pytest -q
```

Existing incomplete/unsupported protocol limitations remain: no TLS decryption,
HTTP/2, HTTP/3 or IP-fragment reconstruction. No SYN/FIN means unobserved coverage
is unknown, even when observed bytes contain no gap. `analysis_incomplete=false`
means no observed capture/TCP damage, not proof of full real-world capture or
complete PII recall. Findings remain rule candidates with heuristic confidence;
network throughput and synthetic corpus success do not establish ML accuracy.

No 1 GiB validation or support claim is made. The 512 MiB configuration ceiling
is deliberate. The measured memory headroom applies to the listed workloads and
Linux runtime, not all adversarial captures or multiple simultaneous jobs.

## Baseline reproduction

The before measurement used the base commit above with `analyze()` followed by
`write_private_report()`, raised input budgets and default pretty JSON. It ran
in a fresh process with a 3 GiB Linux address-space ceiling and a 180-second
external timeout. To reproduce independently, create a separate checkout at
that commit and run this code with `PYTHONPATH=src`, capture and output as args:

```python
import json, resource, sys, time
from pathlib import Path
from packet_pii.engine import analyze, AnalysisLimits
from packet_pii.reporting import write_private_report

capture, output = map(Path, sys.argv[1:3])
limits = AnalysisLimits(max_capture_bytes=256*2**20, max_packets=500000,
                        max_flows=100000, max_tcp_payload_bytes=192*2**20)
start = time.perf_counter()
report = analyze(capture, limits=limits)
analysed = time.perf_counter()
write_private_report(report, output)
end = time.perf_counter()
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps(dict(wall_seconds=end-start, analysis_seconds=analysed-start,
    write_seconds=end-analysed,
    peak_rss_mib=peak/(2**20 if sys.platform == 'darwin' else 1024),
    report_bytes=output.stat().st_size, summary=report['summary'])))
```

Keep baseline and new runs in separate processes and verify both complete
reports. Do not compare the network-only tool to the full engine as though they
measure the same work. No repeated timing distribution was collected; the
published timings are single-run observations, not statistical speed guarantees.
