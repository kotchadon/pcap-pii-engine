# Measured large-capture results

All runs below are **single observations on Linux x86_64, Python 3.12.14**.
They are not M3 Mac measurements. Full-engine rows include rules detection and
complete report writing; none includes ML. Baseline commit is
`19af7a5668e4b20ebd6cff1dfc87234bb2a58615`. Implementation is the first two feature
commits; subsequent changes only document the results. No paid compute was used.

| Workload | Capture MiB | Packets | Sessions | HTTP messages | Findings | Wall seconds | Peak RSS MiB | Report bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Exact user capture, baseline materialized | 110.0003 | 361,389 | 60,232 | 120,462 | 244,046 | 29.988 | 475.781 | 163,104,108 |
| Exact user capture, streamed Large | 110.0003 | 361,389 | 60,232 | 120,462 | 244,046 | 35.265 | 189.176 | 121,439,970 |
| Generated ~256, Large + 240 MiB TCP override | 255.8015 | 386,842 | 18,160 | 392,256 | 98,064 | 44.676 | 337.098 | 47,454,999 |
| Generated ~512, Stress | 511.9342 | 773,910 | 36,320 | 784,512 | 196,128 | 83.508 | 659.211 | 95,137,715 |

Exact-user comparison: **60.2% lower peak RSS**, **17.6% longer wall time**, and
**25.5% fewer report bytes** (compact whitespace, identical finding/flow content).
This is a memory/reporting improvement, not a speedup claim. All complete reports
passed separate-process JSON parsing, array/summary accounting and masked-value
checks. They have no observed capture corruption, stream gaps or orphan messages.

The user's capture has **60,231 HTTP conversations plus one non-HTTP endpoint
pair**, explaining 60,232 total flows. All 244,046 findings match baseline:
60,231 each EMAIL, PHONE, USERNAME and PERSON_NAME_CANDIDATE, plus 3,122 CREDIT_CARD.
Canonical SHA256 over every ordered flow/finding row, including provenance:
`1b8b48583e874d1d30f1e7098b6e4aecfb29260e24e49f04dc8d9a956bf0599a` in both reports.
No rows were sampled or silently dropped. Timing/metadata are excluded from this
digest; the full report includes new profile/resource metadata.

Input identity: `trace_synthetic_110MiB.pcap`, **115343298 bytes**, SHA256
`42e52f7ebb470d45e3d883ba6c800a11fce17357cf0edad417fefb8ca059c9ce`.
An independent dpkt scan counted 361,389 records, 60,232 endpoint pairs,
90,046,044 TCP payload bytes, 60,231 POST starts and 60,231 response starts.
The capture has no FIN packets. Network-only reassembly reports 120,463
`final_coverage_unknown` directions and one `initial_coverage_unknown`; these
are uncertainty about uncaptured lifecycle boundaries, not observed byte gaps.

The independent generator's expected packet/flow/message counts match both
larger reports. It includes mixed HTTP/non-HTTP traffic, segmented/interleaved
connections, out-of-order segments, exact retransmissions, sequence wraparound,
keep-alive, JSON/form bodies, chunking and gzip responses. It is synthetic and
is not representative of every real capture or every PII category. Its manifests
record actual byte sizes, seed 20261014, generator version and SHA256. Targets
255.75 and 511.75 MiB produce complete batches below the profile file-size caps.

## Stage timing (seconds)

| Stage | Exact 110 | Generated ~256 | Generated ~512 |
|---|---:|---:|---:|
| Read/decode/group | 2.906 | 2.945 | 5.942 |
| Session segmentation | 1.006 | 0.770 | 1.439 |
| Reassembly | 1.240 | 0.955 | 1.758 |
| HTTP parsing | 1.950 | 4.031 | 7.394 |
| Field extraction | 3.356 | 4.359 | 7.899 |
| Rules detection | 17.736 | 25.748 | 48.492 |
| Result aggregation, including spooling | 4.935 | 2.552 | 4.542 |
| Final report assembly/write | 0.304 | 0.155 | 0.208 |

These named timers exclude some provenance/correlation/orchestration overhead;
they should not be summed as the full runtime. Throughput including rules and
report writing: **3.119, 5.726 and 6.130 MiB/s**, respectively. This does not imply
larger captures always improve throughput: their content differs.

Separately, the unchanged network-only benchmark processed the exact capture in
**8.057 seconds, 256.699 MiB peak RSS, 13.653 MiB/s**, with 120,462 messages and
no unsafe direction. It excludes rules, reporting and ML, and uses the previous
packet-object retention strategy; do not compare it as an equivalent end-to-end
pipeline. Complete measured JSON is under `results/`. Only local capture paths
were shortened to basenames for committed metadata; numerical values are intact.
Captures and detailed reports are intentionally not committed.

## Readiness and remaining validation

- Full rules-engine completion is demonstrated for these exact 110/~256/~512 MiB
  PCAP workloads, under configured resource limits and well below 4 GiB RSS.
- PCAPNG remains covered by the existing regression suite; no equally large
  PCAPNG performance measurement was run.
- M3 Mac wall time/RSS still requires the documented local commands. No Mac,
  dashboard-upload, hybrid-ML or 1 GiB readiness claim is made.
- Final tests: 278 passed; nine unchanged baseline failures require unavailable
  authentic ML binaries/data. Details and exact nodes are in test-summary.json.
- Observed resource failure/cancellation leaves no newly published partial report;
  sampled RSS checks are not hard OS OOM prevention. Per-run disk capacity and
  controlled worker concurrency remain integration responsibilities.

See [LARGE_CAPTURES.md](LARGE_CAPTURES.md) for budgets, commands and limitations,
and [DASHBOARD_HANDOFF.md](DASHBOARD_HANDOFF.md) for integration contracts.
