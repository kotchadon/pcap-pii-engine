# Large-capture assessment: 1 GiB in 120–180 s on an M3 MacBook Air (16 GB)

Status: **target, not a capability.** Nothing in this branch claims 1 GiB support. All measurements below are Linux
x86-64, 4 threads, CPython 3.13, PyTorch 2.14 (CPU) unless stated; they are not M3 measurements.

Required end-to-end throughput: 1024 MiB / 180 s = **5.69 MiB/s**; / 120 s = **8.53 MiB/s**.

## Six different claims that must not be conflated

| # | Claim | Today |
|---|---|---|
| 1 | Accept a 1 GiB file | **No.** Configuration ceilings: `max_capture_bytes` 512 MiB, `max_tcp_payload_bytes` 480 MiB, `max_packets` 2,000,000 (stress profile). |
| 2 | Parse the entire file | Up to the ceilings above, yes; whole-capture TCP buffering until EOF (see memory). |
| 3 | Inspect every supported plaintext field | Yes within limits; per-message `MAX_FIELDS`/`MAX_FIELD_LENGTH` fail closed (`AnalysisLimitError`) rather than truncate. |
| 4 | Evaluate every eligible ML field | Only within the ML budget: the `complete` profile admits 1,000,000 fields / 200,000,000 characters / 1,800 s of model time; beyond that fields are skipped **with reasons** (`partial` coverage). |
| 5 | Produce complete evidence | Bounded by `max_report_bytes` (2 GiB ceiling); evidence currently expands the capture **4.7× (packet-heavy) to 13.2× (field-heavy)**. |
| 6 | Meet a 2–3 minute deadline | **No.** See throughput. |

## Measured throughput (this branch)

| Workload | Path | Throughput | Gap to 5.69 MiB/s |
|---|---|---|---|
| 8 MiB segmented, packet-heavy (12k packets, 53k fields) | rules only, disk report | ≈1.2–1.4 MiB/s | 4–5× |
| 12 MiB field-heavy JSON API (80k packets, 171k fields) | rules only, disk report | ≈0.55–0.65 MiB/s | 9–10× |
| 52 MiB field-heavy, 570k eligible ML fields | rules + V2, cache, disk report | see `docs/performance/results/hardening_52mib_*` | ≫10× |

Stage profile (12 MiB field-heavy, rules only, after this branch's optimisations): evidence ≈ 30 %, read/decode/group
≈ 25 %, reassembly ≈ 10 %, rule detection ≈ 9 %, result aggregation ≈ 7 %, report publication ≈ 5 %. Everything is
single-threaded Python apart from PyTorch.

## Obstacles, by resource

**CPU (pipeline).** One Python thread decodes, reassembles, extracts, detects and serialises. Even with every
non-model stage removed, field-heavy traffic would need ~10× more throughput. Credible routes: per-flow parallelism
after reassembly (flows are independent once split; ordering is restorable by flow index), and native decoding for the
packet/TCP layer. Neither is safe to bolt on without preserving flow/message identity and evidence offsets.

**CPU (model).** V2 is a 3-member ensemble. On the 52 MiB workload the accelerated model still needs minutes; 1 GiB of
field-heavy traffic is ~11 M eligible fields, far beyond the `complete` budget. Routes (all out of scope here, each
needing its own validation): multiple single-thread inference workers, ONNX Runtime, distillation into one student
(new model version), explicit sampling policies with honest coverage reporting.

**Memory (buffering).** All TCP packets are retained until EOF, because session splitting and reassembly are defined
over the whole capture (tuple reuse, retransmissions, out-of-order data). Peak ≈ payload bytes + per-packet overhead.
This branch reduced the per-packet overhead (657 B/packet on the 12 MiB capture, was 814 B; real endpoint interning
and slotted per-packet dataclasses), but 1 GiB with ~1 M packets still needs ≈1 GiB payload + ≈0.65 GiB objects before
reconstruction starts. Flow memory is released flow by flow afterwards.

**Disk/report (evidence expansion).** 4.7–13.2× expansion means 4.7–13 GiB of report for 1 GiB of capture — beyond the
2 GiB report ceiling and impractical to inspect. A compact evidence encoding (e.g. columnar or range-compressed packet
evidence, deduplicated field paths) is a prerequisite, and it changes the evidence/report contract, so it needs the
Evidence Inspector owner.

**Process memory guard.** Previously, any earlier peak (model load, an earlier scan in the dashboard) failed later
scans; fixed in this branch (`_MemoryGuard`), which is necessary for long-running large-scan sessions.

## Implemented in this branch (measured, output-identical)

1. Per-buffered-packet memory: 814 → 657 B/packet on the 12 MiB capture (-19 %), 1,590 → 1,360 B/packet on the
   segmented capture (-14.5 %), via real endpoint interning and slotted `TcpPacket`/`PacketSourceRange`.
2. Decode path: read/decode/group 8.24 → 5.50 s (12 MiB) and 1.48 → 0.95 s (8 MiB) — no address re-parsing, C-speed
   Internet checksum (fuzz-tested), no `dataclasses.replace` per packet.
3. Evidence/report path: one reused JSON encoder per row format, cheaper JSON-key decoding, and an `evidence` stage
   timer (previously unattributed time).
4. Memory guard that no longer turns earlier transient peaks into failures of later scans.
5. ML: bounded inference working set (token cap 4,096) and larger runner batches (1,024) — faster *and* lower peak.

## Not implemented (and why)

* **Streaming/incremental flow processing during reading.** Releasing a flow before EOF requires proving it can never
  receive another packet (FIN/RST is not sufficient: retransmissions and tuple reuse occur later in real captures).
  Doing this without changing session splitting would need a bounded-lateness contract and new provenance tests; it
  should be an explicit experimental mode in a separate PR, not a silent change of the default path.
* **Parallel/native decoding, multi-worker inference, ONNX, distillation, evidence compaction** — each changes a
  contract or a model and needs its own validated milestone.

## Recommended sequence towards the target

1. Evidence compaction design with the Inspector owner (removes the hard 2 GiB report blocker).
2. Per-flow parallel post-reassembly processing (largest CPU lever for the non-model pipeline).
3. Multi-worker single-thread inference (measured earlier: 1 thread did 4-thread work in 5.6 vs 4.5 s, so 4 workers
   ≈ 2.5–3× aggregate), then ONNX Runtime; distillation only as a new model version.
4. An experimental bounded-lateness streaming mode with explicit, reported limitations.
