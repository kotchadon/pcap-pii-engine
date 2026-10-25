# TRACE performance and memory implementation plan

> For agentic workers: use executing-plans for root work and focused parallel Astra ML work; user explicitly authorized implementation without another approval pause.

**Goal:** Correct historical-peak scan failures and reduce measured work without losing findings, coverage or evidence.
**Architecture:** Keep the in-process API and budgets. Introduce a platform-validated current-RSS reader and per-analysis guard; independently bound inference working sets/cache. Select packet/report optimizations only after baseline profiling. No process-worker rewrite without evidence.
**Tech stack:** Python3.10+, ctypes/Mach on macOS, procfs on Linux, optional PyTorch, pytest, GitHub Actions.
**Spec:** Owner's `Pasted text(20261025-072150).txt`, read completely; main4c9ac080e309ccc21a127c3e1e5e1422ccc4fa1c, PR32 reference79995e65a4006fd680a2a00d43fc4126dda7a068.

## Global constraints

- Preserve Standard1GiB budget, frozen V2 weights/thresholds, schemas/provenance, auth, masking, expiry and atomic output.
- Do not modify PR32 or previous HTTP history; new branch and draft PR only.
- No heavy benchmark concurrency or repeated large runs without a changed hypothesis.
- Genuine V2, macOS/MPS, M3 and browser validations must remain explicitly blocked if unavailable.

## Review focus

- Historical RSS above budget but current below: later scan succeeds, new excess still fails (Task1).
- Native API failure/short ABI output: fail closed with unavailable reading (Task1).
- Long heterogeneous fields: bound tensors, no silently omitted fields/spans (Task2).
- Hash collisions/time exhaustion: avoid incorrect reuse; explicit disposition accounting (Task2).
- Optimization changes source linkage/atomic cleanup: full report comparison and failure tests (Task3).

## Task1 — memory accounting

Files: new `src/packet_pii/memory.py`, `tests/test_memory_accounting.py`; modify engine guard boundaries.
Interface: `current_rss_bytes()->int|None`, `peak_rss_bytes()->int`; `_MemoryGuard(budget).check(stage)`.
- [x] Reproduce false rejection against baseline; red tests for historical/new peak, current excess, reader failure, atomic output.
- [x] Implement declared Mach signatures, packed48-byte info and checked word count; procfs Linux reader; per-analysis guard.
- [x] Green focused tests; cross-check live Linux RSS against /proc/self/status and prepare native macOS cross-check command.

## Task2 — ML inference/cache (Astra)

Files: `ml/bilstm.py`, `ml_runner.py`, focused ML/cache tests.
Interfaces: existing detector outputs/runner API unchanged; admitted/evaluated/skipped accounting explicit.
- [x] Audit PR32, state hypothesis, write failing tests for demonstrated batching/time/cache defects.
- [x] Implement deterministic bounded microbatches and conservative cache-byte accounting; do not increase outer batch fields blindly.
- [x] Compare actual random-network tensors only as algorithm tests; genuine V2 equivalence separately blocked if binary weights inaccessible.

## Task3 — throughput and integration

Files: measured subset of capture/reporting/http_evidence; `scripts/validation/bench_performance_memory.py`, acceptance script, CI and report.
- [x] Generate SHA-bound deterministic2MiB baseline; profile decode/evidence/report and collect fresh-process current/peak/stages.
- [x] Apply independently justified PR32 subsets with attribution, regression tests, exact complete-report comparisons.
- [x] Run controlled baseline/candidate rules scans (2MiB and medium); one52MiB only if justified. Capture Python heap separately to avoid timing contamination.
- [ ] Complete repository suite on committed source; genuine model tests optional only when genuinely unavailable; core CI must not require torch.
- [ ] Manual opt-in Apple Silicon job after runner/billing review; do not trigger unapproved paid compute.
- [ ] Fresh final review, inspect actual CI status, publish exact commits and NOT READY if required gates remain blocked.

## Progress / rulings

Baseline exact tree39fa0d6f470719fc29f0fffd5266d0698ff8fdba in isolated worktree.
Confirmed source defect: main uses lifetime ru_maxrss alone. Mach reader is PR32-only.
Ruling: retain in-process execution for immediate fix; process isolation deferred until load/IPC overhead can be measured. Cost if wrong: native allocator retention may still require a later supervised-worker design.
Ruling: full suite once per significant final milestone rather than per tiny edit, following owner's explicit token/benchmark discipline.

Final source review: Astra found the in-memory report traversal boundary; fixed with demonstrated red/green test. Encoded-row reuse separately reviewed, no remaining concrete source findings. Added 54-pass index/investigation gate and 24-pass new regression gate (overlapping sets). Initial full suite:951 passed,16 skipped,22 failed,92 errors; all114 unsuccessful cases are unavailable binaries. Final committed-SHA runs and CI remain required.

Ruling: owner already selected a draft PR; no completion menu or merge. Environmental failures remain explicit blockers, not fabricated passes. Benchmark scripts and report distinguish engine-only, indexed and random-network scopes. Manual Apple job prepared but not dispatched because paid-run approval is absent.
