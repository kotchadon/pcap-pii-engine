# Scalable ML Implementation Plan

**Goal:** Bounded, explicitly configurable ML coverage with precise skip accounting and conservative incomplete HTTP diagnostics.

**Architecture:** Preserve the existing streamed engine and single job worker. Feed original indexed fields through bounded batches using the existing loaded detector; publish batch findings through the report spool. Add optional parser diagnostics without changing TCP reconstruction.

**Tech stack:** Python, existing optional PyTorch V2 detector, SQLite job index.

**Spec:** User's “ASTRA — TRACE ML SCALABILITY & CRITICAL ROBUSTNESS MISSION”, 2026-10-18.

## Constraints

- Start at main `44de57db97d9caf5b1b0946d2db9dbc0d06507e2`; only `feature/trace-scalable-ml-engine`.
- Preserve checkpoint, tokenizer, thresholds, training data and research results.
- Keep default scan work at 10,000 fields / 2,000,000 characters; greater work requires explicit selection.
- No evaluator, frontend accuracy work, raw traffic publication, paid compute or merge.

## Tasks

- [x] Verify baseline tree, author identity and artifact metadata; run baseline tests.
- [ ] `hybrid.py`, `engine.py`, `tests/test_ml_scalability.py`: validated `MLWorkBudget`, streamed batches, F-03 prevalidation, original indices, exact counters, callbacks between batches; test full/partial/invalid/mixed fields, cancellation and failure.
- [ ] `http_extract.py`, `tests/test_http_incomplete_tail.py`: optional sanitized framing diagnostics; test partial headers, fixed-length/chunked bodies and pipelines; preserve intact/close-delimited handling.
- [ ] Publish focused-test checkpoint with unchanged model tree.
- [ ] `jobs.py`, `dashboard.py`, `cli.py`, `tests/test_ml_budget_jobs.py`: explicit higher coverage configuration, request identity includes ML budget, real progress/cancel state; preserve atomic reporting and cleanup.
- [ ] `scripts/validation/benchmark_dashboard.py` and evidence: measure showcase, field-heavy control workload and exact 110 MiB rules regression. Authentic V2 benchmarks only if real weights are available.
- [ ] `docs/integration/ML_COVERAGE_CONTRACT.md` and scalability guide: define field IDs, offsets, complete/partial/failed semantics, reason codes, measurements and exact Mac commands.
- [ ] Full regression run, protected-tree check, draft PR; no merge.

## Review focus

- Duplicate field paths must retain distinct original indices.
- Invalid fields must not prevent later valid fields reaching inference.
- A cancelled or failed batch must not publish a successful partial report.
- No prediction is not proof of missing inference or file-specific accuracy.
- Missing FIN alone is not evidence of damaged HTTP framing.

Execution is already authorized by the user's explicit implementation assignment.
