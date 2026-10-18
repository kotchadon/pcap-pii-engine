# Handover: full-capture ML coverage, ground-truth evaluation, correctness fixes

Branch `feature/trace-ml-completeness-groundtruth-v1` (from `main` at PR #14). V2 weights, thresholds and existing evaluation results are unchanged (`src/packet_pii/ml/artifacts/bilstm_v2`, `bilstm-v2-d1f9e9fb9a2b`, `min_score` 0.35).

## What changed

| Area | Where | Notes |
|---|---|---|
| Bounded chunked inference | `src/packet_pii/ml_runner.py`, `engine.py` | `MLWorkBudget` profiles; one `MLBatchRunner` per scan; cross-message batches; results released in message order (batch-size invariant); per-field disposition hook |
| Coverage accounting | report `summary` / `metadata` | `ml_coverage_status`, `ml_coverage_ratio`, `ml_fields_skipped_by_reason`, `ml_batches`, `metadata.ml_work_limits` |
| Defect fixes F-03..F-11 | `detect.py`, `http_extract.py`, `capture.py`, `hybrid.py`, `engine.py` | table in `docs/vp-qa/TECHNICAL_VALIDATION.md` §5; former strict xfails are regular tests |
| Ground truth | `groundtruth.py`, `evaluate_cli.py`, `schemas/ground-truth-v1.schema.json`, `examples/groundtruth/` | strict validator (no dependency), exact-span evaluator, fixture generator |
| Dashboard | `dashboard.py`, `jobs.py`, `dashboard_static/{index.html,app.js,lab.js,app.css}` | `X-ML-Coverage`, `POST /api/manifests[/showcase]`, `X-Ground-Truth-Manifest`, `GET /api/jobs/<id>/evaluation[?download=1]` |

## New report fields (all additive; `potential_leaks` is unchanged)

`distinct_exposed_locations`, `locations_flagged_by_rules|model|both`, `unterminated_http_messages`, `http_bodies_not_inspected[_by_reason]`, `http2_streams_not_decoded`, `tls_streams_not_inspected`, `unsupported_packets_by_reason`, `unsupported_packets_hiding_tcp`; ML findings may carry `input_quality`.

## Invariants worth keeping

* Findings never contain raw values by default; evaluation results contain hashes, counts, field ids and offsets only.
* A manifest never becomes reference truth from model output (`labels_derived_from_model_output` must be `false`); the evaluator uses no detector output to build labels.
* Partial coverage, unaligned fields or a failed model are never published as complete / full-file accuracy.
* The frozen controlled fixture must not be edited after model results are seen; a new fixture version should be a new file with a new manifest.

## Operating notes

* Selecting `extended`/`complete` raises CPU time (~2,800 eligible fields/s for V2 on the development machine, about 40 s for 108k fields) but not memory (batches are bounded; queued fields are released per batch).
* Credential-key matching is token-aware (`author` is not `auth`); new credential words go in `_SecretKeyMatcher` in `detect.py`; `tests/test_secret_key_matcher.py` guards the pre-filter.
* `ml/input_policy.py` keeps its own older copy of the credential regex for the offline evaluation scripts; it was deliberately not changed so published evaluation results stay reproducible.
* The Chromium UI test (`tests/test_model_lab_ui.py`) is skipped when Playwright/Chromium are not installed.

## Known limits

Exact-span scoring penalises boundary near-misses twice; fixture statistics are small (64 gold spans) and synthetic; no real-capture accuracy exists; HTTPS, HTTP/2 and non-HTTP traffic are not decoded; scores remain uncalibrated.
