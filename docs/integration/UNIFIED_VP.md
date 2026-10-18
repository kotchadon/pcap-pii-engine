# Unified TRACE demonstration

Integration starts at main `c6098d879466636678fb0a40e7f21b5d0d68f0aa` and selectively
ports showcase branch `86ad30335e9516b9deb7d10ec5849f3304c1bb55`.
PRs 12 and 13 are unchanged. This branch deliberately reconciles orchestration;
it does not replace the PR11 large-file engine with the older hybrid pipeline.

## First runnable checkpoint (A/B)

One shared engine supports rules-only and optional BiLSTM through `analyze()`
and atomic `analyze_to_report()`. Standard/Large/Stress, compact packet retention,
M3C session/safe-prefix reconstruction and private bounded reporting remain.
ML errors fail the scan; no requested hybrid scan silently falls back to rules.

The dashboard includes the actual 12-conversation PCAP generator, masked finding
inspector, client-disconnect handling and live per-scan ML accounting. Research
metrics are read from versioned evaluation JSON and checked against the model
manifest. They are not live-upload accuracy. The How TRACE Works page explains
supported behavior at two levels.

## Mac commands

Use the user's full checkout; preserve any uncommitted work before switching.
From the repository root:

```bash
git fetch origin
git switch --track origin/feature/trace-unified-vp-integration
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[ml]' pytest
python -m pytest -q tests/test_unified_engine.py tests/test_hybrid_integration.py tests/test_dashboard.py tests/test_dashboard_scan_modes.py tests/test_hybrid_dashboard.py tests/test_showcase_live_evidence.py tests/test_dashboard_disconnect.py tests/test_large_capture_performance.py
python -m packet_pii.dashboard --port 8765 --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2
```

Open http://127.0.0.1:8765/. Select AI-assisted hybrid explicitly, run the
12-conversation showcase, inspect actual returned predictions if present, and
compare a rules-only run. Loaded, invoked and prediction-found are distinct
states. Nothing requires network transmission of capture data.

For the exact 110 MiB capture through the full bounded rules CLI:

```bash
pcap-pii /path/to/trace_synthetic_110MiB.pcap --profile large -o trace-110.json
```

The CLI supports optional `--ml-checkpoint`. Hybrid inference is bounded to
10,000 fields / 2,000,000 characters per scan. Counts expose all skipped eligible
fields, and skipped work marks analysis incomplete. A complete large rules scan
is not proof that full 110 MiB hybrid inference ran.

## Validation limits

Cloud tests can execute CPU PyTorch, but authentic committed model.pt files and
v2 train.jsonl.gz could not be materialized here. Their Git entries are unchanged.
Mock-model tests verify integration, not model quality. Real V2 showcase output
must be measured using the complete checkout; no prediction counts are invented.
Linux timings must not be presented as Mac M3 measurements.

The original showcase guide describes its source branch. This document supplies
the integrated launch instructions and supersedes those branch-specific commands.

## Background jobs and large results (C)

The browser now uses jobs for both uploads and showcase generation:

1. `POST /api/jobs` streams a binary PCAP/PCAPNG into a private file, or
   `/api/jobs/showcase` generates the fixture. Explicit mode/profile headers and
   an idempotency request ID accompany the authenticated request.
2. One heavy upload/scan is active at a time. A competing request returns 409;
   there is no unbounded waiting queue. The worker runs independently of its
   HTTP connection. Losing a response cannot release its lock or delete files.
3. Status reports actual stages/counters and elapsed time. Refresh recovers the
   latest server job; a lost POST response does not trigger an automatic retry.
4. `analyze_to_report()` writes the complete masked report and builds a bounded
   derived SQLite index through a row observer. Only completed results become
   accessible. No full-report `json.load()` occurs in the dashboard server.
5. Findings and flows are paginated, at most 100 rows per request. Search/type
   filtering executes on the server; breakdown totals are complete-report counts.
6. Download streams the complete JSON separately, using a normal browser download
   rather than loading/parsing it into JavaScript.

The browser defaults to Standard and Rules-only. For the exact 110 MiB capture,
choose **Large + Rules-only** before selecting the file. Do not choose Standard
and assume 110 MiB fits: that file exceeds Standard packet/flow/payload budgets.
Stress requires explicit selection. Hybrid work caps remain visible and cause
an incomplete result when eligible work is skipped; no full 110 MiB hybrid run
was attempted or claimed.

### Lifecycle and security

- Loopback bind is enforced at server construction (`127.0.0.1` only). Host,
  Origin and session-token validation apply to job operations. Session response
  sets an HttpOnly, SameSite=Strict cookie scoped to `/api/jobs/` for same-origin
  downloads. Tokens never appear in URLs or logs. The cookie is for loopback HTTP;
  this is not an Internet deployment/authentication scheme.
- Capture, report and index files use mode 0600 inside mode-0700 directories.
  Filename headers are display labels only and never determine disk paths.
- Uploads have a 120-second wall deadline, a 30-second inactivity timeout and
  incremental reads. Cancellation interrupts an outstanding upload socket read.
  Worker cancellation is cooperative at progress/row boundaries; a single model
  call/parser operation must return before it can take effect.
- Failed/cancelled jobs expose no report and remove capture/index/output files.
  Captures are deleted after successful processing as well. Previous successful
  results are displayed only with an explicit previous-result label after a new
  failure; live laboratory counters become unavailable, not fabricated zeros.
- Up to three retained jobs, with one-hour access expiry. Old terminal jobs are
  pruned on the next submission; normal server shutdown removes the private job
  directory. A forced OS kill/crash can leave private temporary files for local
  cleanup. Jobs do not survive a server restart and are not a durable queue.
- Default private job disk quota is **12 GiB**, configurable with
  `--job-disk-mib` (at least 32 MiB). Before admission, the server conservatively
  checks free disk/quota for capture + four report budgets + 64 MiB. This covers
  spools, final JSON and capped SQLite storage; it is a capacity check, not an OS
  reservation. Large needs about 4.31 GiB free plus retained results even though
  the measured 110 MiB job used much less. A quota/free-space refusal is HTTP 507.
- SQLite reads close their handles and synchronize with retention cleanup.
  Deletion/unavailability becomes a controlled error. Eight concurrent HTTP
  handlers are allowed; excess connections are closed to bound server threads.
- Legacy `/api/analyze`, `/api/demo`, `/api/showcase` remain small-file compatibility
  endpoints: 8 MiB input, 4 MiB encoded report, 10,000 findings, same heavy-scan
  lock. The new UI uses jobs. A legacy oversized request fails explicitly rather
  than returning a huge response or silently truncated findings.

### ML accounting

For a completed hybrid scan:

`fields_extracted = ml_fields_excluded_by_policy + ml_fields_empty + ml_fields_eligible`

`ml_fields_eligible = ml_fields_evaluated + ml_fields_skipped`

Exclusion is classified before empty fields. Headers and obvious credential,
contact/card/IP fields are excluded by the adapter policy. Skipped means eligible
but outside per-field or scan-wide work bounds. Rules-only counts extracted
fields but does not classify them as ML-eligible/evaluated; its ML counters are
zero because ML was not requested. Inference time measures the validating model
runner, not loading and not the whole packet pipeline. Score types and Unicode
half-open character offsets are retained on every contextual finding. Inference
and output-validation failures fail closed; they are distinct from upload or
capture failures. The model is not retrained or its examples tuned by this PR.

## Measured validation

Linux x86_64, Python 3.12.14, one fresh server process per workload. The benchmark
uses actual loopback HTTP upload, background processing, last-page pagination
and streamed full JSON download. Parent-process JSON verification is excluded
from the server's peak RSS. Timings are single observations; a 250 ms polling
interval adds visible overhead to tiny scans. These are not M3/browser-rendering
measurements.

| Capture | Bytes | Packets | Sessions | HTTP messages | Rules | ML fields / predictions | Engine seconds | Upload through download seconds | Server peak MiB | Report bytes | Full output verified |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 12-conversation showcase | 11,312 | 95 | 12 | 24 | 19 | 0 / 0, not requested | 0.0047 | 0.257 | 20.44 | 13,151 | Yes |
| Generated moderate | 5,414,662 | 7,822 | 368 | 7,944 | 1,986 | 0 / 0, not requested | 0.9445 | 1.062 | 27.83 | 959,242 | Yes |
| Exact user 110 MiB | 115,343,298 | 361,389 | 60,232 | 120,462 | 244,046 | 0 / 0, not requested | 35.3800 | 36.064 | 196.07 | 121,440,475 | Yes |

The exact capture extracted 2,349,009 fields. Its preview was **74,145 bytes**,
containing 100 findings and 100 flows. Its SQLite index was 149,876,736 bytes.
Canonical SHA256 of all ordered finding/flow rows is
`1b8b48583e874d1d30f1e7098b6e4aecfb29260e24e49f04dc8d9a956bf0599a`, identical to
PR11's complete baseline. No rows were dropped to obtain the smaller preview.

Full local suite: **320 passed, 11 failed in 36.95 s**, with nothing deselected.
The eleven failures require missing authentic checkpoints/training data: nine
inherited main failures plus the imported real-model integration/showcase tests.
Two subsequently added invalid-output classification regressions and one worker-start
cleanup regression also pass.
Exact node IDs and focused-check results are in `results/tests.json`. The first
published A/B checkpoint passed both GitHub CI checks. The existing workflow
installs the base package and pytest on Python3.11, without optional PyTorch;
those green checks do not establish real V2 inference.

UI verification includes JavaScript syntax and Node-backed behavior checks for
loaded/invoked/zero-prediction states, benchmark version mismatch, paging, no
automatic duplicate POST, refresh recovery and failure-state labeling. A browser
executable was unavailable here, so visual layout and real browser rendering
remain a local smoke check. Real HTTP transport/security was exercised directly.

### Reproduce the measurements locally

Use a distinct output filename for each run (existing reports are not overwritten):

```bash
python examples/generate_showcase.py /tmp/trace-showcase.pcap
python scripts/validation/benchmark_dashboard.py /tmp/trace-showcase.pcap /tmp/trace-showcase-report.json
# Real V2 measurement on the full local checkout, separately from rules:
python scripts/validation/benchmark_dashboard.py /tmp/trace-showcase.pcap /tmp/trace-showcase-hybrid.json --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2
python scripts/validation/generate_captures.py /tmp/trace-moderate.pcap --size-mib 5
python scripts/validation/benchmark_dashboard.py /tmp/trace-moderate.pcap /tmp/trace-moderate-report.json
python scripts/validation/benchmark_dashboard.py /path/to/trace_synthetic_110MiB.pcap /tmp/trace-110-report.json --profile large
python -m pytest -q tests/test_dashboard_jobs.py tests/test_unified_ui.py
```

Remaining demo checks on the user's M3/Python3.13: authentic V2 loading/showcase
predictions, the full suite with model artifacts, browser layout/refresh/download
smoke test, and local performance. No large hybrid, HTTPS decryption, HTTP/2/3,
1 GiB, independently labelled live-PCAP accuracy or production-readiness claim.
