# Bounded ML scalability and robustness

Branch: `feature/trace-scalable-ml-engine`. Draft PR: #18. Started at merged
main `44de57db97d9caf5b1b0946d2db9dbc0d06507e2`; incorporated subsequent main
`c9a14c0c7f1aaff149ea6070564019bb594e468b` (QA and Model Laboratory updates).

This change controls inference work. It does not retrain V2, change tokenization,
weights, score thresholds or the existing field exclusion policy. It does not
implement ground-truth evaluation or file-specific accuracy. The evaluator
handoff is [ML_COVERAGE_CONTRACT.md](ML_COVERAGE_CONTRACT.md).

## Selecting more coverage

Capture profiles (`standard`, `large`, `stress`) and ML budgets are independent.
Standard ML permits 10,000 fields / 2,000,000 Unicode characters. Explicit
Extended permits 100,000 / 20,000,000. Both use batches of at most 1,024 fields /
262,144 characters (raised from 256 fields by the V2 inference acceleration;
results do not depend on batch size), and never submit a field over 65,536
characters. Fields are
not truncated to fit; skips have machine-readable reasons. A sufficiently large
total budget permits every eligible field that also satisfies the independent
per-field and per-batch safety limits. No unlimited mode is provided.

CLI:

```bash
python -m packet_pii.cli capture.pcap --profile stress \
  --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2 \
  --ml-budget-profile extended -o capture-hybrid.json
```

Explicit CLI overrides are `--ml-batch-fields`, `--ml-batch-characters`,
`--ml-max-total-fields`, `--ml-max-total-characters`, and
`--ml-max-field-characters`. All go through `MLWorkBudget` validation. Specifying
a budget does not enable ML: a checkpoint must also be selected. Safe defaults
remain when no budget options are given. Raw findings remain masked.

For the existing website, start the server with an explicit administrator default:

```bash
python -m packet_pii.dashboard --port 8765 \
  --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2 \
  --ml-budget-profile extended
```

Open `http://127.0.0.1:8765`, select AI-assisted Hybrid and the appropriate capture
profile. There is no competing frontend panel in this change. The existing
website's job requests use the server's selected ML default. `/api/session`
advertises `ml_budget_profile` and `ml_budget_profiles`. An authenticated job
caller may explicitly set `X-ML-Budget-Profile: standard` or `extended` per job.
An omitted header uses the administrator setting; invalid values return 400.
The legacy synchronous endpoints retain their original safe ML defaults.

Every job snapshots its validated `ml_work_budget`; it is included in request
idempotency identity and job status. Reusing a request ID with a different
budget returns 409. The existing one-active-scan rule, token/Origin checks,
private upload storage, pagination and streamed complete downloads remain.

## Execution and failure semantics

The supplied detector is loaded once and reused. Candidate batches are bounded
within the current HTTP message; batches do not cross message boundaries.
Rules are published first, then ordered ML batches with original indices,
Unicode span offsets, model version and typed uncalibrated scores. Full coverage
metadata is spooled beside findings, subject to the same report byte limit.
Only bounded previews enter the website response; the complete JSON contains
`ml_field_coverage`, including evaluated fields with no predictions.

Cancellation is cooperative before/after each batch and after bounded chunks of
excluded/skipped fields. A single model call remains non-interruptible. Job status
includes `cancellation_requested`, `cancellation_completed`, and a
machine-readable `reason_code`. Failed/cancelled jobs expose no completed report;
their `progress` retains only previously observed counters, not a fabricated
final summary. Inference failures never fall back silently to rules. Atomic
writer failure leaves a previously published target intact.

There is no cross-job resume/checkpoint facility: cancelling and submitting a
new request starts a new scan. Retrying the same retained request ID returns the
same job without repeating inference. Completed job expiry remains unchanged.

F-03: overlong/invalid model field paths are skipped before constructing strict
model inputs. The original path is never truncated and valid later fields still
run. Rules continue under their existing independent limits.

F-05: recognizable unfinished request headers, Content-Length bodies and chunk
framing set observed HTTP incompleteness with flow/direction/offset diagnostics.
An absent FIN alone proves nothing. Missing response-body framing is uncertain
without paired request-method context: HEAD/CONNECT may legally omit it. Those
responses remain unparsed; this is a disclosed existing parser limitation.
Other unsupported protocols/encodings and extraction limitations remain.

## Measured evidence and limits

Measurements below used Linux x86_64, Python 3.12.14. They are not Mac M3 results.
Sanitized JSON evidence and model identities are in `results/scalable/`.

| Run | Evaluated / eligible | Skipped | Batches | Full duration | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| Synthetic 5.26 MiB, Standard, empty contract detector | 10,000 / 88,000 | 78,000 | 46 | 1.35 s | 22.02 MiB |
| Same capture, Extended, empty contract detector | 88,000 / 88,000 | 0 | 400 | 1.60 s | 22.02 MiB |
| Exact 110 MiB, Large, rules-only HTTP job | ML not requested | — | 0 | 33.73 s | 195.98 MiB |

**The empty contract detector measurements are not BiLSTM inference performance.**
They verify routing, coverage and bounded adapter/report behavior only. The
representative fixture is generated independently from application code and is
not the user's unavailable 107,484-field lab capture. Its 108,400 extracted fields
comprise 88,000 eligible and 20,400 policy exclusions. Both runs preserve 19,200
rules findings, with zero model predictions by the explicit empty test double.

The exact 110 MiB capture preserves 361,389 packets, 60,232 sessions, 120,462 HTTP
messages and 244,046 rule findings. The full 122,766,366-byte JSON downloaded and
verified; preview was 77,762 bytes. All original flow/finding values match the
prior baseline SHA-256 after excluding only the additive flow diagnostic key.
One non-HTTP tail is marked uncertain; no definite HTTP damage was observed.
RSS is sampled process high-water usage, not an OS-enforced memory reservation.
These single-run timings do not establish a speedup or large-hybrid capability.

Authentic V2 weights and one V2 training dataset blob are unavailable in this
workspace. The original model Git entries and expected manifest hashes remain
unchanged. Real model tests were attempted and fail visibly on missing files;
no replacement model, dummy weights or invented model results are supplied.
Real V2 throughput, output invariance and complete showcase behavior require the
Mac commands below. The baseline was 323 passed / 11 missing-artifact failures;
see `tests.json` for the final regression results and precise command.

The full run after incorporating main's QA suite recorded **436 passed, 18 failed,
58 errors and 3 xfailed in 38.81 s**. All remaining failures/errors originate in
missing model/data artifacts. A subsequent localized job-cleanup ordering fix
was verified by **45 passed, 3 deselected, 1 xfailed in 6.95 s**, plus independent
review of both cancellation/cleanup tests (**2 passed**). The full suite was not
repeated after that localized fix. Terminal states now become visible only after
private-file cleanup and worker-lock release finish. Details:
[`results/scalable/tests.json`](results/scalable/tests.json).

The small rules-only HTTP job also preserved **95 packets, 12 flows, 24 HTTP
messages and 19 rule findings** (0.256 s upload through verified download).
Actual V2 predictions on that fixture were not measured in this environment.

## Mac M3 verification

Use the existing project directory and Python 3.13 environment containing the
authentic committed artifacts:

```bash
git fetch origin
git switch feature/trace-scalable-ml-engine
git pull --ff-only
source .venv/bin/activate
python -m pip install -e '.[ml]' pytest
python -m pytest -q
python -m pytest -q tests/test_ml_scalability.py::test_authentic_v2_batch_size_invariance_and_full_showcase
```

Verify the three original model binaries against the committed ensemble:

```bash
python - <<'PY'
import hashlib, json
from pathlib import Path
p = Path('src/packet_pii/ml/artifacts/bilstm_v2')
m = json.loads((p/'ensemble.json').read_text())
assert m['model_version'] == 'bilstm-v2-d1f9e9fb9a2b'
for item in m['members']:
    assert hashlib.sha256((p/item['dir']/'model.pt').read_bytes()).hexdigest() == item['model_sha256']
print('Authentic V2 member hashes verified')
PY
```

Run each benchmark in a fresh process, keeping captures/reports local:

```bash
python examples/generate_showcase.py showcase.pcap
python scripts/validation/benchmark_dashboard.py showcase.pcap showcase-report.json \
  --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2
python scripts/validation/generate_field_heavy.py field-heavy.pcap
python scripts/validation/benchmark_ml_coverage.py field-heavy.pcap standard-report.json \
  --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2
python scripts/validation/benchmark_ml_coverage.py field-heavy.pcap extended-report.json \
  --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2 --ml-budget-profile extended
python scripts/validation/benchmark_dashboard.py trace_synthetic_110MiB.pcap large-rules-report.json --profile large
```

Use unique output paths: generators and reports refuse accidental overwrites.
For the exact original 5 MiB lab capture, substitute its local path and inspect
both character and field limits. Sufficient field allowance alone cannot
guarantee complete coverage. No report or capture needs to leave the computer.
