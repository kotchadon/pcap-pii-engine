# TRACE Model Laboratory — final-cut frontend contract

**Scope:** presentation and display safeguards only. This branch deliberately
does not change network reconstruction, rule detection, trained V2 weights,
inference budget defaults, scan jobs, report storage or evaluation algorithms.

## What is implemented

The Overview gives a concise processing-completeness diagnosis. A completed
Hybrid scan shows examined/eligible/skipped fields prominently and links
directly to the Model Laboratory.

The Model Laboratory displays a ratio from **actual report summary counters**:
`ml_fields_evaluated / ml_fields_eligible`. The denominator explicitly
excludes fields blocked by model-input policy. The panel also shows those
policy exclusions separately, rather than conflating them with skipped work.
It validates that all counts are nonnegative integers and
`eligible == evaluated + skipped`; inconsistent or absent counters produce
**UNVERIFIED**, not a speculative percentage.

The existing default budget on main remains 10,000 ML fields / 2 million
characters per scan. The work-budget reason is named only when the observed
examined count actually reaches the reported `ml_work_limits.max_fields`.
Other skips use a general budget/input-limits explanation. A partial scan
gets **INCOMPLETE**, not **100%** or **high confidence**. Zero eligible
fields yield an undefined percentage. Rules-only scans do not display
AI-field coverage. A new job clears earlier successful metrics.

The verbose unsupported-protocol / experimental-model caveats remain accessible
in a **collapsed Technical limitations & supported scope** disclosure.
They are not deleted, hidden permanently, or replaced with fake certainty.

## Ground truth: fail-closed display contract

**Not yet a file-accuracy engine.** The frontend does not generate labels, let
users upload annotations, estimate a manifest's truth, or calculate evaluation
from a paginated report preview. These are backend/evaluator responsibilities.
The panel says **NOT VERIFIED** until the evaluation backend independently
validates a capture and emits a compatible object.

For future integration, the backend must include the report metadata field
`capture_sha256` and an authenticated evaluation payload at the top-level
scan-job response `evaluation` (or as `report.evaluation`). No new request
is made in this branch, so existing endpoints remain stable.

The exact display contract is:

```json
{
  "status": "verified",
  "schema_version": "ground-truth-v1",
  "manifest_verified": true,
  "capture_sha256": "<64 lowercase/uppercase hex chars>",
  "manifest_sha256": "<64 lowercase/uppercase hex chars>",
  "model_version": "bilstm-v2-d1f9e9fb9a2b",
  "negative_fields_reviewed": true,
  "scope": "all_eligible_fields",
  "coverage_complete": true,
  "counts": {"tp": 0, "fp": 0, "fn": 0}
}
```

For a limited, independently validated field subset instead, set
`scope` to `evaluated_subset` and supply integer `fields_in_scope` bounded
by the number actually evaluated. The panel then labels results
**VERIFIED SUBSET** and never describes them as entire-file accuracy.

The UI further requires:
- matching `report.metadata.capture_sha256` and model version;
- hybrid detection mode and non-failed inference;
- valid, nonnegative integer TP/FP/FN;
- for full scope: `ml_fields_skipped=0`, `ml_incomplete=false`
  and `coverage_complete=true`;
- independently reviewed negative fields, so false-positive measurement
  isn't artificially limited to only positive examples.

On success, it **derives** precision, recall and exact-span F1 from
TP/FP/FN, not provided percentage fields. Undefined denominators display
**Undefined**, not zero or 100%. This is an explicit exact-span
PERSON_NAME/USERNAME evaluation contract, not accuracy of all PII types.
The backend must separately validate the manifest against decoded field
identities, offsets, labels and negative fields; a browser flag alone is
not scientific validation. A server can withhold verification for missing,
malformed, stale, partial or mismatched inputs. The UI must not try to
override that decision.

No endpoint for submitting a manifest is assumed or invented here.
When Claude's ground-truth evaluator lands, align its verified response
shape with this contract or update the UI and its tests together. Ensure
server-side cryptographic/hash binding and authenticated access before
displaying results.

## End-to-end checks

From repo root:

```bash
python -m pytest -q tests/test_model_lab_final_cut.py tests/test_unified_ui.py
python -m pytest -q
python -m packet_pii.dashboard --port 8765 --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2
```

Browser checks:
- A 10,000/88,192 eligible run must show **11.3%** field coverage,
  **78,192 skipped**, and an INCOMPLETE warning.
- Rules-only and no-eligible-field scans must not say 100% AI coverage.
- A completed Hybrid showcase must show its real evaluated/eligible counts.
- A cancelled/failed scan must clear prior live coverage and evaluation
  status while clearly labelling any retained previous results.
- File-specific precision/recall/F1 must remain hidden without verified labels.
- The offline research benchmark remains separate and explicitly labelled.
- The technical limitations panel is collapsed by default but available.

This is a local research prototype. An observed complete workload does not
mean that encrypted HTTPS, unsupported HTTP versions or unobserved packets
have been inspected. Findings are candidates, not proof of exfiltration.
