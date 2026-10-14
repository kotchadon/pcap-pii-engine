# Integration guide

The core application does **not** import or enable ML. Use it opt-in from your own code or a future, separately reviewed integration.

```
pip install '.[ml]'          # torch>=2.2, CPU is enough
```
```python
from packet_pii.ml import FieldInput, run_detector
from packet_pii.ml.infer import BiLSTMDetector          # imports torch; rules-only code never needs this

det = BiLSTMDetector("src/packet_pii/ml/artifacts/bilstm_v1")      # min_score from meta.json (0.25); override: min_score=0.5
fields = [FieldInput(0, "json_body.user.fullName", "Zoë Müller"),
          FieldInput(1, "json_body.message", "login as @bob_99")]    # field_index = stable identity, location = field key path
for s in run_detector(det, fields):                                # validates input and output, sorted by (field_index, start, end)
    print(s.field_index, s.label.value, s.start, s.end, s.score, s.score_type.value, s.model_version)
```
CLI check: `python scripts/ml/predict.py --location json_body.message --text "Hello, my name is Zoë Müller"` (prints offsets only; `--show-text` to echo).

Contract notes
* Offsets are code-point offsets into the exact input string, `[start, end)`; `EntitySpan` objects always validate.
* `location` is used by the model as context - pass the real extracted field path (`header.x`, `json_body.a.b`, `query.q`, ...).
* `score_type` is always `uncalibrated_model_score`; keep it separate from rule confidences in reports. Do not average or multiply them.
* Output is deterministic for a given checkpoint (CPU). Errors: `MlValidationError` (bad input/limits), `CheckpointError` (bad checkpoint).
* Fields over 192 tokens (incl. key) are processed in windows; entities crossing a window edge may be cut.
* To retrain: `scripts/ml/train.py` then `scripts/ml/evaluate.py` (see EVALUATION.md). Swap in a new checkpoint directory; version string = `bilstm-v1-<sha256[:12]>`.
* Recommended status: **disabled by default** until validated on representative real data (MODEL_CARD.md).

---

# V2 update (branch `feature/ml-bilstm-v2-generalization`)

V2 is a **separate, versioned artifact**; V1 is unchanged and remains the fallback. The core application still does not import or enable ML.

| | V1 | V2 |
|---|---|---|
| Path | `src/packet_pii/ml/artifacts/bilstm_v1` | `src/packet_pii/ml/artifacts/bilstm_v2` (ensemble directory: `ensemble.json` + `seed11/ seed12/ seed13/`) |
| `model_version` | `bilstm-v1-972a87f2b6db` | `bilstm-v2-d1f9e9fb9a2b` |
| Loader | `BiLSTMDetector(path)` | **same class, same call** - it detects `ensemble.json` and verifies every member checksum |
| Contract | `predict_fields(Sequence[FieldInput]) -> list[EntitySpan]` | identical; labels `PERSON_NAME` / `USERNAME`; `ScoreType.UNCALIBRATED_MODEL_SCORE`; code-point offsets |
| Operating point | `min_score` 0.25 | `min_score` 0.35 (override: `BiLSTMDetector(path, min_score=...)`) |

```python
from packet_pii.ml import FieldInput
from packet_pii.ml.infer import BiLSTMDetector
from packet_pii.ml.input_policy import run_with_policy      # recommended wrapper (torch-free module)

det = BiLSTMDetector("src/packet_pii/ml/artifacts/bilstm_v2")          # CPU, offline, ~12 MB
result = run_with_policy(det, [
    FieldInput(0, "json_body.shipping.recipient", "Priyanka Venkataraman"),
    FieldInput(1, "json_body.audit.actor", "night_owl_77", {"truncated": "false"}),
    FieldInput(2, "json_body.invoice.billed_to", "Johnson & Johnson"),
    FieldInput(3, "json_body.password", "Maria Garcia"),               # excluded by policy (secret-bearing key)
])
for s in result.spans:            # sorted by (field_index, start, end, label); no raw text inside
    print(s.field_index, s.label.value, s.start, s.end, round(s.score, 3), s.score_type.value, s.model_version)
print(result.skipped)             # {3: ('secret_bearing_key',)}
print(result.partial_evidence)    # field_index values whose upstream quality flags mean "may be incomplete"
```
Reproducible example (prints offsets only): `python scripts/ml/demo_v2.py` - includes a person name, a username, a hard negative (company -> no finding) and two **known failures** (labelled).

* **Input policy** (`input_policy.py`): secret-bearing keys are excluded from name tagging; empty / 1-char / > 30% U+FFFD fields are skipped; upstream quality flags passed in
  `FieldInput.context` (`truncated`, `stream_gap`, `capture_incomplete`, `decode_replaced`, `fragment`) are surfaced as `partial_evidence`. See `UPSTREAM_INPUT_ASSUMPTIONS.md`.
* **Hybrid use** (proposal, not implemented in the engine): keep every deterministic-rule finding, add ML spans that overlap none and have score >= 0.35, report the two sources separately
  (never one merged probability). Measured: improves on rules alone on all benchmarks; improves on ML alone only on the V1 test (`V2_EVALUATION.md` section 3-4). Given the
  challenge result, ML-only findings should be shown as "contextual, experimental".
* **Smaller artifact:** any member directory is a complete V1-format checkpoint, e.g. `BiLSTMDetector(".../bilstm_v2/seed13")` (3.9 MB, challenge F1 0.808 vs 0.818 for the ensemble).
* **Errors:** `MlValidationError` (bad input / limits), `CheckpointError` (missing, corrupt, tampered, mismatched ensemble). `import packet_pii.ml` never imports PyTorch.
* **Retrain / reproduce:** `scripts/ml/build_lexicons.py` (dev-time, needs `faker==40.43.0`; output committed) -> `scripts/ml/make_dataset_v2.py` -> `scripts/ml/train_v2.py --seed {11,12,13}` ->
  `scripts/ml/package_v2.py` -> `scripts/ml/evaluate_v2.py` (frozen sets need `--final`). Exact commands: `V2_EXPERIMENTS.md`, `V2_EVALUATION.md`.
