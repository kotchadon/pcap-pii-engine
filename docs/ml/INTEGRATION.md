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
