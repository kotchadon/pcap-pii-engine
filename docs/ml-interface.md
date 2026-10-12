# ML Interface Contract (foundation)

Package: `packet_pii.ml` (no dependencies beyond the standard library; imports nothing from the packet pipeline). No model is included; nothing here produces predictions.

## Types
- `FieldInput(field_index, location, text, context={})` — `field_index` (int >= 0) is the identity within one request; `location` (e.g. `json_body.user.name`) is informational and may repeat across fields. `context` is optional str->str metadata, uninterpreted.
- `EntitySpan(field_index, label, start, end, model_version, score=None, score_type=ScoreType.NONE)`
- `EntityLabel`: `PERSON_NAME`, `USERNAME`. Add members to extend.
- `ScoreType`: `none`, `uncalibrated_model_score` (raw softmax etc.; **not** a probability), `calibrated_probability` (only after validated calibration). `score` must be finite in [0, 1]; `score_type` must be `none` iff `score is None`.

## Offsets
Zero-based **Unicode code-point** offsets into the exact `text` (no normalisation/stripping), half-open `[start, end)`; `text[start:end]` is the entity. Not bytes, not UTF-16. Requires `0 <= start < end <= len(text)`.

## Interface
```python
class ContextualPIIDetector(Protocol):
    model_version: str   # property
    def predict_fields(self, fields: Sequence[FieldInput]) -> list[EntitySpan]: ...
```
Callers use `run_detector(detector, fields, limits=DEFAULT_LIMITS)`, which validates input (types, unique `field_index`, <= 10,000 fields, <= 65,536 chars/field by default via `ValidationLimits`), short-circuits empty input to `[]` without calling the model, validates output (known `field_index`, in-range, no exact duplicates) and returns spans sorted by `(field_index, start, end, label)`. Input order is never changed.

## Implementer obligations (BiLSTM)
- Emit spans only for supplied `field_index` values; empty text yields none.
- Map tokenizer/char-level tags back to code-point offsets of the original string.
- Set `model_version` to a traceable id (artifact hash/tag); describe scores honestly.
- Never log, print, or persist input text; validation errors contain only indices, types and lengths.
- Violations raise `MlValidationError` (a `ValueError`).

## Out of scope / not done
Training, tokenizer, label scheme (BIO), calibration, merging with rule-based `Detection`s, pipeline/CLI/report integration.
