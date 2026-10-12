"""Detector interface contract and a validating runner (no model included)."""
from __future__ import annotations

from typing import Protocol, Sequence, runtime_checkable

from .schema import (DEFAULT_LIMITS, EntitySpan, FieldInput, MlValidationError,
                     ValidationLimits, validate_fields, validate_spans)


@runtime_checkable
class ContextualPIIDetector(Protocol):
    """Contract for a contextual span detector (e.g. a future BiLSTM tagger).

    Implementations must: return spans only for the supplied ``field_index``
    values; use code-point offsets into the exact input text; set
    ``model_version``; describe scores honestly via ``score_type``; never log
    or persist input text; and return ``[]`` when nothing is found.
    """

    @property
    def model_version(self) -> str: ...

    def predict_fields(self, fields: Sequence[FieldInput]) -> list[EntitySpan]: ...


def run_detector(detector: ContextualPIIDetector, fields: Sequence[FieldInput],
                 limits: ValidationLimits = DEFAULT_LIMITS) -> list[EntitySpan]:
    """Validate input, call ``detector``, validate output, return sorted spans.

    Empty input short-circuits to ``[]`` without invoking the model. Fields
    with empty text are passed through; a detector must emit nothing for them
    (enforced by output validation since ``start < end <= 0`` is impossible).
    """
    validated = validate_fields(fields, limits)
    if not validated:
        return []
    out = detector.predict_fields(validated)
    if out is None:
        raise MlValidationError("detector returned None instead of a list")
    return validate_spans(out, validated)
