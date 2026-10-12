"""Isolated ML inference interface for contextual PII detection (foundation only)."""
from .detector import ContextualPIIDetector, run_detector
from .schema import (DEFAULT_LIMITS, DEFAULT_MAX_FIELD_CHARS, DEFAULT_MAX_FIELDS,
                     EntityLabel, EntitySpan, FieldInput, MlValidationError,
                     ScoreType, ValidationLimits, validate_fields, validate_spans)

__all__ = [
    "ContextualPIIDetector", "run_detector", "DEFAULT_LIMITS", "DEFAULT_MAX_FIELD_CHARS",
    "DEFAULT_MAX_FIELDS", "EntityLabel", "EntitySpan", "FieldInput", "MlValidationError",
    "ScoreType", "ValidationLimits", "validate_fields", "validate_spans",
]
