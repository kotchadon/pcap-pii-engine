"""Typed, validated data contract for contextual PII span detectors.

This module is deliberately independent of packet-processing internals: it
imports nothing from ``packet_pii`` outside ``packet_pii.ml``.

Offset semantics
----------------
``start``/``end`` are zero-based offsets in *Unicode code points* of the exact
``FieldInput.text`` string (Python ``str`` indexing), half-open: ``[start, end)``.
So ``text[span.start:span.end]`` is the entity. They are NOT byte offsets and
NOT UTF-16 units. Text is never normalised or stripped by this package.

Safety
------
Error messages contain only field indices, attribute names, types and lengths --
never field text, locations, or offending values. Nothing here logs.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Optional, Sequence

DEFAULT_MAX_FIELD_CHARS = 65_536
DEFAULT_MAX_FIELDS = 10_000
MAX_LOCATION_CHARS = 1_024
MAX_MODEL_VERSION_CHARS = 128


class MlValidationError(ValueError):
    """Raised for malformed ML inputs/outputs. Message never contains raw text."""


class EntityLabel(str, Enum):
    """Contextual entity categories (initial, deliberately small)."""

    PERSON_NAME = "PERSON_NAME"
    USERNAME = "USERNAME"


class ScoreType(str, Enum):
    """Honest semantics of ``EntitySpan.score``."""

    NONE = "none"  # no score supplied
    UNCALIBRATED_MODEL_SCORE = "uncalibrated_model_score"  # e.g. raw softmax; NOT a probability
    CALIBRATED_PROBABILITY = "calibrated_probability"  # only if calibration was fitted and validated


@dataclass(frozen=True)
class ValidationLimits:
    max_fields: int = DEFAULT_MAX_FIELDS
    max_field_chars: int = DEFAULT_MAX_FIELD_CHARS

    def __post_init__(self) -> None:
        for name in ("max_fields", "max_field_chars"):
            v = getattr(self, name)
            if type(v) is not int or v <= 0:
                raise MlValidationError(f"{name} must be a positive int")


DEFAULT_LIMITS = ValidationLimits()


def _check_int(name: str, value: object, minimum: int = 0) -> int:
    if type(value) is not int:  # rejects bool and numpy-ish surprises
        raise MlValidationError(f"{name} must be an int, got {type(value).__name__}")
    if value < minimum:
        raise MlValidationError(f"{name} must be >= {minimum}")
    return value


@dataclass(frozen=True)
class FieldInput:
    """One extracted text field submitted for inference.

    ``field_index`` is the stable identity within a request; ``location`` is
    informational (several fields may share a location, e.g. repeated headers).
    ``context`` is optional string metadata (e.g. ``{"content_type": "json"}``);
    it must not contain secrets and is not interpreted by this package.
    """

    field_index: int
    location: str
    text: str
    context: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _check_int("field_index", self.field_index)
        if not isinstance(self.location, str) or not self.location:
            raise MlValidationError(f"field {self.field_index}: location must be a non-empty str")
        if len(self.location) > MAX_LOCATION_CHARS:
            raise MlValidationError(f"field {self.field_index}: location too long")
        if not isinstance(self.text, str):
            raise MlValidationError(
                f"field {self.field_index}: text must be str, got {type(self.text).__name__}")
        if not isinstance(self.context, Mapping):
            raise MlValidationError(f"field {self.field_index}: context must be a mapping")
        for k, v in self.context.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise MlValidationError(f"field {self.field_index}: context keys/values must be str")
        object.__setattr__(self, "context", MappingProxyType(dict(self.context)))

    def __repr__(self) -> str:  # never expose text in repr/logs
        return f"FieldInput(field_index={self.field_index}, text_len={len(self.text)})"


@dataclass(frozen=True)
class EntitySpan:
    """A predicted entity in ``FieldInput.text`` of the field ``field_index``."""

    field_index: int
    label: EntityLabel
    start: int  # inclusive, code points
    end: int  # exclusive, code points
    model_version: str
    score: Optional[float] = None
    score_type: ScoreType = ScoreType.NONE

    def __post_init__(self) -> None:
        _check_int("field_index", self.field_index)
        try:
            object.__setattr__(self, "label", EntityLabel(self.label))
        except ValueError:
            raise MlValidationError("label is not a supported EntityLabel") from None
        try:
            object.__setattr__(self, "score_type", ScoreType(self.score_type))
        except ValueError:
            raise MlValidationError("score_type is not a supported ScoreType") from None
        _check_int("start", self.start)
        _check_int("end", self.end)
        if self.start >= self.end:
            raise MlValidationError("span requires start < end")
        if not isinstance(self.model_version, str) or not self.model_version.strip():
            raise MlValidationError("model_version must be a non-empty str")
        if len(self.model_version) > MAX_MODEL_VERSION_CHARS:
            raise MlValidationError("model_version too long")
        if self.score is None:
            if self.score_type is not ScoreType.NONE:
                raise MlValidationError("score_type must be 'none' when score is None")
        else:
            if type(self.score) not in (int, float) or not math.isfinite(self.score) \
                    or not 0.0 <= self.score <= 1.0:
                raise MlValidationError("score must be a finite number in [0, 1]")
            if self.score_type is ScoreType.NONE:
                raise MlValidationError("score_type must describe the score when score is set")
            object.__setattr__(self, "score", float(self.score))

    def sort_key(self) -> tuple:
        return (self.field_index, self.start, self.end, self.label.value)


def validate_fields(fields: Sequence[FieldInput], limits: ValidationLimits = DEFAULT_LIMITS) -> list[FieldInput]:
    """Validate a request; return it as a list in the caller's order.

    Rejects non-FieldInput items, duplicate ``field_index`` values, too many
    fields and oversized text. Empty input is valid and returns ``[]``.
    """
    if isinstance(fields, (str, bytes)) or not isinstance(fields, Sequence):
        raise MlValidationError("fields must be a sequence of FieldInput")
    if len(fields) > limits.max_fields:
        raise MlValidationError(f"too many fields: {len(fields)} > {limits.max_fields}")
    seen: set[int] = set()
    for item in fields:
        if not isinstance(item, FieldInput):
            raise MlValidationError(f"fields must contain FieldInput, got {type(item).__name__}")
        if item.field_index in seen:
            raise MlValidationError(f"duplicate field_index {item.field_index}")
        seen.add(item.field_index)
        if len(item.text) > limits.max_field_chars:
            raise MlValidationError(
                f"field {item.field_index}: text length {len(item.text)} exceeds {limits.max_field_chars}")
    return list(fields)


def validate_spans(spans: Sequence[EntitySpan], fields: Sequence[FieldInput]) -> list[EntitySpan]:
    """Check detector output against the request; return spans canonically sorted.

    Every span must reference a request ``field_index`` and satisfy
    ``end <= len(text)`` of that field. Exact duplicates are rejected.
    Overlapping spans with different labels/extents are permitted.
    """
    if isinstance(spans, (str, bytes)) or not isinstance(spans, Sequence):
        raise MlValidationError("spans must be a sequence of EntitySpan")
    lengths = {f.field_index: len(f.text) for f in fields}
    seen: set[tuple] = set()
    for sp in spans:
        if not isinstance(sp, EntitySpan):
            raise MlValidationError(f"spans must contain EntitySpan, got {type(sp).__name__}")
        if sp.field_index not in lengths:
            raise MlValidationError(f"span references unknown field_index {sp.field_index}")
        if sp.end > lengths[sp.field_index]:
            raise MlValidationError(
                f"span end {sp.end} exceeds text length {lengths[sp.field_index]} "
                f"of field {sp.field_index}")
        key = sp.sort_key()
        if key in seen:
            raise MlValidationError(f"duplicate span in field {sp.field_index}")
        seen.add(key)
    return sorted(spans, key=EntitySpan.sort_key)
