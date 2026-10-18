"""Optional inference adapter. No PyTorch import or model loading in rules-only mode.

This module adapts the independently trained contextual sequence tagger to
HTTP-extracted fields. It never mixes rule heuristics with uncalibrated model
scores and does not modify the separately owned ML package.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import time
from typing import Sequence

from .detect import _mask, SECRET_KEYS
from .ml import FieldInput, run_detector
from .ml.detector import ContextualPIIDetector
from .ml.schema import DEFAULT_MAX_FIELD_CHARS, DEFAULT_MAX_FIELDS


@dataclass(frozen=True)
class InferenceResult:
    findings: list[dict]
    fields_evaluated: int
    fields_skipped: int
    fields_excluded: int
    fields_eligible: int = 0
    fields_empty: int = 0
    characters_evaluated: int = 0
    processing_time_seconds: float = 0.0
    invoked: bool = False


# Scan-wide work bounds supplement the per-request validation contract.
MAX_SCAN_ML_FIELDS = 10_000
MAX_SCAN_ML_CHARACTERS = 2_000_000


# Clearly structured secrets/contact data are already handled by rules.
# The research tagger is limited to contextual identity extraction; sending
# obvious credential fields to it increases unsupported false positives.
_RESERVED_FIELD = re.compile(r'(?:^|[.\[_-])(?:e_?mail|phone|telephone|mobile|card|credit_?card|cc_?number|ip|ip_?address|content_?length)(?:$|[.\]_-])', re.I)

def _excluded(location: str) -> bool:
    return location.startswith('header.') or bool(SECRET_KEYS.search(location) or _RESERVED_FIELD.search(location))

def load_experimental_bilstm(checkpoint_dir: str) -> ContextualPIIDetector:
    """Explicit opt-in: import torch and verify the checkpoint only if selected."""
    from .ml.infer import BiLSTMDetector
    return BiLSTMDetector(checkpoint_dir)


def infer_http_fields(
    fields: Sequence[tuple[str, str]],
    detector: ContextualPIIDetector,
    *,
    include_values: bool = False,
    max_fields: int = DEFAULT_MAX_FIELDS,
    max_characters: int = MAX_SCAN_ML_CHARACTERS,
) -> InferenceResult:
    """Return stand-alone contextual findings with original Unicode offsets.

    Unsafe oversized fields are skipped, not silently truncated (truncation
    would produce misleading provenance). The caller publishes skipped counts.
    """
    for name, value in (('max_fields', max_fields), ('max_characters', max_characters)):
        if type(value) is not int or value < 0:
            raise ValueError(f'{name} must be a non-negative integer')
    eligible: list[FieldInput] = []
    skipped = excluded = empty = characters = 0
    for index, (location, text) in enumerate(fields):
        if _excluded(location):
            excluded += 1
            continue
        if not text:
            empty += 1
            continue
        if (len(eligible) >= min(DEFAULT_MAX_FIELDS, max_fields)
                or len(text) > DEFAULT_MAX_FIELD_CHARS
                or len(text) > max_characters - characters):
            skipped += 1
            continue
        eligible.append(FieldInput(index, location, text))
        characters += len(text)
    if not eligible:
        return InferenceResult([], 0, skipped, excluded, skipped, empty)

    started = time.perf_counter()
    predictions = run_detector(detector, eligible)
    elapsed = time.perf_counter() - started
    lookup = {item.field_index: item for item in eligible}
    findings: list[dict] = []
    for span in predictions:
        field = lookup[span.field_index]
        if span.model_version != detector.model_version:
            raise ValueError('Detector returned a different model version')
        if span.score is None:
            raise ValueError("Experimental detector must provide a typed score for report output")
        original_value = field.text[span.start:span.end]
        findings.append({
            'pii_type': span.label.value,
            'location': field.location,
            'confidence': span.score,  # raw, uncalibrated; never averaged with rules
            'confidence_type': span.score_type.value,
            'value': original_value if include_values else _mask(original_value),
            'detector': 'bilstm',
            'model_version': span.model_version,
            'span_start': span.start,
            'span_end': span.end,
            'field_index': span.field_index,
        })
    return InferenceResult(findings, len(eligible), skipped, excluded,
                           len(eligible) + skipped, empty, characters, elapsed, True)
