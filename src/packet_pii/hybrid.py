"""Optional inference adapter. No PyTorch import or model loading in rules-only mode.

This module adapts the independently trained contextual sequence tagger to
HTTP-extracted fields. It never mixes rule heuristics with uncalibrated model
scores and does not modify the separately owned ML package.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import time
from typing import Mapping, Sequence

from .detect import _mask, SECRET_KEYS
from .ml import FieldInput, run_detector
from .ml.detector import ContextualPIIDetector
from .ml.schema import DEFAULT_MAX_FIELD_CHARS, DEFAULT_MAX_FIELDS, MAX_LOCATION_CHARS
from .ml.schema import MlValidationError
from .ml.input_policy import MAX_REPLACEMENT_RATIO, QUALITY_FLAGS


class InferenceError(RuntimeError):
    """Sanitized failure of requested contextual inference; never a fallback."""
    ml_inference_failed = True


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
    quality: Mapping[str, str] | None = None,
    max_fields: int = DEFAULT_MAX_FIELDS,
    max_characters: int = MAX_SCAN_ML_CHARACTERS,
) -> InferenceResult:
    """Single-message inference with original Unicode offsets (the scan engine batches across messages itself).

    Unsafe oversized fields are skipped, not silently truncated (truncation would produce misleading provenance). The
    caller publishes skipped counts. ``quality`` carries upstream evidence-quality flags for the whole message (see
    ``ml.input_policy.QUALITY_FLAGS``); they never change the model's input or predictions and are attached to each
    finding as ``input_quality``. Fields that are mostly U+FFFD replacement characters are excluded by policy.
    """
    from .ml_runner import MLBatchRunner, MLWorkBudget
    for name, value in (('max_fields', max_fields), ('max_characters', max_characters)):
        if type(value) is not int or value < 0:
            raise ValueError(f'{name} must be a non-negative integer')
    runner = MLBatchRunner(detector, MLWorkBudget(
        batch_fields=DEFAULT_MAX_FIELDS, batch_characters=DEFAULT_MAX_FIELDS * DEFAULT_MAX_FIELD_CHARS,
        name='single_message'), include_values=include_values)
    # Zero is a legal bound for this compatibility API ("evaluate nothing"); MLWorkBudget itself requires positive limits.
    runner._field_limit, runner._char_limit = min(DEFAULT_MAX_FIELDS, max_fields), max_characters
    runner.add(0, fields, quality)
    runner.flush()
    (_, findings), = runner.take_ready()
    return InferenceResult(findings, runner.evaluated, runner.skipped, runner.excluded,
                           runner.eligible, runner.empty, runner.characters, runner.seconds, runner.invoked)
