"""Bounded adapter for optional contextual inference; rules mode never loads torch."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
import time
from typing import Callable, Iterator, Mapping, Sequence

from .detect import _mask, SECRET_KEYS
from .ml import FieldInput, run_detector
from .ml.detector import ContextualPIIDetector
from .ml.schema import DEFAULT_MAX_FIELD_CHARS, DEFAULT_MAX_FIELDS, MAX_LOCATION_CHARS
from .ml.schema import MlValidationError
from .ml.input_policy import MAX_REPLACEMENT_RATIO, QUALITY_FLAGS


class InferenceError(RuntimeError):
    """Sanitized failure of requested contextual inference; never a fallback."""
    ml_inference_failed = True


MAX_SCAN_ML_FIELDS = 10_000
MAX_SCAN_ML_CHARACTERS = 2_000_000


@dataclass(frozen=True)
class MLWorkBudget:
    """Independent, finite ML budgets; larger capture profiles do not change these.

    Totals may be zero to deliberately disable work. Per-field bounds can only
    tighten the model input contract. All lengths are Unicode code points.
    """
    max_fields_per_batch: int = 256
    max_characters_per_batch: int = 131_072
    max_total_fields: int = MAX_SCAN_ML_FIELDS
    max_total_characters: int = MAX_SCAN_ML_CHARACTERS
    max_field_characters: int = DEFAULT_MAX_FIELD_CHARS

    def __post_init__(self):
        ceilings = dict(max_fields_per_batch=DEFAULT_MAX_FIELDS,
                        max_characters_per_batch=2_000_000,
                        max_total_fields=1_000_000,
                        max_total_characters=200_000_000,
                        max_field_characters=DEFAULT_MAX_FIELD_CHARS)
        for name, value in asdict(self).items():
            minimum = 0 if name.startswith('max_total_') else 1
            if type(value) is not int or not minimum <= value <= ceilings[name]:
                raise ValueError(f'{name} must be an integer in [{minimum}, {ceilings[name]}]')

    @classmethod
    def for_profile(cls, profile: str = 'standard', **overrides) -> 'MLWorkBudget':
        profiles = {'standard': {}, 'extended': dict(max_total_fields=100_000,
                                                     max_total_characters=20_000_000)}
        if profile not in profiles:
            raise ValueError('ML budget profile must be standard or extended')
        return cls(**(profiles[profile] | overrides))


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
    completed_batches: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)


_RESERVED_FIELD = re.compile(r'(?:^|[.\[_-])(?:e_?mail|phone|telephone|mobile|card|credit_?card|cc_?number|ip|ip_?address|content_?length)(?:$|[.\]_-])', re.I)


def _excluded(location: str) -> bool:
    return location.startswith('header.') or bool(SECRET_KEYS.search(location) or _RESERVED_FIELD.search(location))


def load_experimental_bilstm(checkpoint_dir: str) -> ContextualPIIDetector:
    """Explicit opt-in: import torch and verify the checkpoint only if selected."""
    from .ml.infer import BiLSTMDetector
    return BiLSTMDetector(checkpoint_dir)


def _predict_batch(batch, detector, include_values):
    started = time.perf_counter()
    try:
        predictions = run_detector(detector, batch)
        lookup = {item.field_index: item for item in batch}
        findings = []
        for span in predictions:
            source = lookup[span.field_index]
            if span.model_version != detector.model_version:
                raise MlValidationError('Detector returned a different model version')
            if span.score is None:
                raise MlValidationError('Experimental detector must provide a typed score for report output')
            original_value = source.text[span.start:span.end]
            finding = {
                'pii_type': span.label.value, 'location': source.location,
                'confidence': span.score, 'confidence_type': span.score_type.value,
                'value': original_value if include_values else _mask(original_value),
                'detector': 'bilstm', 'model_version': span.model_version,
                'span_start': span.start, 'span_end': span.end,
                'field_index': span.field_index,
            }
            flags = sorted(k for k, v in source.context.items() if k in QUALITY_FLAGS and v == 'true')
            if flags:
                finding['input_quality'] = flags
            findings.append(finding)
    except MlValidationError as exc:
        exc.ml_inference_failed = True
        raise
    except Exception as exc:
        raise InferenceError('Contextual model inference failed') from exc
    return findings, time.perf_counter() - started


def iter_http_field_batches(
    fields: Sequence[tuple[str, str]], detector: ContextualPIIDetector, *,
    include_values: bool = False, work_budget: MLWorkBudget | None = None,
    fields_evaluated: int = 0, characters_evaluated: int = 0,
    before_batch: Callable[[], None] | None = None,
    field_observer: Callable[[int, str, str | None], None] | None = None,
    quality: Mapping[str, str] | None = None,
) -> Iterator[InferenceResult]:
    """Yield bounded findings and accounting deltas, retaining one working batch.

    Previously evaluated totals apply scan-wide limits across messages. Original
    indices remain message-local, including excluded, empty and skipped fields.
    A callback may raise to cancel; inference is never retried. The observer gets
    indices/status/reason only, after validated inference for evaluated fields.
    """
    budget = MLWorkBudget() if work_budget is None else work_budget
    if not isinstance(budget, MLWorkBudget):
        raise TypeError('work_budget must be MLWorkBudget')
    for name, value in (('fields_evaluated', fields_evaluated),
                        ('characters_evaluated', characters_evaluated)):
        if type(value) is not int or value < 0:
            raise ValueError(f'{name} must be a non-negative integer')
    clean_quality = {k: v for k, v in (quality or {}).items() if k in QUALITY_FLAGS and v == 'true'}
    batch = []
    characters = excluded = empty = skipped = examined = 0
    reasons = {}

    def observe(index, status, reason=None):
        if field_observer is not None:
            field_observer(index, status, reason)

    def flush():
        nonlocal batch, characters, excluded, empty, skipped, examined, reasons
        nonlocal fields_evaluated, characters_evaluated
        if before_batch is not None:
            before_batch()
        findings, elapsed = _predict_batch(batch, detector, include_values) if batch else ([], 0.0)
        for item in batch:
            observe(item.field_index, 'evaluated')
        count = len(batch)
        result = InferenceResult(findings, count, skipped, excluded, count + skipped,
                                 empty, characters, elapsed, bool(batch), int(bool(batch)), reasons)
        fields_evaluated += count
        characters_evaluated += characters
        batch = []
        characters = excluded = empty = skipped = examined = 0
        reasons = {}
        return result

    for index, (location, text) in enumerate(fields):
        # Bound cancellation checks even when every field is excluded or skipped.
        if examined >= budget.max_fields_per_batch:
            yield flush()
        if (batch and (len(batch) >= budget.max_fields_per_batch or
                       characters + len(text) > budget.max_characters_per_batch)):
            yield flush()
        examined += 1
        if isinstance(location, str) and _excluded(location):
            excluded += 1
            observe(index, 'excluded_by_policy')
            continue
        if not text:
            empty += 1
            observe(index, 'empty')
            continue
        if text.count('\ufffd') / len(text) > MAX_REPLACEMENT_RATIO:
            excluded += 1
            observe(index, 'excluded_by_policy')
            continue
        reason = None
        if not isinstance(location, str) or not location:
            reason = 'ml_field_path_invalid'
        elif len(location) > MAX_LOCATION_CHARS:
            reason = 'ml_field_path_too_long'
        elif len(text) > budget.max_field_characters:
            reason = 'ml_field_too_large'
        elif len(text) > budget.max_characters_per_batch:
            reason = 'ml_batch_character_budget_exceeded'
        elif fields_evaluated + len(batch) >= budget.max_total_fields:
            reason = 'ml_field_budget_exceeded'
        elif len(text) > budget.max_total_characters - characters_evaluated - characters:
            reason = 'ml_character_budget_exceeded'
        if reason:
            skipped += 1
            reasons[reason] = reasons.get(reason, 0) + 1
            observe(index, 'skipped', reason)
            continue
        field_context = dict(clean_quality)
        if '\ufffd' in text:
            field_context['decode_replaced'] = 'true'
        batch.append(FieldInput(index, location, text, field_context))
        characters += len(text)
    if examined:
        yield flush()


def infer_http_fields(
    fields: Sequence[tuple[str, str]], detector: ContextualPIIDetector, *,
    include_values: bool = False, max_fields: int = DEFAULT_MAX_FIELDS,
    max_characters: int = MAX_SCAN_ML_CHARACTERS,
    quality: Mapping[str, str] | None = None,
) -> InferenceResult:
    """Compatible materializing adapter; the scan engine uses the batch iterator."""
    budget = MLWorkBudget(max_total_fields=max_fields, max_total_characters=max_characters)
    findings, reasons = [], {}
    totals = dict(fields_evaluated=0, fields_skipped=0, fields_excluded=0,
                  fields_eligible=0, fields_empty=0, characters_evaluated=0,
                  processing_time_seconds=0.0, completed_batches=0)
    invoked = False
    for result in iter_http_field_batches(fields, detector, include_values=include_values,
                                         work_budget=budget, quality=quality):
        findings.extend(result.findings)
        for key in totals:
            totals[key] += getattr(result, key)
        for reason, count in result.skip_reasons.items():
            reasons[reason] = reasons.get(reason, 0) + count
        invoked |= result.invoked
    return InferenceResult(findings, invoked=invoked, skip_reasons=reasons, **totals)
