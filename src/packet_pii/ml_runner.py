"""Bounded, chunked contextual-model inference across all HTTP messages of one scan.

``MLBatchRunner`` replaces per-message inference calls. Eligible fields from many messages are queued and run through
the detector in bounded batches, so the model is invoked far fewer times and work is limited by an explicit, validated
``MLWorkBudget`` instead of an arbitrary hard cut-off. Every eligible field is either evaluated or counted as skipped
with a reason; nothing is dropped silently, truncated, or reported as covered when it was not.

The runner never changes what the model sees (location + text; quality flags travel in ``FieldInput.context``, which the
BiLSTM ignores) and never re-orders findings: results are released in message order, and within a message in the
detector's deterministic span order, so output does not depend on batch size.
"""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
import time
from typing import Callable, Mapping, Sequence

from .detect import _mask
from .hybrid import InferenceError, _excluded
from .ml import FieldInput, run_detector
from .ml.detector import ContextualPIIDetector
from .ml.input_policy import MAX_REPLACEMENT_RATIO, QUALITY_FLAGS
from .ml.schema import DEFAULT_MAX_FIELD_CHARS, DEFAULT_MAX_FIELDS, MAX_LOCATION_CHARS, MlValidationError

SKIP_REASONS = ('location_too_long', 'field_too_large', 'invalid_field', 'time_budget', 'field_budget', 'character_budget')
COVERAGE_STATES = ('not_requested', 'unavailable', 'no_eligible_fields', 'complete', 'partial', 'failed')


@dataclass(frozen=True)
class MLWorkBudget:
    """Validated limits on contextual inference for one scan. There is deliberately no "unlimited" value.

    ``max_fields``/``max_characters`` bound the eligible fields and characters admitted to the model. ``max_seconds`` bounds
    cumulative model time (not parsing). ``batch_fields``/``batch_characters`` bound a single detector call (memory).
    """
    max_fields: int = 10_000
    max_characters: int = 2_000_000
    max_seconds: float = 60.0
    batch_fields: int = 256
    batch_characters: int = 262_144
    max_field_chars: int = DEFAULT_MAX_FIELD_CHARS
    name: str = 'custom'

    # Absolute ceilings: even the most generous profile stays bounded.
    CEILING_FIELDS = 5_000_000
    CEILING_CHARACTERS = 1_000_000_000
    CEILING_SECONDS = 7_200.0

    def __post_init__(self) -> None:
        for key in ('max_fields', 'max_characters', 'batch_fields', 'batch_characters', 'max_field_chars'):
            value = getattr(self, key)
            if type(value) is not int or value <= 0:
                raise ValueError(f'{key} must be a positive integer')
        if type(self.max_seconds) not in (int, float) or not 0 < self.max_seconds <= self.CEILING_SECONDS:
            raise ValueError('max_seconds must be in (0, 7200]')
        if self.max_fields > self.CEILING_FIELDS or self.max_characters > self.CEILING_CHARACTERS:
            raise ValueError('ML work budget exceeds the absolute ceiling')
        if self.batch_fields > DEFAULT_MAX_FIELDS:
            raise ValueError(f'batch_fields must be <= {DEFAULT_MAX_FIELDS} (detector request limit)')
        if self.max_field_chars > DEFAULT_MAX_FIELD_CHARS:
            raise ValueError(f'max_field_chars must be <= {DEFAULT_MAX_FIELD_CHARS} (detector field limit)')
        if self.batch_characters < self.max_field_chars:
            raise ValueError('batch_characters must be at least max_field_chars')
        if not isinstance(self.name, str) or not self.name or len(self.name) > 40:
            raise ValueError('name must be a short non-empty string')

    @classmethod
    def for_profile(cls, name: str) -> 'MLWorkBudget':
        profiles = {
            'standard': dict(max_fields=10_000, max_characters=2_000_000, max_seconds=60.0),
            'extended': dict(max_fields=100_000, max_characters=20_000_000, max_seconds=300.0),
            'complete': dict(max_fields=1_000_000, max_characters=200_000_000, max_seconds=1_800.0),
        }
        if name not in profiles:
            raise ValueError('ML coverage profile must be standard, extended or complete')
        return cls(name=name, **profiles[name])

    def public(self) -> dict:
        return {'profile': self.name, 'max_fields': self.max_fields, 'max_characters': self.max_characters,
                'max_seconds': self.max_seconds, 'batch_fields': self.batch_fields,
                'batch_characters': self.batch_characters, 'max_field_chars': self.max_field_chars}


ML_PROFILES = ('standard', 'extended', 'complete')


class _Ticket:
    __slots__ = ('key', 'findings', 'outstanding')

    def __init__(self, key):
        self.key, self.findings, self.outstanding = key, [], 0


class _Item:
    __slots__ = ('slot', 'ticket', 'index', 'field')

    def __init__(self, slot, ticket, index, field):
        self.slot, self.ticket, self.index, self.field = slot, ticket, index, field


class MLBatchRunner:
    """Queue eligible fields from many messages and infer them in bounded, order-preserving batches.

    ``checkpoint`` is called before and after every detector call with a small counter dict; it may raise (for example to
    cancel the scan). A failure of the detector raises ``InferenceError``/``MlValidationError`` flagged
    ``ml_inference_failed``; the runner is then unusable and the caller must not publish a result.
    """

    def __init__(self, detector: ContextualPIIDetector, budget: MLWorkBudget, *, include_values: bool = False,
                 checkpoint: Callable[[dict], None] | None = None, max_pending_messages: int = 4096,
                 disposition: Callable[[object, int, str], None] | None = None,
                 zero_work: bool = False):
        if not isinstance(budget, MLWorkBudget):
            raise TypeError('budget must be an MLWorkBudget')
        self.detector, self.budget, self.include_values = detector, budget, include_values
        self._checkpoint, self._max_pending_messages = checkpoint, max_pending_messages
        self._disposition = disposition  # optional (ticket key, field index, status) audit hook; carries no text
        self._field_limit, self._char_limit = (0 if zero_work else budget.max_fields), budget.max_characters
        self._pending: list[_Item] = []
        self._pending_chars = 0
        self._order: deque[_Ticket] = deque()
        self._next_slot = 0
        self.eligible = self.evaluated = self.excluded = self.empty = self.skipped = 0
        self.characters = self.batches = self.inferred = 0
        self.seconds = 0.0
        self.skip_reasons: Counter = Counter()
        self.labels: Counter = Counter()

    # ------------------------------------------------------------------ admission
    def add(self, key, fields: Sequence[tuple[str, str]], quality: Mapping[str, str] | None = None) -> None:
        """Register one message's extracted fields. ``key`` identifies the message when results are released."""
        ticket = _Ticket(key)
        self._order.append(ticket)
        flags = {k: v for k, v in (quality or {}).items() if k in QUALITY_FLAGS}
        budget = self.budget
        for index, (location, text) in enumerate(fields):
            if _excluded(location):
                self.excluded += 1
                self._note(key, index, 'excluded_by_policy')
                continue
            if not text:
                self.empty += 1
                self._note(key, index, 'empty')
                continue
            if text.count('\ufffd') / len(text) > MAX_REPLACEMENT_RATIO:
                self.excluded += 1
                self._note(key, index, 'excluded_by_policy')
                continue
            self.eligible += 1
            reason = None
            if not location:
                reason = 'invalid_field'
            elif len(location) > MAX_LOCATION_CHARS:
                reason = 'location_too_long'
            elif len(text) > budget.max_field_chars:
                reason = 'field_too_large'
            elif self.seconds >= budget.max_seconds:
                reason = 'time_budget'
            elif self.evaluated >= self._field_limit:
                reason = 'field_budget'
            elif len(text) > self._char_limit - self.characters:
                reason = 'character_budget'
            if reason is not None:
                self.skipped += 1
                self.skip_reasons[reason] += 1
                self._note(key, index, 'skipped:' + reason)
                continue
            context = dict(flags)
            if '\ufffd' in text:
                context['decode_replaced'] = 'true'
            self._pending.append(_Item(self._next_slot, ticket, index, FieldInput(self._next_slot, location, text, context)))
            self._next_slot += 1
            self._pending_chars += len(text)
            self.evaluated += 1
            self.characters += len(text)
            ticket.outstanding += 1
            self._note(key, index, 'evaluated')
        if len(self._order) >= self._max_pending_messages:
            self.flush()  # bound on queued messages: drain everything
        elif len(self._pending) >= budget.batch_fields or self._pending_chars >= budget.batch_characters:
            self.flush(final=False)

    def _note(self, key, index: int, status: str) -> None:
        if self._disposition is not None:
            self._disposition(key, index, status)

    # ------------------------------------------------------------------ inference
    def flush(self, *, final: bool = True) -> None:
        """Run queued fields through the detector in bounded sub-batches, preserving order.

        With ``final=False`` only completely filled batches run and the remainder stays queued so it can join later
        messages' fields (fewer, fuller detector calls). ``final=True`` drains everything.
        """
        budget = self.budget
        while self._pending:
            take, chars, full = 0, 0, False
            for item in self._pending:
                size = len(item.field.text)
                if take and (take >= budget.batch_fields or chars + size > budget.batch_characters):
                    full = True
                    break
                take, chars = take + 1, chars + size
            full = full or take >= budget.batch_fields or chars >= budget.batch_characters
            if not full and not final:
                return
            batch, self._pending = self._pending[:take], self._pending[take:]
            self._pending_chars -= chars
            self._notify()
            self._run(batch)
            self._notify()

    def _notify(self) -> None:
        if self._checkpoint is not None:
            self._checkpoint({'ml_fields_evaluated_so_far': self.inferred,
                              'ml_fields_eligible_so_far': self.eligible, 'ml_batches': self.batches})

    def _run(self, batch: list[_Item]) -> None:
        started = time.perf_counter()
        try:
            predictions = run_detector(self.detector, [item.field for item in batch])
        except MlValidationError as exc:
            exc.ml_inference_failed = True  # contract errors carry indices/types, never field text
            raise
        except Exception as exc:
            raise InferenceError('Contextual model inference failed') from exc
        self.seconds += time.perf_counter() - started
        self.batches += 1
        by_slot = {item.slot: item for item in batch}
        for span in predictions:
            item = by_slot.get(span.field_index)
            error = None
            if item is None:
                error = 'Detector returned a span for an unknown field'
            elif span.model_version != self.detector.model_version:
                error = 'Detector returned a different model version'
            elif span.score is None:
                error = 'Experimental detector must provide a typed score for report output'
            if error:
                failure = MlValidationError(error)
                failure.ml_inference_failed = True
                raise failure
            original = item.field.text[span.start:span.end]
            finding = {
                'pii_type': span.label.value,
                'location': item.field.location,
                'confidence': span.score,  # raw, uncalibrated; never averaged with rules
                'confidence_type': span.score_type.value,
                'value': original if self.include_values else _mask(original),
                'detector': 'bilstm',
                'model_version': span.model_version,
                'span_start': span.start,
                'span_end': span.end,
                'field_index': item.index,  # position within the HTTP message's extracted fields
            }
            quality = sorted(k for k in QUALITY_FLAGS if item.field.context.get(k) == 'true')
            if quality:
                finding['input_quality'] = quality
            item.ticket.findings.append(finding)
            self.labels[span.label.value] += 1
        for item in batch:
            item.ticket.outstanding -= 1
        self.inferred += len(batch)

    # ------------------------------------------------------------------ release
    def take_ready(self) -> list[tuple[object, list[dict]]]:
        """Messages whose fields have all been inferred, in the order they were added."""
        ready = []
        while self._order and self._order[0].outstanding == 0:
            ticket = self._order.popleft()
            ready.append((ticket.key, ticket.findings))
        return ready

    # ------------------------------------------------------------------ accounting
    @property
    def invoked(self) -> bool:
        return self.batches > 0

    @property
    def status(self) -> str:
        if self.eligible == 0:
            return 'no_eligible_fields'
        return 'partial' if self.skipped else 'complete'

    @property
    def coverage_ratio(self) -> float | None:
        return None if self.eligible == 0 else round(self.evaluated / self.eligible, 6)
