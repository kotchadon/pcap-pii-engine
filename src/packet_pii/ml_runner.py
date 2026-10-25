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

from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
import hashlib
import sys
import time
from typing import Callable, Mapping, Sequence

from .detect import _mask
from .hybrid import InferenceError, _excluded
from .ml import FieldInput, run_detector
from .ml.detector import ContextualPIIDetector
from .ml.input_policy import MAX_REPLACEMENT_RATIO, QUALITY_FLAGS
from .ml.schema import DEFAULT_MAX_FIELD_CHARS, DEFAULT_MAX_FIELDS, MAX_LOCATION_CHARS, MlValidationError

# Scan-local prediction cache bounds (see ``MLBatchRunner``): entries, and the longest field text that is cached at all
# (long free-text values rarely repeat, so they are not worth hashing or holding).
PREDICTION_CACHE_ENABLED = True
PREDICTION_CACHE_MAX_ENTRIES = 65_536
PREDICTION_CACHE_MAX_BYTES = 16 * 2 ** 20
PREDICTION_CACHE_MAX_FIELD_CHARS = 4_096


def _cache_key(location: str, text: str) -> bytes:
    """Independent digests of exact input; a primary collision must also pass SHA-256 verification.

    Neither digest retains raw text. This is cryptographic collision resistance, not an exact-text identity proof.
    """
    digest = hashlib.blake2b(digest_size=16)
    verifier = hashlib.sha256()
    for part in (str(len(location)).encode('ascii') + b':', location.encode('utf-8', 'surrogatepass'),
                 text.encode('utf-8', 'surrogatepass')):
        digest.update(part)
        verifier.update(part)
    return digest.digest() + verifier.digest()

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
    cancel the scan).

    Prediction cache: when the detector declares ``prediction_cache_safe = True`` (its output depends only on the field
    location and text), an identical ``(location, text)`` pair seen again in this scan reuses the earlier *neural
    prediction* (span offsets, label, raw score) instead of running the model again; inputs are keyed by independent
    BLAKE2b/SHA-256 digests of the exact location and text, so the cache retains no field text. Only predictions are reused: every
    occurrence still gets its own finding, message provenance, field index and quality flags, and still counts as an
    evaluated field against the field and character budgets exactly as before. The cache lives only as long as this
    runner (one scan), is bounded (``PREDICTION_CACHE_*``, least-recently-used eviction), is never logged or serialised,
    and is disabled with ``prediction_cache=False`` or for detectors that do not opt in. ``model_evaluations`` counts
    fields actually sent to the detector and ``cache_hits`` the reused ones; ``evaluated`` = both (model-covered fields). A failure of the detector raises ``InferenceError``/``MlValidationError`` flagged
    ``ml_inference_failed``; the runner is then unusable and the caller must not publish a result.
    """

    def __init__(self, detector: ContextualPIIDetector, budget: MLWorkBudget, *, include_values: bool = False,
                 checkpoint: Callable[[dict], None] | None = None, max_pending_messages: int = 4096,
                 disposition: Callable[[object, int, str], None] | None = None,
                 zero_work: bool = False, prediction_cache: bool | None = None, prediction_cache_entries: int | None = None):
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
        self.model_evaluations = self.cache_hits = self.cache_evictions = 0
        self._cache_value_bytes = 0
        enabled = PREDICTION_CACHE_ENABLED if prediction_cache is None else prediction_cache
        entries = PREDICTION_CACHE_MAX_ENTRIES if prediction_cache_entries is None else prediction_cache_entries
        if type(entries) is not int or entries < 0:
            raise ValueError('prediction_cache_entries must be a non-negative int')
        self._cache_limit = entries
        self._cache: OrderedDict | None = (OrderedDict() if enabled and entries > 0
                                           and getattr(detector, 'prediction_cache_safe', False) is True else None)

    @property
    def prediction_cache_enabled(self) -> bool:
        return self._cache is not None

    # ------------------------------------------------------------------ admission
    def add(self, key, fields: Sequence[tuple[str, str]], quality: Mapping[str, str] | None = None) -> None:
        """Register one message's extracted fields. ``key`` identifies the message when results are released."""
        ticket = _Ticket(key)
        ticket.outstanding = 1  # admission sentinel: checkpoints cannot release a partly admitted message
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
            # Finish the previous character-bounded batch before admitting another field. Keeping at most one
            # batch pending also bounds time-budget overshoot to that single detector call, even for huge messages.
            if (self._pending and len(text) <= budget.max_field_chars
                    and self._pending_chars + len(text) > budget.batch_characters):
                self.flush()
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
            if len(self._pending) >= budget.batch_fields or self._pending_chars >= budget.batch_characters:
                self.flush()
        ticket.outstanding -= 1
        if len(self._order) >= self._max_pending_messages:
            self.flush()  # bound on queued messages: drain everything

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
        cache = self._cache
        reused: dict[int, tuple] = {}     # slot -> cached prediction tuple
        follower: dict[int, int] = {}     # slot -> slot of an identical field earlier in this batch
        to_model = batch
        if cache is not None:
            to_model, leaders = [], {}
            for item in batch:
                if len(item.field.text) > PREDICTION_CACHE_MAX_FIELD_CHARS:
                    to_model.append(item)  # never hashed or cached
                    continue
                key = _cache_key(item.field.location, item.field.text)
                hit = cache.get(key)
                if hit is not None:
                    cache.move_to_end(key)
                    reused[item.slot] = hit
                elif key in leaders:
                    follower[item.slot] = leaders[key]
                else:
                    leaders[key] = item.slot
                    to_model.append(item)
        predictions = []
        if to_model:
            model_started = time.perf_counter()
            try:
                predictions = run_detector(self.detector, [item.field for item in to_model])
            except MlValidationError as exc:
                exc.ml_inference_failed = True  # contract errors carry indices/types, never field text
                raise
            except Exception as exc:
                raise InferenceError('Contextual model inference failed') from exc
            # Budget tracks actual detector work, not cache bookkeeping or finding reconstruction.
            self.seconds += time.perf_counter() - model_started
        by_slot = {item.slot: item for item in to_model}
        fresh: dict[int, list] = {item.slot: [] for item in to_model}
        for span in predictions:  # validated and sorted by (field_index, start, end, label)
            error = None
            if span.field_index not in by_slot:
                error = 'Detector returned a span for an unknown field'
            elif span.model_version != self.detector.model_version:
                error = 'Detector returned a different model version'
            elif span.score is None:
                error = 'Experimental detector must provide a typed score for report output'
            if error:
                failure = MlValidationError(error)
                failure.ml_inference_failed = True
                raise failure
            fresh[span.field_index].append((span.start, span.end, span.label.value, span.score, span.score_type.value,
                                            span.model_version))
        if to_model:
            self.batches += 1
        for item in batch:  # slot order == the order of the detector's sorted output
            slot = item.slot
            spans = fresh[slot] if slot in fresh else reused[slot] if slot in reused else fresh[follower[slot]]
            for start, end, label, score, score_type, model_version in spans:
                original = item.field.text[start:end]
                finding = {
                    'pii_type': label,
                    'location': item.field.location,
                    'confidence': score,  # raw, uncalibrated; never averaged with rules
                    'confidence_type': score_type,
                    'value': original if self.include_values else _mask(original),
                    'detector': 'bilstm',
                    'model_version': model_version,
                    'span_start': start,
                    'span_end': end,
                    'field_index': item.index,  # position within the HTTP message's extracted fields
                }
                quality = sorted(k for k in QUALITY_FLAGS if item.field.context.get(k) == 'true')
                if quality:
                    finding['input_quality'] = quality
                item.ticket.findings.append(finding)
                self.labels[label] += 1
            item.ticket.outstanding -= 1
        if cache is not None:
            for item in to_model:
                if len(item.field.text) <= PREDICTION_CACHE_MAX_FIELD_CHARS:
                    self._remember(_cache_key(item.field.location, item.field.text), tuple(fresh[item.slot]))
        self.inferred += len(batch)
        self.model_evaluations += len(to_model)
        self.cache_hits += len(batch) - len(to_model)

    @staticmethod
    def _entry_bytes(key: bytes, spans: tuple) -> int:
        """Conservative retained Python-object size; shared scalar/string objects are counted again.

        The mapping's own allocation is counted separately. This is not RSS or native allocator accounting.
        """
        return (sys.getsizeof(key) + sys.getsizeof(spans)
                + sum(sys.getsizeof(span) + sum(sys.getsizeof(value) for value in span) for span in spans))

    @property
    def cache_bytes(self) -> int:
        return 0 if self._cache is None else sys.getsizeof(self._cache) + self._cache_value_bytes

    def _remember(self, key: bytes, spans: tuple) -> None:
        cache = self._cache
        if key in cache:
            return
        size = self._entry_bytes(key, spans)
        if size + sys.getsizeof(OrderedDict()) > PREDICTION_CACHE_MAX_BYTES:
            return
        cache[key] = spans or ()
        self._cache_value_bytes += size
        while cache and (len(cache) > self._cache_limit or self.cache_bytes > PREDICTION_CACHE_MAX_BYTES):
            evicted_key, evicted = cache.popitem(last=False)
            self._cache_value_bytes -= self._entry_bytes(evicted_key, evicted)
            self.cache_evictions += 1
        if not cache:
            cache.clear()  # release the hash table's historical capacity, not only its entries

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
    def time_budget_overshoot_seconds(self) -> float:
        """Admitted work finishes; excess cumulative model time is at most one bounded detector call."""
        return round(max(0.0, self.seconds - self.budget.max_seconds), 6)

    @property
    def coverage_ratio(self) -> float | None:
        return None if self.eligible == 0 else round(self.evaluated / self.eligible, 6)


class SharedDetector:
    """Serialises individual detector calls so a scan and a post-scan assessment can interleave safely.

    The wrapped model is not assumed to be re-entrant; each ``predict_fields`` call (one bounded batch) holds the lock,
    so neither stage blocks the other for longer than a single batch.
    """

    def __init__(self, detector):
        import threading
        self._detector, self._lock = detector, threading.Lock()

    @property
    def model_version(self):
        return self._detector.model_version

    @property
    def prediction_cache_safe(self) -> bool:
        # Forward only an explicit opt-in; the shared wrapper does not change model semantics.
        return getattr(self._detector, 'prediction_cache_safe', False) is True

    def predict_fields(self, fields):
        with self._lock:
            return self._detector.predict_fields(fields)


def shared(detector):
    """Idempotent: wrap a detector for shared use (None stays None)."""
    return detector if detector is None or isinstance(detector, SharedDetector) else SharedDetector(detector)
