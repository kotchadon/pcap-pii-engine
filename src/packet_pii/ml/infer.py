"""Checkpoint-backed implementation of ``ContextualPIIDetector`` (requires PyTorch)."""
from __future__ import annotations

from typing import Sequence

from .bilstm import CheckpointError, SpanPredictor, load_predictor
from .schema import EntitySpan, FieldInput, ScoreType, validate_fields


class BiLSTMDetector:
    """Loads a trained BiLSTM checkpoint (single model, or a V2 ensemble directory) and returns validated ``EntitySpan`` objects.

    * ``score`` is the mean softmax probability of the chosen BIO tags over the span:
      an UNCALIBRATED raw model score (``ScoreType.UNCALIBRATED_MODEL_SCORE``), not a probability
      of correctness.
    * ``min_score`` filters spans (default: the operating point stored in the checkpoint metadata,
      chosen on the calibration split).
    * Never logs or stores text; works offline on CPU; deterministic for a fixed checkpoint.
    * ``batch_size`` is the internal forward-batch size (chunks); ``max_batch_tokens`` bounds padded positions per
      forward batch; ``length_bucketing=False`` restores legacy input-order batching. None of these change predictions.
    """

    # Predictions depend only on (location, text) - ``FieldInput.context`` is ignored - so a caller may reuse them for an
    # identical (location, text) pair within one scan (see ``MLBatchRunner``).
    prediction_cache_safe = True

    def __init__(self, checkpoint_dir: str, min_score: float | None = None, batch_size: int = SpanPredictor.DEFAULT_BATCH_SIZE,
                 *, length_bucketing: bool = True, max_batch_tokens: int | None = None):
        self._predictor, self._meta = load_predictor(checkpoint_dir, batch_size if type(batch_size) is int and batch_size >= 1 else 64,
                                                     length_bucketing=length_bucketing, max_batch_tokens=max_batch_tokens)
        ms = self._meta.get("min_score", 0.0) if min_score is None else min_score
        if type(ms) not in (int, float) or not 0.0 <= ms <= 1.0:
            raise CheckpointError("min_score must be a number in [0, 1]")
        if type(batch_size) is not int or batch_size < 1:
            raise ValueError("batch_size must be a positive int")
        self._min_score = float(ms)

    @property
    def model_version(self) -> str:
        return self._meta["model_version"]

    @property
    def min_score(self) -> float:
        return self._min_score

    def predict_fields(self, fields: Sequence[FieldInput]) -> list[EntitySpan]:
        fields = validate_fields(fields)
        pairs = [(f.location, f.text) for f in fields]
        raw = self._predictor.predict_pairs(pairs)
        out = []
        for f, spans in zip(fields, raw):
            for s, e, label, score in spans:
                if score >= self._min_score:
                    out.append(EntitySpan(f.field_index, label, s, e, self.model_version, round(score, 6),
                                          ScoreType.UNCALIBRATED_MODEL_SCORE))
        return sorted(out, key=EntitySpan.sort_key)
