"""Entity-level (exact span + label) metrics. Pure standard library."""
from __future__ import annotations

from typing import Iterable, Mapping

from .spans import LABELS

Span = tuple[int, str, int, int, str]  # (example_id, label) packed as (ex, label, start, end) below


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": p, "recall": r, "f1": f, "tp": tp, "fp": fp, "fn": fn, "support": tp + fn}


def entity_metrics(gold: Mapping[object, Iterable[tuple[int, int, str]]],
                   pred: Mapping[object, Iterable[tuple[int, int, str]]]) -> dict:
    """Exact (start, end, label) match per example id.

    Ids missing from ``pred`` mean no predictions (their gold spans are false negatives); ids present in
    ``pred`` but missing from ``gold`` have empty gold, so all their predictions are false positives.
    """
    counts = {l: [0, 0, 0] for l in LABELS}
    errors = {"false_positives": [], "false_negatives": []}
    # Predictions for ids absent from gold are false positives (gold is empty for them), never ignored.
    ids = list(gold) + [ex for ex in pred if ex not in gold]
    for ex in ids:
        g = {(s, e, l) for s, e, l in gold.get(ex, ())}
        p = {(s, e, l) for s, e, l in pred.get(ex, ())}
        for l in LABELS:
            gl = {x for x in g if x[2] == l}
            pl = {x for x in p if x[2] == l}
            counts[l][0] += len(gl & pl)
            counts[l][1] += len(pl - gl)
            counts[l][2] += len(gl - pl)
        errors["false_positives"] += [(ex, *x) for x in sorted(p - g)]
        errors["false_negatives"] += [(ex, *x) for x in sorted(g - p)]
    per = {l: _prf(*counts[l]) for l in LABELS}
    micro = _prf(*(sum(counts[l][i] for l in LABELS) for i in range(3)))
    macro_f1 = sum(per[l]["f1"] for l in LABELS) / len(LABELS)
    return {"per_class": per, "micro": micro, "macro_f1": macro_f1, "errors": errors}


def error_samples(errors: list, examples_by_id: Mapping[object, object], limit: int = 25,
                  include_text: bool = False) -> list[dict]:
    """Summarise error tuples ``(id, start, end, label)`` for reports.

    By default NO raw field text, location or entity string is exported: only the example id, kind,
    label, offsets and lengths. ``include_text=True`` (explicit opt-in) adds location, text and span text.
    """
    out = []
    for ex_id, s, e, label in errors[:limit]:
        ex = examples_by_id.get(ex_id)
        row = {"id": ex_id, "kind": getattr(ex, "kind", None), "label": label, "start": s, "end": e,
               "span_length": e - s, "text_length": len(ex.text) if ex is not None else None}
        if include_text and ex is not None:
            row.update({"location": ex.location, "text": ex.text, "span": ex.text[s:e]})
        out.append(row)
    return out
