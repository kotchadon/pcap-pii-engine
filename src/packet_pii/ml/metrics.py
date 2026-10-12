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
    """Exact (start, end, label) match per example id. Missing ids in ``pred`` mean no predictions."""
    counts = {l: [0, 0, 0] for l in LABELS}
    errors = {"false_positives": [], "false_negatives": []}
    for ex in gold:
        g = {(s, e, l) for s, e, l in gold[ex]}
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
