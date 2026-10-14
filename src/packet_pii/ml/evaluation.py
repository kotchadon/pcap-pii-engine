"""Torch-free evaluation helpers: slices, bootstrap CIs, hybrid policies, reliability. No raw text is returned.

Spans are ``(start, end, label)``; scored spans are ``(start, end, label, score)``.
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from .encoding import location_tokens
from .spans import tokenize

Span = tuple[int, int, str]


def per_example_counts(gold: Mapping[object, Iterable[Span]], pred: Mapping[object, Iterable[Span]]) -> dict:
    out = {}
    for ex in list(gold) + [e for e in pred if e not in gold]:
        g, p = set(gold.get(ex, ())), set(pred.get(ex, ()))
        out[ex] = (len(g & p), len(p - g), len(g - p))
    return out


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0, "tp": tp, "fp": fp, "fn": fn}


def bootstrap_ci(counts: Mapping[object, tuple], reps: int = 1000, seed: int = 0, alpha: float = 0.05) -> dict:
    """Percentile CI of micro-F1 / precision / recall, resampling EXAMPLES with replacement."""
    vals = list(counts.values())
    n, rng = len(vals), random.Random(seed)
    f1s, ps, rs = [], [], []
    for _ in range(reps):
        tp = fp = fn = 0
        for _i in range(n):
            a, b, c = vals[rng.randrange(n)]
            tp += a; fp += b; fn += c
        m = prf(tp, fp, fn); f1s.append(m["f1"]); ps.append(m["precision"]); rs.append(m["recall"])
    q = lambda xs, f: sorted(xs)[min(len(xs) - 1, max(0, int(f * len(xs))))]
    return {k: [round(q(v, alpha / 2), 4), round(q(v, 1 - alpha / 2), 4)] for k, v in (("f1", f1s), ("precision", ps), ("recall", rs))}


def paired_bootstrap_diff(counts_a: Mapping, counts_b: Mapping, reps: int = 1000, seed: int = 0) -> dict:
    """CI of F1(a) - F1(b) on the same examples (paired resampling)."""
    ids = list(counts_a)
    n, rng, d = len(ids), random.Random(seed), []
    for _ in range(reps):
        sa = [0, 0, 0]; sb = [0, 0, 0]
        for _i in range(n):
            k = ids[rng.randrange(n)]
            for j in range(3):
                sa[j] += counts_a[k][j]; sb[j] += counts_b.get(k, (0, 0, 0))[j]
        d.append(prf(*sa)["f1"] - prf(*sb)["f1"])
    d.sort()
    return {"mean": round(sum(d) / len(d), 4), "ci95": [round(d[int(.025 * reps)], 4), round(d[int(.975 * reps)], 4)],
            "p_a_not_better": round(sum(1 for x in d if x <= 0) / reps, 4)}


# ------------------------------------------------------------------ context-novelty slices
_DIG = re.compile(r"\d")


@dataclass
class TrainContext:
    """What the training set has seen: key tokens, entity left-contexts and value-only key tails."""
    key_tokens: set = field(default_factory=set)
    left_ctx: set = field(default_factory=set)
    last_key: set = field(default_factory=set)

    @staticmethod
    def build(train_examples: Iterable) -> "TrainContext":
        t = TrainContext()
        for e in train_examples:
            kt = location_tokens(e.location)
            t.key_tokens.update(kt)
            for s, en, _ in e.spans:
                c = _left_context(e.text, s)
                if c is None:
                    if kt: t.last_key.add(kt[-1])
                else:
                    t.left_ctx.add(c)
        return t

    def unseen_key(self, ex) -> bool:
        return any(k not in self.key_tokens for k in location_tokens(ex.location))

    def unseen_context(self, ex, span) -> bool:
        c = _left_context(ex.text, span[0])
        if c is None:
            kt = location_tokens(ex.location)
            return not kt or kt[-1] not in self.last_key
        return c not in self.left_ctx


def _left_context(text: str, start: int):
    """Two normalised tokens before ``start`` (None when the entity opens the field)."""
    toks = [t for t in tokenize(text[:start])]
    if not toks:
        return None
    return tuple(_DIG.sub("0", t.text.lower()) for t in toks[-2:])


def recall_on(gold_examples: Sequence, pred: Mapping, predicate) -> dict:
    tp = fn = 0
    for e in gold_examples:
        p = set(pred.get(e.id, ()))
        for sp in e.spans:
            if predicate(e, sp):
                if sp in p: tp += 1
                else: fn += 1
    return {"n": tp + fn, "recall": round(tp / (tp + fn), 4) if tp + fn else None}


def no_entity_false_positive_rate(examples: Sequence, pred: Mapping, only_tag: str | None = None) -> dict:
    """Fraction of entity-free examples on which the system emitted >=1 span (per-example FP rate)."""
    neg = [e for e in examples if not e.spans and (only_tag is None or only_tag in getattr(e, "tags", ()))]
    hit = sum(1 for e in neg if pred.get(e.id))
    return {"n": len(neg), "with_false_positive": hit, "rate": round(hit / len(neg), 4) if neg else None}


# ------------------------------------------------------------------ hybrid policies
def _overlap(a: Span, b: Span) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def hybrid_rules_first(rule_spans: Sequence[Span], ml_spans: Sequence[tuple], tau_add: float,
                       veto_ids: Sequence[Span] = (), tau_veto: float | None = None) -> list[Span]:
    """Rules-first combination.

    * every rule span is kept (rules win label/boundary conflicts);
    * an ML span is ADDED only if it overlaps no rule span and score >= tau_add;
    * optional veto: rule spans listed in ``veto_ids`` (ambiguous-key matches) are dropped when ML has NO overlapping
      span with score >= tau_veto.
    Scores of the two sources are never mixed into one number: the output is a span set.
    """
    kept = []
    for r in rule_spans:
        if tau_veto is not None and r in set(veto_ids):
            if not any(_overlap(r, m) and m[3] >= tau_veto for m in ml_spans):
                continue
        kept.append(r)
    out = list(kept)
    for m in sorted(ml_spans, key=lambda x: -x[3]):
        sp = (m[0], m[1], m[2])
        if m[3] >= tau_add and not any(_overlap(sp, r) for r in rule_spans) and not any(_overlap(sp, o) for o in out):
            out.append(sp)
    return sorted(out)


def hybrid_union(rule_spans: Sequence[Span], ml_spans: Sequence[tuple], tau: float) -> list[Span]:
    return sorted(set(rule_spans) | {(s, e, l) for s, e, l, sc in ml_spans if sc >= tau})


def reliability_bins(pairs: Sequence[tuple], bins: int = 10) -> tuple:
    """(ECE, rows) of raw score vs span correctness; pairs = (score, 0/1)."""
    if not pairs:
        return None, []
    tot, ece, rows = len(pairs), 0.0, []
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        sel = [(s, c) for s, c in pairs if lo <= s < hi or (b == bins - 1 and s >= 1.0)]
        if sel:
            conf, acc = sum(s for s, _ in sel) / len(sel), sum(c for _, c in sel) / len(sel)
            ece += len(sel) / tot * abs(conf - acc)
            rows.append({"bin": f"[{lo:.1f},{hi:.1f})", "n": len(sel), "mean_score": round(conf, 3), "precision": round(acc, 3)})
    return round(ece, 4), rows
