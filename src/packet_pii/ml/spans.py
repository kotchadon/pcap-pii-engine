"""Deterministic Unicode tokenizer with character offsets, BIO tagging and span decoding.

Pure standard library (no torch). Offsets are zero-based Unicode code-point
offsets into the original string, half-open ``[start, end)``, matching
``EntitySpan``.

Tokens are maximal runs of "word characters" (alphanumeric, ``_`` or a combining
mark) or single non-space characters (punctuation/symbols/emoji). Whitespace is
skipped. So ``cool.cat`` -> ``cool`` ``.`` ``cat`` and ``O'Brien`` -> ``O`` ``'`` ``Brien``.
"""
from __future__ import annotations

import math
import unicodedata
from dataclasses import dataclass
from typing import Sequence

LABELS = ("PERSON_NAME", "USERNAME")
TAGS = ("O", "B-PERSON_NAME", "I-PERSON_NAME", "B-USERNAME", "I-USERNAME")
TAG2ID = {t: i for i, t in enumerate(TAGS)}
O_ID = 0


class AlignmentError(ValueError):
    """A gold span does not align to token boundaries or overlaps another. No raw text in message."""


@dataclass(frozen=True)
class Token:
    text: str
    start: int
    end: int


def _is_word_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_" or unicodedata.category(ch).startswith("M")


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
        elif _is_word_char(ch):
            j = i + 1
            while j < n and _is_word_char(text[j]):
                j += 1
            tokens.append(Token(text[i:j], i, j))
            i = j
        else:
            tokens.append(Token(ch, i, i + 1))
            i += 1
    return tokens


def spans_to_tags(tokens: Sequence[Token], spans: Sequence[tuple[int, int, str]]) -> list[int]:
    """Gold character spans -> BIO tag ids. Strict: raises AlignmentError, never drops a span."""
    tags = [O_ID] * len(tokens)
    start_at = {t.start: k for k, t in enumerate(tokens)}
    end_at = {t.end: k for k, t in enumerate(tokens)}
    for (s, e, label) in spans:
        if label not in LABELS:
            raise AlignmentError("unknown label in gold span")
        if s not in start_at or e not in end_at or end_at[e] < start_at[s]:
            raise AlignmentError(f"gold span [{s},{e}) does not align to token boundaries")
        for k in range(start_at[s], end_at[e] + 1):
            if tags[k] != O_ID:
                raise AlignmentError(f"gold span [{s},{e}) overlaps another span")
            tags[k] = TAG2ID[("B-" if k == start_at[s] else "I-") + label]
    return tags


_NEG = -math.inf


def _allowed(prev: int, cur: int) -> bool:
    name = TAGS[cur]
    if not name.startswith("I-"):
        return True
    label = name[2:]
    return TAGS[prev] in ("B-" + label, "I-" + label)


def viterbi_decode(logprobs: Sequence[Sequence[float]]) -> list[int]:
    """BIO-constraint-aware best path over per-token log-probabilities.

    Forbidden: starting on I-*, O->I-*, and B/I-X -> I-Y for Y != X.
    """
    n, k = len(logprobs), len(TAGS)
    if n == 0:
        return []
    score = [[_NEG] * k for _ in range(n)]
    back = [[0] * k for _ in range(n)]
    for c in range(k):
        if not TAGS[c].startswith("I-"):
            score[0][c] = logprobs[0][c]
    for t in range(1, n):
        for c in range(k):
            best, arg = _NEG, 0
            for p in range(k):
                if score[t - 1][p] > _NEG and _allowed(p, c) and score[t - 1][p] > best:
                    best, arg = score[t - 1][p], p
            if best > _NEG:
                score[t][c] = best + logprobs[t][c]
                back[t][c] = arg
    c = max(range(k), key=lambda x: score[-1][x])
    path = [c]
    for t in range(n - 1, 0, -1):
        c = back[t][c]
        path.append(c)
    return path[::-1]


def tags_to_spans(tokens: Sequence[Token], tag_ids: Sequence[int],
                  tag_probs: Sequence[float] | None = None) -> list[tuple[int, int, str, float | None]]:
    """BIO tag ids -> (start, end, label, score). Tolerant of invalid I-* (starts a new span).

    ``score`` is the mean probability of the chosen tags over the span's tokens
    (a raw, uncalibrated model score) or None when ``tag_probs`` is not given.
    """
    out = []
    cur = None  # [first_idx, last_idx, label]
    def close():
        if cur is not None:
            a, b, label = cur
            sc = None if tag_probs is None else sum(tag_probs[a:b + 1]) / (b - a + 1)
            out.append((tokens[a].start, tokens[b].end, label, sc))
    for i, tid in enumerate(tag_ids):
        name = TAGS[tid]
        if name == "O":
            close(); cur = None
        elif name.startswith("B-") or cur is None or cur[2] != name[2:]:
            close(); cur = [i, i, name[2:]]
        else:
            cur[1] = i
    close()
    return out
