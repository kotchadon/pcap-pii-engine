"""Frozen BIO decoder equivalence, including ties and unreachable transitions."""
import math
import random
import pytest
from packet_pii.ml import spans
from packet_pii.ml.spans import TAGS
from typing import Sequence
_NEG = -math.inf
# Exact reference decoder from c17abe7f176116629d726a982f49df1f30b052bc.
def _allowed(prev: int, cur: int) -> bool:
    name = TAGS[cur]
    if not name.startswith("I-"):
        return True
    label = name[2:]
    return TAGS[prev] in ("B-" + label, "I-" + label)


def reference_decode(logprobs: Sequence[Sequence[float]]) -> list[int]:
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


@pytest.mark.parametrize('length', [0, 1, 2, 17, 192, 400])
def test_decoder_matches_reference_with_ties_and_unreachable_states(length):
    rng = random.Random(105 + length)
    for _ in range(12):
        rows = [[rng.choice([-math.inf, -3., -2., -1., 0.]) for _ in TAGS] for _ in range(length)]
        assert spans.viterbi_decode(rows) == reference_decode(rows)
    rows = [[-math.inf] * len(TAGS) for _ in range(length)]
    assert spans.viterbi_decode(rows) == reference_decode(rows)
    assert spans.viterbi_decode([[0.] * len(TAGS)] * length) == [0] * length


def test_illegal_cross_label_and_initial_inside_tags_are_never_selected():
    # I-PERSON has the largest emission initially but cannot begin a BIO path.
    rows = [[-9., 0., 10., -99., -99.], [-9., -9., 0., -9., 10.]]
    assert spans.viterbi_decode(rows) == [1, 2]


def test_transition_validation_does_not_scale_with_field_length(monkeypatch):
    calls = []
    original = spans._allowed
    def counted(*a):
        calls.append(1)
        return original(*a)
    monkeypatch.setattr(spans, '_allowed', counted)
    assert spans.viterbi_decode([[0.] * 5] * 192) == [0] * 192
    assert len(calls) <= len(TAGS) ** 2
