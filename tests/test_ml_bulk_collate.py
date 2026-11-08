"""Bulk collation must preserve every tensor and dropout RNG draw of c17abe7."""
import copy
import random
from typing import Sequence
from pathlib import Path
import pytest

torch = pytest.importorskip('torch')
from packet_pii.ml import bilstm
from packet_pii.ml.encoding import Encoded, IGNORE, MAX_CHARS, build_vocab, encode_example

# Frozen implementation from c17abe7f176116629d726a982f49df1f30b052bc.
def reference_collate(batch: Sequence[Encoded], max_seq: int, unk_id: int = 1, word_dropout: float = 0.0,
            rng: random.Random | None = None, ctx_dropout: float = 0.0) -> dict:
    lens = [len(e) for e in batch]
    if not lens or max(lens) > max_seq:
        raise ValueError("batch empty or sequence longer than max_seq (chunk before encoding)")
    B, T = len(batch), max(lens)
    C = max(1, min(MAX_CHARS, max((len(c) for e in batch for c in e.char_ids), default=1)))
    word = torch.zeros(B, T, dtype=torch.long); shape = torch.zeros(B, T, dtype=torch.long)
    ctx = torch.zeros(B, T, dtype=torch.long); chars = torch.zeros(B, T, C, dtype=torch.long)
    labels = torch.full((B, T), IGNORE, dtype=torch.long)
    for i, e in enumerate(batch):
        n = len(e)
        wids = list(e.word_ids)
        if word_dropout > 0 and rng is not None:  # train the <unk> embedding on realistic OOV contexts
            for k in range(e.n_ctx, n):
                if rng.random() < word_dropout:
                    wids[k] = unk_id
        if ctx_dropout > 0 and rng is not None:  # simulate unseen field keys (not the <sep> marker at n_ctx-1)
            for k in range(e.n_ctx - 1):
                if rng.random() < ctx_dropout:
                    wids[k] = unk_id
        word[i, :n] = torch.tensor(wids); shape[i, :n] = torch.tensor(e.shape_ids)
        ctx[i, :n] = torch.tensor(e.ctx_flags)
        for k, cid in enumerate(e.char_ids):
            if cid:
                chars[i, k, :len(cid)] = torch.tensor(cid[:C])
        if e.tags is not None:
            labels[i, e.n_ctx:n] = torch.tensor(e.tags)
    return {"word": word, "shape": shape, "ctx": ctx, "chars": chars, "labels": labels,
            "lengths": torch.tensor(lens, dtype=torch.long)}


@pytest.fixture
def encoded():
    pairs = [('json_body.user.fullName', 'Zoë Ångström'), ('query.q', ''),
             ('json_body.items[123].comment', '東京 ' + 'a' * 40 + ' Mary-Jane'),
             ('json_body.username', 'fictional_123')]
    vocab = build_vocab(pairs, min_word_count=1, min_char_count=1)
    return [encode_example(vocab, loc, text, []) for loc, text in pairs]


@pytest.mark.parametrize('word_dropout,ctx_dropout', [(0, 0), (.35, .65), (1, 1)])
def test_exact_reference_tensors_rng_and_independent_storage(encoded, word_dropout, ctx_dropout):
    saved = copy.deepcopy(encoded)
    old_rng, new_rng = random.Random(53), random.Random(53)
    expected = reference_collate(encoded, 192, word_dropout=word_dropout, rng=old_rng, ctx_dropout=ctx_dropout)
    actual = bilstm.collate(encoded, 192, word_dropout=word_dropout, rng=new_rng, ctx_dropout=ctx_dropout)
    assert actual.keys() == expected.keys()
    for key in expected:
        assert actual[key].dtype == expected[key].dtype == torch.long
        assert torch.equal(actual[key], expected[key]), key
    assert old_rng.getstate() == new_rng.getstate()
    assert encoded == saved
    actual['word'].fill_(999)
    fresh = bilstm.collate(encoded, 192)
    assert not torch.any(fresh['word'] == 999)
    assert encoded == saved


def test_tensor_construction_is_bounded_by_columns_not_token_count(encoded, monkeypatch):
    # A real-call spy catches a regression to per-token Python/PyTorch boundary crossings.
    calls = []
    original = torch.tensor
    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(torch, 'tensor', counted)
    actual = bilstm.collate(encoded * 12, 192)
    assert actual['word'].shape[0] == 48
    assert len(calls) <= 6


def test_genuine_v2_scores_and_threshold_decisions_are_bit_identical(monkeypatch):
    from test_ml_decoder_efficiency import reference_decode
    checkpoint = Path(__file__).resolve().parents[1] / 'src/packet_pii/ml/artifacts/bilstm_v2'
    if not all((checkpoint / seed / 'model.pt').exists() for seed in ('seed11', 'seed12', 'seed13')):
        pytest.skip('genuine V2 weights unavailable')
    predictor, meta = bilstm.load_predictor(str(checkpoint))
    assert meta['model_version'] == 'bilstm-v2-d1f9e9fb9a2b'
    pairs = [('json_body.name', 'Zoë Ångström'), ('json_body.username', 'fictional_123'),
             ('json_body.note', 'Mary-Jane Watson-Parker ordered a blue parcel. ' * 80),
             ('query.q', ''), ('json_body.name', '東京 Priya Patel')]
    candidate = predictor.predict_pairs(pairs)
    monkeypatch.setattr(bilstm, 'collate', reference_collate)
    monkeypatch.setattr(bilstm, 'viterbi_decode', reference_decode)
    baseline = predictor.predict_pairs(pairs)
    assert any(baseline), 'comparison must contain genuine predictions'
    assert candidate == baseline  # includes raw scores, labels, spans, ordering and every threshold decision
