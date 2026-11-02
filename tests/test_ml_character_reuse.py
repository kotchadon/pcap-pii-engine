"""Batch-local character work reuse; random-weight mechanics are not V2 acceptance."""
import pytest

torch = pytest.importorskip('torch')
from packet_pii.ml.bilstm import BiLSTMTagger, ModelConfig


def test_ensemble_prepares_character_indices_once_per_batch(monkeypatch):
    from packet_pii.ml.bilstm import SpanPredictor
    from packet_pii.ml.encoding import build_vocab
    pairs = [('json_body.name', 'Alex Example')] * 8
    vocab = build_vocab(pairs, min_word_count=1, min_char_count=1)
    cfg = ModelConfig(len(vocab.words),len(vocab.chars),word_dim=8,char_dim=4,
                      char_filters=4,hidden=8,dropout=0)
    predictor = SpanPredictor([BiLSTMTagger(cfg) for _ in range(3)],vocab)
    reference = predictor.predict_pairs(pairs)
    calls = []
    from packet_pii.ml import bilstm
    prepare = bilstm._character_plan
    def observed(*args, **kwargs):
        calls.append(1)
        return prepare(*args, **kwargs)
    monkeypatch.setattr(bilstm, '_character_plan', observed)
    assert predictor.predict_pairs(pairs) == reference
    assert len(calls) == 1  # shared indices, independent learned features


@pytest.mark.parametrize('widths', [(3,), (2, 3, 4)])
def test_repeated_character_rows_convolved_once_with_identical_logits_and_training(widths):
    # Wrong word-ID dedup merges distinct case/unknown character rows. Wrong
    # inverse mapping assigns a neighbour's features to an occurrence.
    torch.manual_seed(903)
    model = BiLSTMTagger(ModelConfig(32, 16, word_dim=8, char_dim=4, char_filters=4,
                                    hidden=8, dropout=0, char_widths=widths, key_broadcast=True)).eval()
    word = torch.ones((8, 5), dtype=torch.long)  # deliberately all the same word ID
    shape = torch.tensor([[1, 2, 3, 4, 0]] * 8)
    ctx = torch.tensor([[1, 1, 0, 0, 0]] * 8)
    chars = torch.tensor([[[1, 0, 0, 0], [2, 3, 0, 0], [3, 2, 0, 0],
                           [2, 3, 0, 0], [0, 0, 0, 0]]] * 8)
    lengths = torch.tensor([5, 4, 5, 4, 5, 4, 5, 4])
    rows = []
    hook = model.conv.register_forward_pre_hook(lambda _, args: rows.append(args[0].shape[0]))
    reference = model(word, shape, ctx, chars, lengths)
    reference.sum().backward()
    assert model.conv.weight.grad.abs().sum() > 0
    assert model.lstm.weight_ih_l0_reverse.grad.abs().sum() > 0
    assert rows.pop() == 40  # gradient path continues to process every row
    with torch.inference_mode():
        actual = model(word, shape, ctx, chars, lengths)
    hook.remove()
    assert rows == [3]  # 32 nonempty occurrences, three distinct character rows
    torch.testing.assert_close(actual, reference, atol=1e-6, rtol=1e-6)


def test_reuse_does_not_retain_features_across_calls_or_weight_changes():
    torch.manual_seed(24)
    model = BiLSTMTagger(ModelConfig(16, 16, word_dim=8, char_dim=4, char_filters=4,
                                    hidden=8, dropout=0)).eval()
    ids = torch.ones((2, 3), dtype=torch.long)
    chars = torch.tensor([[[1, 2, 0], [1, 2, 0], [2, 1, 0]]] * 2)
    lengths = torch.tensor([3, 3])
    before = {k: v.clone() for k, v in model.state_dict().items()}
    with torch.inference_mode():
        a = model(ids, ids, ids, chars, lengths)
        model.conv.weight.add_(1)
        b = model(ids, ids, ids, chars, lengths)
        model.load_state_dict(before)
        c = model(ids, ids, ids, chars, lengths)
    assert not torch.equal(a, b)
    assert torch.equal(a, c)
