"""Algorithmic tensor tests use random weights, never stand in for frozen V2 acceptance."""
from types import SimpleNamespace

import pytest

torch = pytest.importorskip('torch')
from packet_pii.ml.bilstm import BiLSTMTagger, ModelConfig, SpanPredictor


def test_default_forward_batches_bound_padded_work_without_losing_jobs():
    predictor = SpanPredictor(SimpleNamespace(cfg=SimpleNamespace(max_seq=192)), None)
    jobs = [(i, range(n)) for i, n in enumerate([192] * 100 + [4] * 100)]
    batches = predictor._batches(jobs)
    assert sorted(j for part in batches for j in part) == list(range(200))
    assert max(len(part) * max(len(jobs[j][1]) for j in part) for part in batches) <= 4096


@pytest.mark.parametrize('widths', [(3,), (2, 3, 4)])
def test_inference_convolves_only_nonempty_character_rows_and_matches_training_path(widths):
    torch.manual_seed(701)
    model = BiLSTMTagger(ModelConfig(32, 16, word_dim=8, char_dim=4, char_filters=4,
                                     hidden=8, dropout=0, char_widths=widths, key_broadcast=True)).eval()
    word = torch.tensor([[1, 2, 3, 4], [1, 2, 0, 0]])
    shape = torch.zeros_like(word)
    ctx = torch.tensor([[1, 0, 0, 0], [1, 0, 0, 0]])
    chars = torch.zeros((2, 4, 8), dtype=torch.long)
    chars[0, 1:, :4] = torch.tensor([1, 2, 3, 4])
    chars[1, 1, :4] = torch.tensor([4, 3, 2, 1])
    lengths = torch.tensor([4, 2])
    # Gradient-enabled path retains the reference training calculation and must remain differentiable.
    reference = model(word, shape, ctx, chars, lengths)
    reference.sum().backward()
    assert model.conv.weight.grad.abs().sum() > 0
    rows = []
    hook = model.conv.register_forward_pre_hook(lambda module, args: rows.append(args[0].shape[0]))
    with torch.inference_mode():
        actual = model(word, shape, ctx, chars, lengths)
    hook.remove()
    assert rows == [4]  # four real character sequences; no convolution for padding or empty separator rows
    torch.testing.assert_close(actual, reference, atol=1e-6, rtol=1e-6)


def test_all_empty_character_rows_still_produce_finite_logits():
    torch.manual_seed(701)
    model = BiLSTMTagger(ModelConfig(32, 16, word_dim=8, char_dim=4, char_filters=4, hidden=8, dropout=0)).eval()
    word = torch.ones((1, 2), dtype=torch.long)
    chars = torch.zeros((1, 2, 8), dtype=torch.long)
    with torch.inference_mode():
        logits = model(word, word, word, chars, torch.tensor([2]))
    assert torch.isfinite(logits).all() and logits.shape == (1, 2, 5)
