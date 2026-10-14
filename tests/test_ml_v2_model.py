import json
import os

import pytest

torch = pytest.importorskip("torch")

from packet_pii.ml import data2 as D
from packet_pii.ml.bilstm import (BiLSTMTagger, CheckpointError, ModelConfig, SpanPredictor, collate, load_checkpoint, save_checkpoint,
                                  train_model)
from packet_pii.ml.encoding import IGNORE, build_vocab, encode_example
from packet_pii.ml.infer import BiLSTMDetector


@pytest.fixture(scope="module")
def mini():
    ds = D.generate_dataset(seed=9, sizes={"train": 400, "val": 100, "calib": 50})
    v = build_vocab([(e.location, e.text) for e in ds["train"]])
    return ds, v


def cfg_for(v, **kw):
    base = dict(hidden=24, word_dim=16, char_filters=8, char_dim=8)
    base.update(kw)
    return ModelConfig(len(v.words), len(v.chars), **base).validate()


def batch(ds, v, cfg, n=6):
    encs = [encode_example(v, e.location, e.text, e.spans) for e in ds["train"][:n]]
    return encs, collate(encs, cfg.max_seq)


@pytest.mark.parametrize("kw", [dict(), dict(key_broadcast=True), dict(char_widths=(2, 3, 4)), dict(key_broadcast=True, char_widths=(3, 5)),
                                dict(char_filters=0, key_broadcast=True)])
def test_v2_architecture_variants_forward_backward(mini, kw):
    ds, v = mini
    cfg = cfg_for(v, **kw)
    m = BiLSTMTagger(cfg)
    _, b = batch(ds, v, cfg)
    logits = m(b["word"], b["shape"], b["ctx"], b["chars"], b["lengths"])
    assert logits.shape == (6, b["word"].shape[1], 5)
    loss = torch.nn.functional.cross_entropy(logits.reshape(-1, 5), b["labels"].reshape(-1), ignore_index=IGNORE)
    loss.backward()
    assert torch.isfinite(loss) and all(p.grad is None or torch.isfinite(p.grad).all() for p in m.parameters())
    if cfg.key_broadcast:
        assert m.key_proj.weight.grad.abs().sum() > 0


@pytest.mark.parametrize("kw", [dict(key_broadcast=True), dict(char_widths=(2, 3, 4))])
def test_padding_invariance_holds_for_v2_variants(mini, kw):
    ds, v = mini
    cfg = cfg_for(v, **kw)
    m = BiLSTMTagger(cfg).eval()
    exs = sorted(ds["val"], key=lambda e: len(e.text))
    short, long_ = exs[3], exs[-1]
    e1 = encode_example(v, short.location, short.text, short.spans)
    b1 = collate([e1], cfg.max_seq)
    b2 = collate([encode_example(v, long_.location, long_.text, long_.spans), e1], cfg.max_seq)
    with torch.no_grad():
        a = m(b1["word"], b1["shape"], b1["ctx"], b1["chars"], b1["lengths"])[0, :len(e1)]
        c = m(b2["word"], b2["shape"], b2["ctx"], b2["chars"], b2["lengths"])[1, :len(e1)]
    assert torch.allclose(a, c, atol=1e-5)


def test_key_broadcast_gives_text_positions_access_to_the_key(mini):
    """Changing only the key tokens must be able to change logits at TEXT positions even with a 1-token window effect."""
    ds, v = mini
    cfg = cfg_for(v, key_broadcast=True)
    m = BiLSTMTagger(cfg).eval()
    k = lambda loc: encode_example(v, loc, "Maria Garcia", [])
    outs = []
    for loc in ("json_body.username", "json_body.customer_name"):
        e = k(loc); b = collate([e], 64)
        with torch.no_grad():
            outs.append(m(b["word"], b["shape"], b["ctx"], b["chars"], b["lengths"])[0, e.n_ctx:])
    assert outs[0].shape == outs[1].shape and not torch.allclose(outs[0], outs[1])


def test_config_validation_and_roundtrip_for_new_fields(mini):
    _, v = mini
    base = dict(vocab_size=50, char_vocab_size=10)
    for bad in (dict(char_widths=()), dict(char_widths=(0,)), dict(char_widths=(3, 9)), dict(char_widths="3"), dict(key_broadcast="yes"), dict(key_dim=0),
                dict(char_widths=(1, 2, 3, 4, 5))):
        with pytest.raises(ValueError):
            ModelConfig(**{**base, **bad}).validate()
    c = ModelConfig.from_dict({**base, "char_widths": [2, 3], "key_broadcast": True})
    assert c.char_widths == (2, 3)
    # legacy (V1) config dicts without the new keys still load with V1 defaults
    legacy = ModelConfig.from_dict({**base})
    assert legacy.char_widths == (3,) and legacy.key_broadcast is False


def test_v1_checkpoint_still_loads_and_is_unchanged():
    d = os.path.join(os.path.dirname(__file__), "..", "src", "packet_pii", "ml", "artifacts", "bilstm_v1")
    meta = json.load(open(os.path.join(d, "meta.json")))
    assert meta["model_sha256"] == "972a87f2b6db8b701ba43a63d1949ca0dc7684ec67c2c2a304ebbbaa19495d6a"
    m, v, _ = load_checkpoint(d)
    assert m.cfg.char_widths == (3,) and not m.cfg.key_broadcast


def test_training_options_hn_boost_and_tag_weights_run_and_roundtrip(mini, tmp_path):
    ds, v = mini
    cfg = cfg_for(v, key_broadcast=True, char_widths=(2, 3))
    model, rec = train_model(ds["train"], ds["val"], v, cfg, epochs=2, patience=3, hn_boost=1, tag_weights=[0.5, 1, 1, 1, 1], log=lambda s: None)
    assert rec["hn_boost"] == 1 and rec["tag_weights"][0] == 0.5 and len(rec["history"]) == 2
    save_checkpoint(str(tmp_path / "c"), model, v, version_prefix="bilstm-v2x", training=rec, extra={"min_score": 0.3})
    det = BiLSTMDetector(str(tmp_path / "c"))
    assert det.model_version.startswith("bilstm-v2x-") and det.min_score == 0.3
    m2, _, meta = load_checkpoint(str(tmp_path / "c"))
    assert m2.cfg.key_broadcast and m2.cfg.char_widths == (2, 3)
    p1 = SpanPredictor(model, v).predict_pairs([("json_body.name", "Maria Garcia")])
    p2 = SpanPredictor(m2, v).predict_pairs([("json_body.name", "Maria Garcia")])
    assert p1 == p2


def test_tampered_v2_checkpoint_rejected(mini, tmp_path):
    ds, v = mini
    model = BiLSTMTagger(cfg_for(v, key_broadcast=True))
    save_checkpoint(str(tmp_path / "c"), model, v)
    blob = (tmp_path / "c" / "model.pt").read_bytes()
    (tmp_path / "c" / "model.pt").write_bytes(blob[:-20] + b"\x00" * 20)
    with pytest.raises(CheckpointError, match="checksum"):
        load_checkpoint(str(tmp_path / "c"))
