import json
import logging
import os
import subprocess
import sys
import textwrap

import pytest

torch = pytest.importorskip("torch")

from packet_pii.ml import (EntityLabel, EntitySpan, FieldInput, MlValidationError, ScoreType, ValidationLimits,
                           run_detector)
from packet_pii.ml import data as D
from packet_pii.ml.bilstm import (BiLSTMTagger, CheckpointError, ModelConfig, SpanPredictor, collate, load_checkpoint,
                                  save_checkpoint, train_model)
from packet_pii.ml.encoding import IGNORE, build_vocab, encode_example
from packet_pii.ml.infer import BiLSTMDetector

SECRET = "Zq9-SECRET-hunter2"


@pytest.fixture(scope="module")
def tiny(tmp_path_factory):
    ds = D.generate_dataset(5, {"train": 500, "val": 120, "calib": 50, "test": 50})
    vocab = build_vocab([(e.location, e.text) for e in ds["train"]])
    cfg = ModelConfig(len(vocab.words), len(vocab.chars), hidden=32, word_dim=24, char_filters=16).validate()
    model, rec = train_model(ds["train"], ds["val"], vocab, cfg, epochs=14, patience=20, log=lambda s: None)
    d = tmp_path_factory.mktemp("ck") / "ck"
    save_checkpoint(str(d), model, vocab, training=rec, extra={"min_score": 0.0})
    return {"ds": ds, "vocab": vocab, "cfg": cfg, "model": model, "rec": rec, "dir": str(d)}


def _batch(tiny, n=4, pick=None):
    exs = tiny["ds"]["train"][:n] if pick is None else pick
    encs = [encode_example(tiny["vocab"], e.location, e.text, e.spans) for e in exs]
    return encs, collate(encs, tiny["cfg"].max_seq)


def test_forward_backward_real_gradients(tiny):
    m = BiLSTMTagger(tiny["cfg"])
    _, b = _batch(tiny, 8)
    logits = m(b["word"], b["shape"], b["ctx"], b["chars"], b["lengths"])
    assert logits.shape == (8, b["word"].shape[1], 5)
    loss = torch.nn.functional.cross_entropy(logits.reshape(-1, 5), b["labels"].reshape(-1), ignore_index=IGNORE)
    loss.backward()
    assert torch.isfinite(loss)
    for name in ("word", "out", "conv"):
        g = getattr(m, name).weight.grad
        assert g is not None and torch.isfinite(g).all() and g.abs().sum() > 0
    assert m.lstm.bidirectional and m.lstm.weight_ih_l0_reverse.grad.abs().sum() > 0  # backward direction trained


def test_labels_ignore_context_and_padding(tiny):
    encs, b = _batch(tiny, 6)
    for i, e in enumerate(encs):
        assert (b["labels"][i, :e.n_ctx] == IGNORE).all() and (b["labels"][i, len(e):] == IGNORE).all()
        assert (b["labels"][i, e.n_ctx:len(e)] != IGNORE).all()


def test_padding_does_not_change_outputs(tiny):
    m = tiny["model"].eval()
    exs = tiny["ds"]["test"]
    short = min(exs, key=lambda e: len(e.text)); long_ = max(exs, key=lambda e: len(e.text))
    e1, b1 = _batch(tiny, pick=[short]); _, b2 = _batch(tiny, pick=[long_, short])
    with torch.no_grad():
        a = m(b1["word"], b1["shape"], b1["ctx"], b1["chars"], b1["lengths"])[0, :len(e1[0])]
        c = m(b2["word"], b2["shape"], b2["ctx"], b2["chars"], b2["lengths"])[1, :len(e1[0])]
    assert torch.allclose(a, c, atol=1e-5)
    assert b2["word"].shape[1] > len(e1[0])  # the short sequence really was padded


def test_future_context_matters(tiny):
    m = tiny["model"].eval()
    v = tiny["vocab"]
    def logits(text):
        e = encode_example(v, "body.text", text, [])
        b = collate([e], 192)
        with torch.no_grad():
            return m(b["word"], b["shape"], b["ctx"], b["chars"], b["lengths"])[0, e.n_ctx]
    assert not torch.allclose(logits("Maria went home"), logits("Maria logged in as"), atol=1e-6)


def test_oov_maps_to_trained_unk_and_unicode_ok(tiny):
    v = tiny["vocab"]
    e = encode_example(v, "x.name", "ΖΖΖ 日本語 qwxzvv", [])
    assert all(w == v.words["<unk>"] for w in e.word_ids[e.n_ctx:])
    p = SpanPredictor(tiny["model"], v).predict_pairs([("x.name", "ΖΖΖ 日本語 qwxzvv 😀")])
    assert isinstance(p[0], list)


def test_training_reduces_loss_and_learns(tiny):
    h = tiny["rec"]["history"]
    assert h[-1]["train_loss"] < 0.6 * h[0]["train_loss"]
    assert tiny["rec"]["best_val_micro_f1"] > 0.2


def test_checkpoint_roundtrip_cpu_and_deterministic(tiny):
    m, v, meta = load_checkpoint(tiny["dir"])
    assert all(p.device.type == "cpu" for p in m.parameters()) and not m.training
    d1, d2 = BiLSTMDetector(tiny["dir"], 0.0), BiLSTMDetector(tiny["dir"], 0.0)
    fields = [FieldInput(i, e.location, e.text) for i, e in enumerate(tiny["ds"]["test"][:40])]
    a, b = d1.predict_fields(fields), d2.predict_fields(fields)
    assert a == b and a == d1.predict_fields(fields) and len(a) > 0
    alone = d1.predict_fields([fields[3]])
    assert [(s.start, s.end, s.label) for s in alone] == [(s.start, s.end, s.label) for s in a if s.field_index == 3]
    assert meta["score_semantics"] == "uncalibrated_model_score"


def test_detector_contract_and_spans_valid(tiny):
    d = BiLSTMDetector(tiny["dir"], 0.0)
    fields = [FieldInput(0, "json_body.name", "Maria Garcia"), FieldInput(1, "json_body.name", "Pat Lee"),
              FieldInput(2, "json_body.name", ""), FieldInput(3, "json_body.message", "Hello Zoë, 😀 @bob_99")]
    out = run_detector(d, fields)
    assert all(isinstance(s, EntitySpan) and s.model_version == d.model_version and 0 <= s.score <= 1
               and s.score_type is ScoreType.UNCALIBRATED_MODEL_SCORE for s in out)
    assert all(s.field_index != 2 for s in out)
    for s in out:
        assert s.end <= len(fields[s.field_index].text) and s.label in EntityLabel
    assert [s.field_index for s in out] == sorted(s.field_index for s in out)
    # identical text/location at different indices keep separate identities
    same = run_detector(d, [FieldInput(7, "h.x", "Maria Garcia"), FieldInput(9, "h.x", "Maria Garcia")])
    assert {s.field_index for s in same} <= {7, 9} and len(same) % 2 == 0
    assert d.predict_fields([]) == [] and run_detector(d, []) == []


def test_threshold_filters_and_validates(tiny):
    fields = [FieldInput(i, e.location, e.text) for i, e in enumerate(tiny["ds"]["test"][:30])]
    lo = BiLSTMDetector(tiny["dir"], 0.0).predict_fields(fields)
    hi = BiLSTMDetector(tiny["dir"], 0.99).predict_fields(fields)
    assert len(hi) <= len(lo) and all(s.score >= 0.99 for s in hi)
    for bad in (-0.1, 1.5, "0.5", float("nan")):
        with pytest.raises(CheckpointError):
            BiLSTMDetector(tiny["dir"], bad)


def test_long_and_oversized_fields(tiny):
    d = BiLSTMDetector(tiny["dir"], 0.0)
    text = ("Hello Maria Garcia, please contact Bob for details. " * 400)  # ~ 20k chars, thousands of tokens
    out = run_detector(d, [FieldInput(0, "body.text", text)])
    assert all(0 <= s.start < s.end <= len(text) for s in out)
    with pytest.raises(MlValidationError):
        run_detector(d, [FieldInput(0, "body.text", "x" * 100)], ValidationLimits(max_field_chars=50))


def test_corrupt_or_missing_checkpoints(tiny, tmp_path):
    with pytest.raises(CheckpointError):
        load_checkpoint(str(tmp_path / "nope"))
    d = tmp_path / "bad"; os.makedirs(d)
    for f in ("model.pt", "meta.json"):
        with open(os.path.join(tiny["dir"], f), "rb") as s, open(d / f, "wb") as t:
            t.write(s.read())
    (d / "model.pt").write_bytes((d / "model.pt").read_bytes()[:-50])
    with pytest.raises(CheckpointError, match="checksum"):
        load_checkpoint(str(d))
    (d / "meta.json").write_text("{not json")
    with pytest.raises(CheckpointError):
        load_checkpoint(str(d))
    meta = json.load(open(os.path.join(tiny["dir"], "meta.json")))
    meta["config"]["hidden"] = 999  # tensor shapes no longer match
    meta["model_sha256"] = json.load(open(os.path.join(tiny["dir"], "meta.json")))["model_sha256"]
    (d / "meta.json").write_text(json.dumps(meta))
    with open(os.path.join(tiny["dir"], "model.pt"), "rb") as s:
        (d / "model.pt").write_bytes(s.read())
    with pytest.raises(CheckpointError):
        load_checkpoint(str(d))


@pytest.mark.parametrize("kw", [dict(hidden=0), dict(dropout=1.0), dict(max_seq=4), dict(layers=9), dict(n_tags=3),
                                dict(vocab_size=1), dict(hidden=True)])
def test_invalid_model_config(kw):
    base = dict(vocab_size=50, char_vocab_size=10)
    base.update(kw)
    with pytest.raises(ValueError):
        ModelConfig(**base).validate()
    with pytest.raises(ValueError):
        ModelConfig.from_dict({"vocab_size": 50, "char_vocab_size": 10, "evil": 1})


def test_no_raw_pii_in_logs_stdout_or_errors(tiny, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    d = BiLSTMDetector(tiny["dir"], 0.0)
    f = FieldInput(0, "json_body.password", f"my name is {SECRET} and @{SECRET}")
    out = run_detector(d, [f])
    with pytest.raises(MlValidationError) as e:
        run_detector(d, [f], ValidationLimits(max_field_chars=5))
    cap = capsys.readouterr()
    assert SECRET not in caplog.text and SECRET not in cap.out + cap.err and SECRET not in str(e.value)
    assert SECRET not in repr(out) and SECRET not in repr(f)


def test_rules_only_engine_does_not_need_torch():
    src = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
    code = f"SRC = {src!r}\n" + textwrap.dedent("""
        import sys
        sys.path.insert(0, SRC)
        sys.modules['torch'] = None   # make 'import torch' fail
        import packet_pii.ml as ml, packet_pii.cli, packet_pii.engine, packet_pii.detect
        from packet_pii.ml import data, spans, baseline, metrics, encoding   # torch-free parts
        try:
            import packet_pii.ml.bilstm
        except ImportError as e:
            assert 'PyTorch is required' in str(e)
        else:
            raise SystemExit('bilstm import should fail without torch')
        print('ok')
    """)
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "ok", r.stderr
