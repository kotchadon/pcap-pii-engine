import hashlib
import json
import os
import shutil

import pytest

torch = pytest.importorskip("torch")

from packet_pii.ml import FieldInput, run_detector
from packet_pii.ml import data2 as D
from packet_pii.ml.bilstm import (ENSEMBLE_FILE, BiLSTMTagger, CheckpointError, ModelConfig, SpanPredictor, ensemble_version, load_predictor,
                                  save_checkpoint, train_model)
from packet_pii.ml.encoding import build_vocab
from packet_pii.ml.infer import BiLSTMDetector

ROOT = os.path.join(os.path.dirname(__file__), "..")
V1 = os.path.join(ROOT, "src", "packet_pii", "ml", "artifacts", "bilstm_v1")
V2 = os.path.join(ROOT, "src", "packet_pii", "ml", "artifacts", "bilstm_v2")


def _write_ens(path, members, min_score=0.3, prefix="bilstm-v2"):
    shas = [m["model_sha256"] for m in members]
    ens = {"format": 1, "version_prefix": prefix, "model_version": ensemble_version(shas, prefix), "members": members, "min_score": min_score}
    json.dump(ens, open(os.path.join(path, ENSEMBLE_FILE), "w"))
    return ens


@pytest.fixture(scope="module")
def tiny(tmp_path_factory):
    ds = D.generate_dataset(seed=17, sizes={"train": 600, "val": 80, "calib": 40})
    v = build_vocab([(e.location, e.text) for e in ds["train"]])
    cfg = ModelConfig(len(v.words), len(v.chars), hidden=16, word_dim=12, char_filters=8, char_dim=8).validate()
    root = tmp_path_factory.mktemp("ens")
    members = []
    for i, seed in enumerate((1, 2)):
        m, rec = train_model(ds["train"], ds["val"], v, cfg, seed=seed, epochs=6, patience=9, log=lambda s: None)
        meta = save_checkpoint(str(root / f"seed{seed}"), m, v, version_prefix="bilstm-v2x", training=rec)
        members.append({"dir": f"seed{seed}", "model_sha256": meta["model_sha256"]})
    _write_ens(str(root), members)
    return root, members, ds, v


def test_ensemble_average_is_deterministic_bounded_and_not_a_single_member(tiny):
    root, members, ds, v = tiny
    P, meta = load_predictor(str(root))
    assert meta["members"] == 2 and meta["model_version"].startswith("bilstm-v2-") and meta["score_semantics"] == "uncalibrated_model_score"
    pairs = [(e.location, e.text) for e in ds["val"][:30]]
    assert P.predict_pairs(pairs) == P.predict_pairs(pairs)
    # random-initialised members emit arbitrary tag paths, so the averaging effect is observable
    cfg = ModelConfig(len(v.words), len(v.chars), hidden=16, word_dim=12, char_filters=8, char_dim=8).validate()
    ms = []
    for seed in (101, 202):
        torch.manual_seed(seed); ms.append(BiLSTMTagger(cfg))
    ens = SpanPredictor(ms, v).predict_pairs(pairs)
    singles = [SpanPredictor(m, v).predict_pairs(pairs) for m in ms]
    assert any(ens) and ens != singles[0] and ens != singles[1]
    assert all(0.0 <= sc <= 1.0 for r in ens for *_, sc in r)


def test_detector_loads_ensemble_dir_and_reports_ensemble_version(tiny):
    root, members, ds, v = tiny
    d = BiLSTMDetector(str(root))
    assert d.model_version == ensemble_version([m["model_sha256"] for m in members]) and d.min_score == 0.3
    out = run_detector(d, [FieldInput(0, "json_body.name", "Maria Garcia"), FieldInput(1, "json_body.name", "")])
    assert all(s.model_version == d.model_version for s in out)


def _clone(root, tmp_path):
    dst = tmp_path / "e"
    shutil.copytree(root, dst)
    return dst


def test_ensemble_rejects_tampering(tiny, tmp_path):
    root, members, ds, v = tiny
    # 1. member weights modified
    d = _clone(root, tmp_path / "a"); blob = (d / "seed1" / "model.pt").read_bytes()
    (d / "seed1" / "model.pt").write_bytes(blob[:-8] + b"\x00" * 8)
    with pytest.raises(CheckpointError):
        load_predictor(str(d))
    # 2. ensemble.json lists a different digest than the member's meta
    d = _clone(root, tmp_path / "b"); bad = [dict(members[0], model_sha256="0" * 64), members[1]]
    _write_ens(str(d), bad)
    with pytest.raises(CheckpointError):
        load_predictor(str(d))
    # 3. version string forged
    d = _clone(root, tmp_path / "c"); ens = json.load(open(d / ENSEMBLE_FILE)); ens["model_version"] = "bilstm-v2-forged00000"
    json.dump(ens, open(d / ENSEMBLE_FILE, "w"))
    with pytest.raises(CheckpointError, match="model_version"):
        load_predictor(str(d))
    # 4. member path escaping the directory
    d = _clone(root, tmp_path / "d"); shutil.copytree(d / "seed1", tmp_path / "outside")
    _write_ens(str(d), [dict(members[0], dir="../outside"), members[1]])
    with pytest.raises(CheckpointError, match="escapes"):
        load_predictor(str(d))
    # 5. malformed / empty / oversized member lists, bad min_score
    d = _clone(root, tmp_path / "e")
    for bad_ens in ({"format": 1, "members": []}, {"format": 2, "members": members}, "not json", {"format": 1, "members": members * 5}):
        (d / ENSEMBLE_FILE).write_text(json.dumps(bad_ens) if not isinstance(bad_ens, str) else bad_ens)
        with pytest.raises(CheckpointError):
            load_predictor(str(d))
    _write_ens(str(d), members, min_score=1.5)
    with pytest.raises(CheckpointError):
        load_predictor(str(d))


def test_ensemble_members_must_share_config(tiny, tmp_path):
    root, members, ds, v = tiny
    cfg2 = ModelConfig(len(v.words), len(v.chars), hidden=24, word_dim=12, char_filters=8, char_dim=8).validate()
    with pytest.raises(ValueError):
        SpanPredictor([BiLSTMTagger(ModelConfig(len(v.words), len(v.chars), hidden=16, word_dim=12, char_filters=8, char_dim=8).validate()), BiLSTMTagger(cfg2)], v)


def test_v1_checkpoint_identity_preserved():
    meta = json.load(open(os.path.join(V1, "meta.json")))
    assert meta["model_sha256"] == "972a87f2b6db8b701ba43a63d1949ca0dc7684ec67c2c2a304ebbbaa19495d6a"
    assert hashlib.sha256(open(os.path.join(V1, "model.pt"), "rb").read()).hexdigest() == meta["model_sha256"]
    assert BiLSTMDetector(V1).model_version == "bilstm-v1-972a87f2b6db"


@pytest.mark.skipif(not os.path.isdir(V2), reason="V2 artifact not present")
def test_committed_v2_ensemble_integrity_and_separation_from_v1():
    ens = json.load(open(os.path.join(V2, ENSEMBLE_FILE)))
    assert V2 != V1 and len(ens["members"]) == 3 and ens["model_version"].startswith("bilstm-v2-")
    for m in ens["members"]:
        assert hashlib.sha256(open(os.path.join(V2, m["dir"], "model.pt"), "rb").read()).hexdigest() == m["model_sha256"]
    P, meta = load_predictor(V2)
    assert meta["model_version"] == ens["model_version"] and 0 <= meta["min_score"] <= 1
    assert all(p.device.type == "cpu" for mdl in P.models for p in mdl.parameters())
    assert BiLSTMDetector(V1).model_version != meta["model_version"]


@pytest.mark.skipif(not os.path.isdir(V2), reason="V2 artifact not present")
def test_committed_v2_deterministic_unicode_and_repeated_locations():
    d = BiLSTMDetector(V2)
    fields = [FieldInput(0, "json_body.name", "Zoë Müller"), FieldInput(1, "json_body.name", "Zoë Müller"),
              FieldInput(2, "body.text", "Thanks, 田中美咲, see you at 5"), FieldInput(3, "json_body.name", "")]
    a = run_detector(d, fields)
    assert a == run_detector(BiLSTMDetector(V2), fields)
    by = {i: [(s.start, s.end) for s in a if s.field_index == i] for i in range(4)}
    assert by[0] == by[1] and by[3] == []
    for s in a:
        assert s.end <= len(fields[s.field_index].text)
