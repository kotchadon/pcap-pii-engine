#!/usr/bin/env python
"""Train the BiLSTM tagger on the deterministic synthetic dataset (CPU).

  python scripts/ml/train.py --out src/packet_pii/ml/artifacts/bilstm_v1 --seed 1337

Only the TRAIN split is used for fitting and vocabulary; VAL selects the checkpoint (entity F1);
CALIB picks the reporting threshold ``min_score``. The TEST split is never read here.
"""
import argparse, json, os, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
import torch
from packet_pii.ml import data as D
from packet_pii.ml.bilstm import ModelConfig, SpanPredictor, evaluate_examples, save_checkpoint, train_model
from packet_pii.ml.encoding import build_vocab


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--data-seed", type=int, default=1234)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--patience", type=int, default=6)
    ap.add_argument("--max-minutes", type=float, default=20.0)
    ap.add_argument("--hidden", type=int, default=96)
    ap.add_argument("--word-dim", type=int, default=64)
    ap.add_argument("--char-filters", type=int, default=48)
    ap.add_argument("--word-dropout", type=float, default=0.15)
    ap.add_argument("--ctx-dropout", type=float, default=0.0, help="prob. of masking each field-key token (simulates unseen keys)")
    ap.add_argument("--min-word-count", type=int, default=2)
    ap.add_argument("--threads", type=int, default=4)
    a = ap.parse_args()
    torch.set_num_threads(a.threads)
    ds = D.generate_dataset(a.data_seed)
    vocab = build_vocab([(e.location, e.text) for e in ds["train"]], a.min_word_count)
    cfg = ModelConfig(len(vocab.words), len(vocab.chars), word_dim=a.word_dim, hidden=a.hidden,
                      char_filters=a.char_filters).validate()
    print(f"train={len(ds['train'])} val={len(ds['val'])} vocab={len(vocab.words)} chars={len(vocab.chars)}", flush=True)
    model, rec = train_model(ds["train"], ds["val"], vocab, cfg, seed=a.seed, epochs=a.epochs, patience=a.patience,
                             word_dropout=a.word_dropout, ctx_dropout=a.ctx_dropout, max_minutes=a.max_minutes)
    # operating threshold from the CALIBRATION split (never val/test)
    pred = SpanPredictor(model, vocab)
    sweep = {}
    for th in [i / 20 for i in range(0, 20)]:
        sweep[th] = evaluate_examples(pred, ds["calib"], th)["micro"]["f1"]
    best_th = max(sweep, key=lambda t: (round(sweep[t], 6), t))
    rec["calib_threshold_sweep_f1"] = {str(k): round(v, 4) for k, v in sweep.items()}
    rec.update({"data_seed": a.data_seed, "dataset_manifest": {s: len(v) for s, v in ds.items()},
                "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "cli": " ".join(sys.argv[1:])})
    meta = save_checkpoint(a.out, model, vocab, training=rec, extra={"min_score": best_th})
    print(json.dumps({"model_version": meta["model_version"], "min_score": best_th,
                      "best_val_micro_f1": rec["best_val_micro_f1"], "epochs_run": rec["epochs_run"]}))


if __name__ == "__main__":
    main()
