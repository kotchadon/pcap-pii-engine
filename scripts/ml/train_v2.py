#!/usr/bin/env python
"""Train a V2 BiLSTM on the V2 development distribution (CPU).

  python scripts/ml/train_v2.py --name e0 --out build/ml/exp/e0 --seed 11
Selection uses VAL entity micro-F1 only; the operating threshold uses CALIB. The independent challenge set is never read.
"""
import argparse, json, os, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
import torch
from packet_pii.ml import data2 as D
from packet_pii.ml.bilstm import ModelConfig, SpanPredictor, evaluate_examples, save_checkpoint, train_model
from packet_pii.ml.encoding import build_vocab

DS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "src", "packet_pii", "ml", "datasets", "v2")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=11); ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--patience", type=int, default=5); ap.add_argument("--max-minutes", type=float, default=25)
    ap.add_argument("--hidden", type=int, default=96); ap.add_argument("--word-dim", type=int, default=64)
    ap.add_argument("--char-filters", type=int, default=48); ap.add_argument("--char-widths", default="3")
    ap.add_argument("--key-broadcast", action="store_true"); ap.add_argument("--layers", type=int, default=1)
    ap.add_argument("--dropout", type=float, default=0.3)
    ap.add_argument("--word-dropout", type=float, default=0.15); ap.add_argument("--ctx-dropout", type=float, default=0.0)
    ap.add_argument("--hn-boost", type=int, default=0); ap.add_argument("--o-weight", type=float, default=1.0)
    ap.add_argument("--min-word-count", type=int, default=2); ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--version-prefix", default="bilstm-v2x")
    a = ap.parse_args()
    torch.set_num_threads(a.threads)
    ds = {s: D.read_split(os.path.join(DS_DIR, f"{s}.jsonl.gz")) for s in D.SPLITS}
    vocab = build_vocab([(e.location, e.text) for e in ds["train"]], a.min_word_count)
    cfg = ModelConfig(len(vocab.words), len(vocab.chars), word_dim=a.word_dim, hidden=a.hidden, layers=a.layers,
                      dropout=a.dropout, char_filters=a.char_filters, char_widths=tuple(int(x) for x in a.char_widths.split(",")),
                      key_broadcast=a.key_broadcast).validate()
    tw = None if a.o_weight == 1.0 else [a.o_weight, 1, 1, 1, 1]
    model, rec = train_model(ds["train"], ds["val"], vocab, cfg, seed=a.seed, epochs=a.epochs, patience=a.patience,
                             word_dropout=a.word_dropout, ctx_dropout=a.ctx_dropout, hn_boost=a.hn_boost, tag_weights=tw,
                             max_minutes=a.max_minutes, log=lambda s: print(f"[{a.name}] {s}", flush=True))
    pred = SpanPredictor(model, vocab)
    sweep = {t / 20: evaluate_examples(pred, ds["calib"], t / 20)["micro"]["f1"] for t in range(0, 20)}
    best_th = max(sweep, key=lambda t: (round(sweep[t], 6), t))
    rec["calib_threshold_sweep_f1"] = {f"{k:.2f}": round(v, 4) for k, v in sweep.items()}
    rec.update({"experiment": a.name, "cli": " ".join(sys.argv[1:]), "params": sum(p.numel() for p in model.parameters()),
                "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "dataset": "v2 train/val/calib",
                "val_at_threshold": {k: round(v, 4) for k, v in evaluate_examples(pred, ds["val"], best_th)["micro"].items()},
                "calib_at_threshold": {k: round(v, 4) for k, v in evaluate_examples(pred, ds["calib"], best_th)["micro"].items()}})
    meta = save_checkpoint(a.out, model, vocab, version_prefix=a.version_prefix, training=rec, extra={"min_score": best_th})
    print(json.dumps({"experiment": a.name, "model_version": meta["model_version"], "params": rec["params"], "min_score": best_th,
                      "best_val_f1": round(rec["best_val_micro_f1"], 4), "val": rec["val_at_threshold"], "calib": rec["calib_at_threshold"],
                      "epochs": rec["epochs_run"], "seconds": rec["wall_seconds"]}))


if __name__ == "__main__":
    main()
