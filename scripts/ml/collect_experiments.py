#!/usr/bin/env python
"""Collect training records + dev slices of all V2 experiments into docs/ml/results/v2_experiments.json (metrics only)."""
import json, os, sys

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
EXP = os.path.join(ROOT, "build", "ml", "exp")
RUNS = [("E0", "v2.1", "e0", "V1 architecture on V2.1 data (isolates the data effect)", "dev_round1.json", "bilstm:e0"),
        ("E1", "v2.1", "e1", "E0 + key-summary broadcast", "dev_round1.json", "bilstm:e1"),
        ("E2", "v2.1", "e2", "E0 + char-CNN widths (2,3,4) x 64 filters", "dev_round1.json", "bilstm:e2"),
        ("E3", "v2.1", "e3", "E0 + hard-negative oversampling (x2)", "dev_round1.json", "bilstm:e3"),
        ("R2-a (seed 11)", "v2.2", "r2a", "E0 config on V2.2 data", "dev_round2.json", "bilstm:s11"),
        ("R2-a (seed 12)", "v2.2", "r2a_s12", "same, seed 12", "dev_round2.json", "bilstm:s12"),
        ("R2-a (seed 13)", "v2.2", "r2a_s13", "same, seed 13", "dev_round2.json", "bilstm:s13"),
        ("R2-b", "v2.2", "r2b", "E0 + hard-negative oversampling", "dev_r2bc.json", "bilstm:r2b"),
        ("R2-c", "v2.2", "r2c", "hn-boost + char widths (2,3,4) x 64", "dev_r2bc.json", "bilstm:r2c")]


def main():
    out = []
    for name, data, d, desc, devfile, key in RUNS:
        meta = json.load(open(os.path.join(EXP, d, "meta.json")))
        t = meta["training"]
        row = {"id": name, "data": data, "description": desc, "model_version": meta["model_version"], "params": t["params"], "epochs_run": t["epochs_run"],
               "wall_seconds": t["wall_seconds"], "seed": t["seed"], "min_score_from_calib": meta["min_score"],
               "best_val_f1_during_training": round(t["best_val_micro_f1"], 4), "val_at_threshold": t["val_at_threshold"], "calib_at_threshold": t["calib_at_threshold"],
               "cli": t["cli"], "config": {k: meta["config"][k] for k in ("hidden", "word_dim", "char_filters", "char_widths", "key_broadcast", "dropout", "layers") if k in meta["config"]}}
        p = os.path.join(EXP, devfile)
        if os.path.exists(p):
            s = json.load(open(p))["datasets"]["v2val"]["systems"].get(key)
            if s:
                row["val_slices"] = {"ci95_f1": s["ci95_bootstrap"]["f1"], "recall_unseen_key_examples": s["recall_unseen_key_examples"], "recall_unseen_context": s["recall_unseen_context"],
                                     "fp_rate_hard_negative_examples": s["fp_rate_hard_negative_examples"]["rate"], "recall_multi_entity": s["recall_multi_entity_examples"]["recall"]}
        out.append(row)
    json.dump(out, open(os.path.join(ROOT, "docs", "ml", "results", "v2_experiments.json"), "w"), indent=1)
    for r in out:
        print(f"{r['id']:16s} {r['data']:5s} params {r['params']:>8d} ep {r['epochs_run']:2d} {r['wall_seconds']:7.0f}s val {r['val_at_threshold']['f1']:.4f} calib {r['calib_at_threshold']['f1']:.4f} {r.get('val_slices', {}).get('recall_unseen_context', {}).get('recall')} {r.get('val_slices', {}).get('fp_rate_hard_negative_examples')}")


if __name__ == "__main__":
    main()
