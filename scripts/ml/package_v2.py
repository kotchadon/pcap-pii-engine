#!/usr/bin/env python
"""Package trained members into a verified V2 ensemble directory (model.pt + meta.json per member + ensemble.json).

  python scripts/ml/package_v2.py --members build/ml/exp/r2a build/ml/exp/r2a_s12 build/ml/exp/r2a_s13 --out src/packet_pii/ml/artifacts/bilstm_v2

The ensemble operating threshold is chosen on V2 CALIB only. The challenge benchmark is never read here.
"""
import argparse, hashlib, json, os, shutil, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
import torch
from packet_pii.ml import data2 as D
from packet_pii.ml.bilstm import ENSEMBLE_FORMAT, SpanPredictor, ensemble_version, evaluate_examples, load_checkpoint, load_predictor

DS = os.path.join(os.path.dirname(__file__), "..", "..", "src", "packet_pii", "ml", "datasets", "v2")


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--members", nargs="+", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--threads", type=int, default=4); a = ap.parse_args()
    torch.set_num_threads(a.threads)
    members = []
    os.makedirs(a.out, exist_ok=True)
    for d in a.members:
        model, vocab, meta = load_checkpoint(d)
        seed = meta["training"]["seed"]; name = f"seed{seed}"
        os.makedirs(os.path.join(a.out, name), exist_ok=True)
        for f in ("model.pt", "meta.json"):
            shutil.copyfile(os.path.join(d, f), os.path.join(a.out, name, f))
        members.append({"dir": name, "model_sha256": meta["model_sha256"], "seed": seed, "member_version": meta["model_version"],
                        "member_val_f1_at_own_threshold": meta["training"]["val_at_threshold"]["f1"]})
    shas = [m["model_sha256"] for m in members]
    version = ensemble_version(shas)
    val, calib = (D.read_split(os.path.join(DS, f"{s}.jsonl.gz")) for s in ("val", "calib"))
    ens = {"format": ENSEMBLE_FORMAT, "version_prefix": "bilstm-v2", "model_version": version, "members": members, "min_score": 0.0}
    json.dump(ens, open(os.path.join(a.out, "ensemble.json"), "w"), indent=1, sort_keys=True)
    pred, meta = load_predictor(a.out)
    sweep = {t / 20: evaluate_examples(pred, calib, t / 20)["micro"]["f1"] for t in range(0, 20)}
    best = max(sweep, key=lambda t: (round(sweep[t], 6), t))
    ens["min_score"] = best
    ens["selection"] = {"rule": "ensemble of all seeds trained for the selected configuration (no seed cherry-picking); threshold = argmax micro-F1 on V2 calib",
                        "config_selected_on": "V2 validation micro-F1 (see docs/ml/V2_EXPERIMENTS.md)", "calib_threshold_sweep_f1": {f"{k:.2f}": round(v, 4) for k, v in sweep.items()},
                        "val_at_threshold": {k: round(v, 4) for k, v in evaluate_examples(pred, val, best)["micro"].items()},
                        "calib_at_threshold": {k: round(v, 4) for k, v in evaluate_examples(pred, calib, best)["micro"].items()},
                        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "torch": torch.__version__, "members_n": len(members)}
    json.dump(ens, open(os.path.join(a.out, "ensemble.json"), "w"), indent=1, sort_keys=True)
    pred2, meta2 = load_predictor(a.out)
    print(json.dumps({"model_version": meta2["model_version"], "min_score": meta2["min_score"], "members": meta2["members"], "val": ens["selection"]["val_at_threshold"],
                      "calib": ens["selection"]["calib_at_threshold"]}, indent=1))


if __name__ == "__main__":
    main()
