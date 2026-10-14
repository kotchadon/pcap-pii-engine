#!/usr/bin/env python
"""Generate the deterministic synthetic dataset, run leakage checks and write JSONL + manifest.

  python scripts/ml/make_dataset.py --out build/ml/data --manifest docs/ml/results/dataset_manifest.json
"""
import argparse, json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from packet_pii.ml import data as D


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--out", required=True)
    ap.add_argument("--manifest", default=None)
    a = ap.parse_args()
    ds = D.generate_dataset(a.seed)
    man = D.write_dataset(ds, a.out)
    man["seed"] = a.seed
    man["leakage_report"] = D.leakage_report(ds)
    man["entity_strings_shared_with_train"] = D.entity_value_overlap(ds)
    print(json.dumps(man, indent=1))
    if a.manifest:
        os.makedirs(os.path.dirname(os.path.abspath(a.manifest)), exist_ok=True)
        with open(a.manifest, "w") as f:
            json.dump(man, f, indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
