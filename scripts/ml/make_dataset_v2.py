#!/usr/bin/env python
"""Generate the V2 development distribution (train/val/calib), run leakage checks, write gz JSONL + manifest.

  python scripts/ml/make_dataset_v2.py --out src/packet_pii/ml/datasets/v2 --manifest docs/ml/results/v2_dataset_manifest.json
"""
import argparse, gzip, hashlib, json, os, sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from packet_pii.ml import data2 as D


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20261014)
    ap.add_argument("--out", required=True)
    ap.add_argument("--manifest", default=None)
    a = ap.parse_args()
    ds = D.generate_dataset(a.seed)
    os.makedirs(a.out, exist_ok=True)
    man = {"seed": a.seed, "lexicon_faker_version": D.LEX["faker_version"], "splits": {}}
    for s, exs in ds.items():
        blob = D.dumps_split(exs).encode("utf-8")
        with gzip.GzipFile(os.path.join(a.out, f"{s}.jsonl.gz"), "wb", mtime=0) as f:
            f.write(blob)
        lab = Counter(l for e in exs for *_, l in e.spans)
        man["splits"][s] = {"examples": len(exs), "entities": dict(lab), "no_entity_examples": sum(1 for e in exs if not e.spans),
                            "by_kind": dict(Counter(e.kind for e in exs)), "tags": dict(Counter(t for e in exs for t in e.tags)),
                            "distinct_entity_strings": len({e.text[x:y].lower() for e in exs for x, y, _ in e.spans}),
                            "sha256_jsonl": hashlib.sha256(blob).hexdigest()}
    man["leakage_report"] = D.leakage_report(ds)
    man["common_cue_example_share"] = D.common_cue_share(ds)
    print(json.dumps(man, indent=1))
    if a.manifest:
        os.makedirs(os.path.dirname(os.path.abspath(a.manifest)), exist_ok=True)
        json.dump(man, open(a.manifest, "w"), indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
