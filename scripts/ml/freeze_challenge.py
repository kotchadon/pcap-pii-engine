#!/usr/bin/env python
"""Generate and FREEZE the independent challenge benchmark (writes gz JSONL + manifest with sha256).

  python scripts/ml/freeze_challenge.py --out src/packet_pii/ml/datasets/challenge_v1.jsonl.gz --manifest docs/ml/results/challenge_v1_manifest.json

The frozen file is the benchmark. Never use it for training, model selection or threshold tuning.
"""
import argparse, gzip, hashlib, json, os, sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from packet_pii.ml import challenge as C
from packet_pii.ml import data2 as D


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True); ap.add_argument("--manifest", required=True)
    a = ap.parse_args()
    ex = C.generate()
    blob = D.dumps_split(ex).encode("utf-8")
    with gzip.GzipFile(a.out, "wb", mtime=0) as f:
        f.write(blob)
    man = {"name": "challenge_v1", "seed": C.SEED, "examples": len(ex), "entities": dict(Counter(l for e in ex for *_, l in e.spans)),
           "no_entity_examples": sum(1 for e in ex if not e.spans), "by_source": dict(Counter(e.kind for e in ex)),
           "tags": dict(Counter(t for e in ex for t in e.tags)), "distinct_entity_strings": len({e.text[s:t].lower() for e in ex for s, t, _ in e.spans}),
           "sha256_jsonl": hashlib.sha256(blob).hexdigest(), "sha256_gz": hashlib.sha256(open(a.out, "rb").read()).hexdigest(),
           "status": "FROZEN: evaluation only; no training / selection / tuning", "kind": "out-of-generator SYNTHETIC validation (not real traffic)"}
    json.dump(man, open(a.manifest, "w"), indent=1, sort_keys=True)
    print(json.dumps(man, indent=1))


if __name__ == "__main__":
    main()
