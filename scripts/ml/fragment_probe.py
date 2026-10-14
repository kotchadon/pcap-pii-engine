#!/usr/bin/env python
"""Model-behaviour probe on synthetic *extracted-field* defects (NOT a test of TCP reassembly). Uses V2 VAL examples only.

  python scripts/ml/fragment_probe.py --checkpoint src/packet_pii/ml/artifacts/bilstm_v2 --out docs/ml/results/v2_fragment_probe.json
For every single-entity val example the same field is perturbed and we report how often the ORIGINAL entity is still detected
(exact span after mapping offsets, or any overlap). Counts and rates only, no raw text.
"""
import argparse, json, os, random, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
import torch
from packet_pii.ml import data2 as D
from packet_pii.ml.bilstm import load_predictor

DS = os.path.join(os.path.dirname(__file__), "..", "..", "src", "packet_pii", "ml", "datasets", "v2")


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--checkpoint", required=True); ap.add_argument("--out", required=True)
    a = ap.parse_args(); torch.set_num_threads(4)
    P, meta = load_predictor(a.checkpoint); th = meta.get("min_score", 0.0)
    val = [e for e in D.read_split(os.path.join(DS, "val.jsonl.gz")) if len(e.spans) == 1 and 6 <= len(e.text) <= 160 and "truncated" not in e.tags]
    rng = random.Random(7)

    def variants(e):
        s, t, l = e.spans[0]; x = e.text
        ent = x[s:t]
        out = {"baseline": (x, (s, t))}
        if t - s >= 5:
            cut = s + max(2, (t - s) // 2)
            out["clipped_mid_entity"] = (x[:cut], (s, cut))
        out["entity_tail_cut_after_entity"] = (x[:t], (s, t))
        out["entity_head_cut_before_entity"] = (x[s:], (0, t - s))
        out["fused_with_preceding_word"] = (x[:s].rstrip() + x[s:], (len(x[:s].rstrip()), len(x[:s].rstrip()) + t - s)) if s > 0 and x[s - 1] == " " else None
        out["duplicated_value"] = (x[:t] + ent + x[t:], (s, t))
        if " " in ent:
            i = ent.index(" "); out["gap_inside_entity_fused"] = (x[:s] + ent[:i] + ent[i + 1:] + x[t:], None)
        out["replacement_char_in_entity"] = (x[:s + (t - s) // 2] + "�" + x[s + (t - s) // 2 + 1:t] + x[t:], (s, t)) if t - s >= 4 else None
        out["long_field_entity_after_3000_tokens"] = ("lorem ipsum dolor " * 1000 + x, (len("lorem ipsum dolor " * 1000) + s, len("lorem ipsum dolor " * 1000) + t))
        return out

    stats = {}
    for e in rng.sample(val, 600):
        for name, v in variants(e).items():
            if v is None: continue
            text, gold = v
            r = [(s, t, lab) for s, t, lab, sc in P.predict_pairs([(e.location, text)])[0] if sc >= th]
            d = stats.setdefault(name, {"n": 0, "exact": 0, "overlap": 0, "any_span": 0, "label_ok_overlap": 0})
            d["n"] += 1
            d["any_span"] += bool(r)
            if gold:
                d["exact"] += any((s, t) == gold for s, t, _ in r)
                ov = [x for x in r if x[0] < gold[1] and x[1] > gold[0]]
                d["overlap"] += bool(ov); d["label_ok_overlap"] += any(x[2] == e.spans[0][2] for x in ov)
    res = {"checkpoint": meta["model_version"], "min_score": th, "dataset": "v2 val single-entity (dev only)",
           "cases": {k: {**v, **{r: round(v[r] / v["n"], 3) for r in ("exact", "overlap", "any_span", "label_ok_overlap")}} for k, v in stats.items()}}
    json.dump(res, open(a.out, "w"), indent=1); print(json.dumps({k: (v["exact"], v["overlap"], v["any_span"]) for k, v in res["cases"].items()}, indent=1))


if __name__ == "__main__":
    main()
