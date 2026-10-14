#!/usr/bin/env python
"""Aggregate failure taxonomy of a checkpoint on a labelled set (counts + frame ids only; no field text).

  python scripts/ml/failure_taxonomy.py --checkpoint src/packet_pii/ml/artifacts/bilstm_v2 --dataset challenge --final --out docs/ml/results/v2_challenge_failure_taxonomy.json
REPORTING ONLY: the challenge benchmark must not be used to choose configurations.
"""
import argparse, json, os, sys
from collections import Counter, defaultdict

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
import torch
from packet_pii.ml import data2 as D
from packet_pii.ml.bilstm import load_predictor

DS = os.path.join(ROOT, "src", "packet_pii", "ml", "datasets")


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--checkpoint", required=True); ap.add_argument("--dataset", default="challenge")
    ap.add_argument("--final", action="store_true"); ap.add_argument("--out", required=True); a = ap.parse_args()
    if a.dataset == "challenge" and not a.final:
        sys.exit("frozen benchmark requires --final")
    torch.set_num_threads(4)
    P, meta = load_predictor(a.checkpoint); th = meta["min_score"]
    exs = D.read_split(os.path.join(DS, "challenge_v1.jsonl.gz")) if a.dataset == "challenge" else D.read_split(os.path.join(DS, "v2", a.dataset + ".jsonl.gz"))
    raw = P.predict_pairs([(e.location, e.text) for e in exs])
    st = defaultdict(lambda: [0, 0, 0, 0]); cat = Counter(); fp_frames = Counter(); label_fn = Counter(); label_fp = Counter()
    for e, r in zip(exs, raw):
        p = {(s, t, l) for s, t, l, sc in r if sc >= th}; g = set(e.spans)
        k = (e.kind, e.template)
        st[k][0] += len(p & g); st[k][1] += len(p - g); st[k][2] += len(g - p); st[k][3] += 1
        for (s, t, l) in p - g:
            ov = [x for x in g if x[0] < t and x[1] > s]
            c = "FP_label_confusion_same_span" if any((x[0], x[1]) == (s, t) and x[2] != l for x in ov) else "FP_boundary_overlap" if ov else "FP_no_gold_overlap"
            cat[c] += 1; label_fp[l] += 1
            if not ov: fp_frames[(e.kind, e.template)] += 1
        for (s, t, l) in g - p:
            ov = [x for x in p if x[0] < t and x[1] > s]
            c = "FN_label_confusion_same_span" if any((x[0], x[1]) == (s, t) and x[2] != l for x in ov) else "FN_boundary_overlap" if ov else "FN_missed_entirely"
            cat[c] += 1; label_fn[l] += 1
    src = defaultdict(lambda: [0, 0, 0])
    for (kind, _), (tp, fp, fn, n) in st.items():
        src[kind][0] += tp; src[kind][1] += fp; src[kind][2] += fn
    res = {"checkpoint": meta["model_version"], "min_score": th, "dataset": a.dataset, "taxonomy": dict(cat), "fn_by_label": dict(label_fn), "fp_by_label": dict(label_fp),
           "worst_frames": [{"source": k[0], "frame": k[1], "tp": v[0], "fp": v[1], "fn": v[2], "examples": v[3]} for k, v in sorted(st.items(), key=lambda kv: -(kv[1][1] + kv[1][2]))[:25]],
           "false_positive_frames_without_gold_overlap": [{"source": k[0], "frame": k[1], "count": c} for k, c in fp_frames.most_common(15)]}
    json.dump(res, open(a.out, "w"), indent=1)
    print(json.dumps(res["taxonomy"]))


if __name__ == "__main__":
    main()
