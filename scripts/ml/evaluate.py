#!/usr/bin/env python
"""Evaluate a BiLSTM checkpoint and the rule baselines with ONE protocol (exact span + label).

  python scripts/ml/evaluate.py --checkpoint src/packet_pii/ml/artifacts/bilstm_v1 --splits val,calib --out docs/ml/results/dev.json
  python scripts/ml/evaluate.py --checkpoint ... --splits test --final --out docs/ml/results/test.json

The frozen TEST split is only evaluated with ``--final`` (once, after all choices were made on val/calib).
"""
import argparse, json, os, sys, time
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
import torch
from packet_pii.ml import data as D
from packet_pii.ml.baseline import existing_key_rules, majority, strong_rules
from packet_pii.ml.bilstm import SpanPredictor, load_checkpoint
from packet_pii.ml.metrics import entity_metrics


def slim(m):
    return {"micro": m["micro"], "macro_f1": m["macro_f1"], "per_class": m["per_class"]}


def ece(pairs, bins=10):
    """pairs: (score, correct). Expected calibration error of the RAW score as a probability of correctness."""
    if not pairs:
        return None, []
    tot, e, rows = len(pairs), 0.0, []
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        sel = [(s, c) for s, c in pairs if lo <= s < hi or (b == bins - 1 and s == 1.0)]
        if sel:
            conf, acc = sum(s for s, _ in sel) / len(sel), sum(c for _, c in sel) / len(sel)
            e += len(sel) / tot * abs(conf - acc)
            rows.append({"bin": f"[{lo:.1f},{hi:.1f})", "n": len(sel), "mean_score": round(conf, 3), "precision": round(acc, 3)})
    return round(e, 4), rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkpoint", required=True)
    ap.add_argument("--splits", default="val,calib")
    ap.add_argument("--data-seed", type=int, default=None)
    ap.add_argument("--final", action="store_true", help="required to evaluate the frozen test split")
    ap.add_argument("--out", required=True)
    ap.add_argument("--threads", type=int, default=4)
    a = ap.parse_args()
    splits = a.splits.split(",")
    if "test" in splits and not a.final:
        sys.exit("refusing to touch the frozen test split without --final")
    torch.set_num_threads(a.threads)
    model, vocab, meta = load_checkpoint(a.checkpoint)
    seed = a.data_seed if a.data_seed is not None else meta["training"]["data_seed"]
    ds = D.generate_dataset(seed)
    min_score = meta.get("min_score", 0.0)
    pred = SpanPredictor(model, vocab)
    result = {"model_version": meta["model_version"], "min_score": min_score, "data_seed": seed,
              "torch": torch.__version__, "python": sys.version.split()[0], "threads": a.threads,
              "checkpoint_sha256": meta["model_sha256"], "splits": {}}
    for sp in splits:
        exs = ds[sp]
        gold = {e.id: e.spans for e in exs}
        raw = pred.predict_pairs([(e.location, e.text) for e in exs])
        pred_at = lambda th: {e.id: [(s, t, l) for s, t, l, sc in p if sc >= th] for e, p in zip(exs, raw)}
        main_m = entity_metrics(gold, pred_at(min_score))
        sweep = {}
        for th in [i / 20 for i in range(0, 20)] + [0.97, 0.99]:
            mm = entity_metrics(gold, pred_at(th))["micro"]
            sweep[f"{th:.2f}"] = {k: round(mm[k], 4) for k in ("precision", "recall", "f1")}
        base = {n: slim(entity_metrics(gold, {e.id: fn(e.location, e.text) for e in exs}))
                for n, fn in (("majority(no_entities)", majority), ("existing_detect_key_rules", existing_key_rules),
                              ("strong_key_aware_rules", strong_rules))}
        by_id = {e.id: e for e in exs}
        errs = main_m["errors"]
        fn_kinds = Counter(by_id[x[0]].kind for x in errs["false_negatives"])
        fp_kinds = Counter(by_id[x[0]].kind for x in errs["false_positives"])
        support_kinds = Counter(by_id[i].kind for i, s in gold.items() for _ in s)
        recall_by_kind = {k: round(1 - fn_kinds.get(k, 0) / v, 3) for k, v in sorted(support_kinds.items())}
        # raw-score reliability on spans predicted at threshold 0
        gset = {e.id: set(e.spans) for e in exs}
        pairs = [(sc, int((s, t, l) in gset[e.id])) for e, p in zip(exs, raw) for s, t, l, sc in p]
        e_ece, bins = ece(pairs)
        sample = lambda lst: [{"kind": by_id[x[0]].kind, "location": by_id[x[0]].location, "text": by_id[x[0]].text,
                               "span": by_id[x[0]].text[x[1]:x[2]], "label": x[3]} for x in lst[:25]]
        # CPU timing (single-field latency and batched throughput)
        pairs_t = [(e.location, e.text) for e in exs[:300]]
        t0 = time.perf_counter()
        for p in pairs_t[:100]:
            pred.predict_pairs([p])
        lat = (time.perf_counter() - t0) / 100 * 1000
        t0 = time.perf_counter(); pred.predict_pairs(pairs_t); thr = len(pairs_t) / (time.perf_counter() - t0)
        result["splits"][sp] = {
            "examples": len(exs), "entities": sum(len(g) for g in gold.values()),
            "bilstm_at_min_score": slim(main_m), "threshold_sweep": sweep, "baselines": base,
            "errors": {"false_positives": len(errs["false_positives"]), "false_negatives": len(errs["false_negatives"]),
                       "fp_by_kind": dict(fp_kinds), "fn_by_kind": dict(fn_kinds), "recall_by_kind": recall_by_kind,
                       "sample_false_positives": sample(errs["false_positives"]),
                       "sample_false_negatives": sample(errs["false_negatives"])},
            "raw_score_ece_vs_precision": e_ece, "raw_score_reliability_bins": bins,
            "cpu_timing": {"single_field_ms": round(lat, 2), "batched_fields_per_sec": round(thr, 1)}}
        m = main_m["micro"]
        print(f"[{sp}] BiLSTM@{min_score}: P {m['precision']:.3f} R {m['recall']:.3f} F1 {m['f1']:.3f} | "
              + " | ".join(f"{n}: F1 {b['micro']['f1']:.3f}" for n, b in base.items()), flush=True)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
