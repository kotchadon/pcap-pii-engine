#!/usr/bin/env python
"""Matched evaluation of rules / BiLSTM-only / rules+BiLSTM hybrids on one labelled benchmark (exact span + label).

  python scripts/ml/evaluate_v2.py --models v1=src/packet_pii/ml/artifacts/bilstm_v1 v2=src/packet_pii/ml/artifacts/bilstm_v2 \
      --datasets v2val,v2calib --out docs/ml/results/v2_eval_dev.json
  python scripts/ml/evaluate_v2.py --models ... --datasets challenge --final --out docs/ml/results/v2_eval_challenge.json

Frozen sets (challenge, v1test) require --final. Hybrid thresholds are chosen on V2 CALIB only. Reports contain counts/rates,
never raw text (unless --include-text, for authorised synthetic debugging).
"""
import argparse, json, os, sys, time
from collections import Counter, defaultdict
from statistics import mean, pstdev

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
import torch
from packet_pii import detect as host_detect
from packet_pii.ml import data as D1
from packet_pii.ml import data2 as D2
from packet_pii.ml.baseline import AMBIGUOUS_PERSON_KEYS, _norm_key, majority, strong_rules
from packet_pii.ml.bilstm import load_predictor
from packet_pii.ml.evaluation import (TrainContext, bootstrap_ci, hybrid_rules_first, hybrid_union, no_entity_false_positive_rate,
                                      paired_bootstrap_diff, per_example_counts, prf, recall_on, reliability_bins)
from packet_pii.ml.metrics import entity_metrics, error_samples

DS = os.path.join(ROOT, "src", "packet_pii", "ml", "datasets")
FROZEN = {"challenge", "v1test"}


def load(name):
    if name in ("v2val", "v2calib"):
        return D2.read_split(os.path.join(DS, "v2", name[2:] + ".jsonl.gz"))
    if name == "challenge":
        return D2.read_split(os.path.join(DS, "challenge_v1.jsonl.gz"))
    if name == "v1test":
        return D1.generate_dataset(1234)["test"]
    raise SystemExit(f"unknown dataset {name}")


def host_rules(loc, text):
    """The ACTUAL host-engine rule detector (packet_pii.detect), restricted to the two contextual labels."""
    out = set()
    for d in host_detect.detect_fields([(loc, text)], threshold=0.8, include_values=True):
        if d.pii_type == "USERNAME": out.add((0, len(text), "USERNAME"))
        elif d.pii_type == "PERSON_NAME_CANDIDATE": out.add((0, len(text), "PERSON_NAME"))
    return sorted(out)


def f1_of(gold, pred): return entity_metrics(gold, pred)["micro"]["f1"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", required=True, help="name=checkpoint_dir ...")
    ap.add_argument("--datasets", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--hybrid-models", default=None, help="comma list of model names for hybrid analysis (default: all)")
    ap.add_argument("--seed-group", default=None, help="comma list of model names to summarise as mean/std (BiLSTM-only)")
    ap.add_argument("--final", action="store_true"); ap.add_argument("--include-text", action="store_true")
    ap.add_argument("--bootstrap", type=int, default=1000); ap.add_argument("--threads", type=int, default=4)
    a = ap.parse_args()
    names = a.datasets.split(",")
    if set(names) & FROZEN and not a.final:
        sys.exit("frozen benchmark requires --final")
    torch.set_num_threads(a.threads)
    models = {}
    for spec in a.models:
        n, p = spec.split("=", 1)
        models[n] = load_predictor(p)
    hyb_names = a.hybrid_models.split(",") if a.hybrid_models else list(models)
    train = D2.read_split(os.path.join(DS, "v2", "train.jsonl.gz")); ctx = TrainContext.build(train)
    calib = load("v2calib"); calib_gold = {e.id: e.spans for e in calib}
    # --- hybrid thresholds from CALIB only
    taus = {}
    calib_rules = {e.id: strong_rules(e.location, e.text) for e in calib}
    for n in hyb_names:
        P, meta = models[n]
        raw = dict(zip([e.id for e in calib], P.predict_pairs([(e.location, e.text) for e in calib])))
        amb = {e.id: [s for s in calib_rules[e.id] if _norm_key(e.location) in AMBIGUOUS_PERSON_KEYS and s[0] == 0 and s[1] >= len(e.text.rstrip())] for e in calib}
        best_add = max((t / 20 for t in range(2, 20)), key=lambda t: (round(f1_of(calib_gold, {e.id: hybrid_rules_first(calib_rules[e.id], raw[e.id], t) for e in calib}), 6), t))
        best_veto = max((t / 20 for t in range(0, 12)), key=lambda t: (round(f1_of(calib_gold, {e.id: hybrid_rules_first(calib_rules[e.id], raw[e.id], best_add, amb[e.id], t) for e in calib}), 6), -t))
        best_u = max((t / 20 for t in range(2, 20)), key=lambda t: (round(f1_of(calib_gold, {e.id: hybrid_union(calib_rules[e.id], raw[e.id], t) for e in calib}), 6), t))
        taus[n] = {"tau_add": best_add, "tau_veto": best_veto, "tau_union": best_u}
    result = {"torch": torch.__version__, "python": sys.version.split()[0], "threads": a.threads,
              "models": {n: {"model_version": m[1]["model_version"], "min_score": m[1].get("min_score", 0.0), "sha256": m[1]["model_sha256"]} for n, m in models.items()},
              "hybrid_thresholds_chosen_on_v2_calib": taus, "datasets": {}}
    for dn in names:
        exs = load(dn); gold = {e.id: e.spans for e in exs}; by_id = {e.id: e for e in exs}
        systems: dict[str, dict] = {"majority": {e.id: [] for e in exs}, "rules_strong": {e.id: strong_rules(e.location, e.text) for e in exs},
                                    "host_detect_py": {e.id: host_rules(e.location, e.text) for e in exs}}
        raws = {}
        timing = {}
        for n, (P, meta) in models.items():
            pairs = [(e.location, e.text) for e in exs]
            t0 = time.perf_counter(); raw = P.predict_pairs(pairs); dt = time.perf_counter() - t0
            raws[n] = dict(zip([e.id for e in exs], raw))
            t1 = time.perf_counter()
            for pr in pairs[:100]: P.predict_pairs([pr])
            timing[n] = {"batched_fields_per_sec": round(len(pairs) / dt, 1), "single_field_ms": round((time.perf_counter() - t1) / min(100, len(pairs)) * 1000, 2)}
            ms = meta.get("min_score", 0.0)
            systems[f"bilstm:{n}"] = {i: [(s, t, l) for s, t, l, sc in r if sc >= ms] for i, r in raws[n].items()}
        for n in hyb_names:
            tau = taus[n]
            amb = {e.id: [s for s in systems["rules_strong"][e.id] if _norm_key(e.location) in AMBIGUOUS_PERSON_KEYS and s[0] == 0] for e in exs}
            systems[f"hybrid_union:{n}"] = {e.id: hybrid_union(systems["rules_strong"][e.id], raws[n][e.id], tau["tau_union"]) for e in exs}
            systems[f"hybrid_rules_first:{n}"] = {e.id: hybrid_rules_first(systems["rules_strong"][e.id], raws[n][e.id], tau["tau_add"]) for e in exs}
            systems[f"hybrid_rules_first_veto:{n}"] = {e.id: hybrid_rules_first(systems["rules_strong"][e.id], raws[n][e.id], tau["tau_add"], amb[e.id], tau["tau_veto"]) for e in exs}
        rep = {"examples": len(exs), "entities": sum(len(g) for g in gold.values()), "no_entity_examples": sum(1 for e in exs if not e.spans), "systems": {}}
        counts = {}
        for sn, pred in systems.items():
            m = entity_metrics(gold, pred); counts[sn] = per_example_counts(gold, pred)
            slim = lambda x: {k: (round(v, 4) if isinstance(v, float) else v) for k, v in x.items()}
            kinds = defaultdict(lambda: [0, 0, 0])
            for i, (tp, fp, fn) in counts[sn].items():
                k = kinds[by_id[i].kind if i in by_id else "unknown"]; k[0] += tp; k[1] += fp; k[2] += fn
            rep["systems"][sn] = {
                "micro": slim(m["micro"]), "macro_f1": round(m["macro_f1"], 4), "per_class": {l: slim(c) for l, c in m["per_class"].items()},
                "ci95_bootstrap": bootstrap_ci(counts[sn], a.bootstrap),
                "by_source": {k: slim(prf(*v)) for k, v in sorted(kinds.items())},
                "recall_unseen_key_examples": recall_on(exs, pred, lambda e, sp: ctx.unseen_key(e)),
                "recall_seen_key_examples": recall_on(exs, pred, lambda e, sp: not ctx.unseen_key(e)),
                "recall_unseen_context": recall_on(exs, pred, lambda e, sp: ctx.unseen_context(e, sp)),
                "recall_seen_context": recall_on(exs, pred, lambda e, sp: not ctx.unseen_context(e, sp)),
                "recall_non_ascii": recall_on(exs, pred, lambda e, sp: not e.text[sp[0]:sp[1]].isascii()),
                "recall_lowercase_entity": recall_on(exs, pred, lambda e, sp: e.text[sp[0]:sp[1]].islower()),
                "recall_multi_entity_examples": recall_on(exs, pred, lambda e, sp: len(e.spans) >= 2),
                "fp_rate_entity_free_examples": no_entity_false_positive_rate(exs, pred),
                "fp_rate_hard_negative_examples": no_entity_false_positive_rate(exs, pred, "hard_negative"),
                "error_counts": {"false_positives": m["micro"]["fp"], "false_negatives": m["micro"]["fn"]},
                "error_samples_fp": error_samples(m["errors"]["false_positives"], by_id, 15, a.include_text),
                "error_samples_fn": error_samples(m["errors"]["false_negatives"], by_id, 15, a.include_text)}
        # ML-only threshold sweep + reliability
        rep["bilstm_threshold_sweep"], rep["raw_score_reliability"] = {}, {}
        for n in models:
            rep["bilstm_threshold_sweep"][n] = {f"{t:.2f}": {k: round(v, 4) for k, v in entity_metrics(gold, {i: [(s, e2, l) for s, e2, l, sc in r if sc >= t] for i, r in raws[n].items()})["micro"].items() if k in ("precision", "recall", "f1")}
                                                for t in [0, .1, .25, .5, .75, .9, .97]}
            pairs = [(sc, int((s, e2, l) in set(gold[i]))) for i, r in raws[n].items() for s, e2, l, sc in r]
            ece, rows = reliability_bins(pairs); rep["raw_score_reliability"][n] = {"ece_vs_span_precision": ece, "bins": rows}
        # hybrid contribution vs rules
        rep["hybrid_vs_rules"] = {}
        for n in hyb_names:
            for pol in ("hybrid_union", "hybrid_rules_first", "hybrid_rules_first_veto"):
                sn = f"{pol}:{n}"; r0, r1 = rep["systems"]["rules_strong"]["micro"], rep["systems"][sn]["micro"]
                rep["hybrid_vs_rules"][sn] = {"additional_true_detections": r1["tp"] - r0["tp"], "additional_false_positives": r1["fp"] - r0["fp"],
                                              "lost_true_detections": sum(max(0, counts["rules_strong"][i][0] - counts[sn][i][0]) for i in counts[sn]),
                                              "f1_delta_vs_rules": round(r1["f1"] - r0["f1"], 4),
                                              "paired_bootstrap_f1_delta": paired_bootstrap_diff(counts[sn], counts["rules_strong"], min(a.bootstrap, 500))}
        rep["bilstm_vs_rules_paired"] = {n: paired_bootstrap_diff(counts[f"bilstm:{n}"], counts["rules_strong"], min(a.bootstrap, 500)) for n in models}
        rep["cpu_timing"] = timing
        result["datasets"][dn] = rep
        print(f"== {dn}: {len(exs)} examples")
        for sn, s in rep["systems"].items():
            if sn.startswith(("hybrid_union", "hybrid_rules_first_veto")) and len(hyb_names) > 1: pass
            print(f"  {sn:42s} P {s['micro']['precision']:.3f} R {s['micro']['recall']:.3f} F1 {s['micro']['f1']:.3f}  CI {s['ci95_bootstrap']['f1']}", flush=True)
    if a.seed_group:
        g = a.seed_group.split(",")
        result["seed_group"] = {dn: {"models": g, "bilstm_f1": [result["datasets"][dn]["systems"][f"bilstm:{n}"]["micro"]["f1"] for n in g]} for dn in names}
        for dn, v in result["seed_group"].items():
            v["mean"], v["std"] = round(mean(v["bilstm_f1"]), 4), round(pstdev(v["bilstm_f1"]), 4)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(result, open(a.out, "w"), indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
