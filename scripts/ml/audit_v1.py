#!/usr/bin/env python
"""Diagnostic audit of a checkpoint (V1 or V2) on V1 TRAIN/VAL/CALIB data only (the frozen V1 test is NOT read).

  python scripts/ml/audit_v1.py --checkpoint src/packet_pii/ml/artifacts/bilstm_v1 --out docs/ml/results/v2_audit_v1.json

Outputs aggregate counts only (no raw field text).
"""
import argparse, json, os, random, re, sys
from collections import Counter, defaultdict
from statistics import mean, pstdev

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
import torch
from packet_pii.ml import data as D
from packet_pii.ml.bilstm import load_predictor
from packet_pii.ml.encoding import location_tokens
from packet_pii.ml.metrics import entity_metrics
from packet_pii.ml.spans import tokenize

GREET = {"hello", "hi", "hey", "dear", "signed", "congratulations", "welcome", "thanks", "everyone", "there",
         "regards", "sincerely", "account", "user", "banned", "reported", "greetings", "good", "morning"}


def preds(P, exs, th):
    raw = P.predict_pairs([(e.location, e.text) for e in exs])
    return {e.id: [(s, t, l) for s, t, l, sc in r if sc >= th] for e, r in zip(exs, raw)}


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--checkpoint", required=True); ap.add_argument("--out", required=True)
    a = ap.parse_args()
    torch.set_num_threads(4)
    P, meta = load_predictor(a.checkpoint); vocab = P.vocab
    th = meta["min_score"]
    ds = D.generate_dataset(meta.get("training", {}).get("data_seed", 1234))
    out = {"checkpoint": meta["model_version"], "min_score": th}
    rng = random.Random(0)

    # ---- A. template / key-shortcut structure of the training set
    tr = ds["train"]
    tpl = Counter(e.template for e in tr if not e.kind.startswith("field_"))
    keys = defaultdict(Counter)
    for e in tr:
        if e.kind.startswith("field_"):
            k = re.split(r"\.", re.sub(r"\[\d+\]", "", e.location))[-1]
            keys[k][e.spans[0][2] if e.spans else "NONE"] += 1
    pure = sum(1 for k, c in keys.items() if len(c) == 1)
    out["A_train_structure"] = {
        "train_examples": len(tr), "distinct_free_text_templates": len(tpl),
        "examples_per_template_mean": round(mean(tpl.values()), 1), "distinct_field_keys": len(keys),
        "keys_with_single_label_in_train": pure,
        "ambiguous_keys": {k: dict(c) for k, c in keys.items() if len(c) > 1},
        "entity_types_in_train": dict(Counter(l for e in tr for *_, l in e.spans)),
        "distinct_entity_strings_train": len({e.text[s:t].lower() for e in tr for s, t, _ in e.spans}),
        **({"train_loss_last_epoch": meta["training"]["history"][-1]["train_loss"],
            "val_f1_last10_mean": round(mean(h["val_micro_f1"] for h in meta["training"]["history"][-10:]), 4),
            "val_f1_last10_std": round(pstdev(h["val_micro_f1"] for h in meta["training"]["history"][-10:]), 4)} if meta.get("training", {}).get("history") else {})}
    cap = lambda s: s[:1].isupper()
    out["A_surface_shortcuts_train"] = {
        "person_spans_capitalised": round(mean(cap(e.text[s:t]) for e in tr for s, t, l in e.spans if l == "PERSON_NAME"), 3),
        "username_spans_capitalised": round(mean(cap(e.text[s:t]) for e in tr for s, t, l in e.spans if l == "USERNAME"), 3),
        "negative_field_values_capitalised": round(mean(cap(e.text) for e in tr if e.kind == "field_neg"), 3)}

    # ---- A2. frame-vs-entity reliance (VAL, single-entity free-text examples)
    val = ds["val"]
    base = preds(P, val, th)
    def swap(e, rep):
        s, t, l = e.spans[0]
        txt = e.text[:s] + rep + e.text[t:]
        return type(e)(e.id, e.split, e.family, e.kind, e.template, e.skeleton, e.location, txt, ((s, s + len(rep), l),))
    singles = [e for e in val if e.kind in ("text_person", "text_user") and len(e.spans) == 1]
    cities = D.POOLS["city"]["val"]
    sw = [swap(e, rng.choice(cities)) for e in singles]
    p = preds(P, sw, th)
    still = sum(1 for e in sw if any(a == e.spans[0][0] and b == e.spans[0][1] for a, b, _ in p[e.id]))
    out["A2_frame_reliance"] = {"examples": len(sw), "entity_replaced_by_city_name_still_tagged_exact": round(still / len(sw), 3),
                                "any_span_overlapping_replacement": round(sum(1 for e in sw if any(a < e.spans[0][1] and b > e.spans[0][0] for a, b, _ in p[e.id])) / len(sw), 3)}
    names = [f"{rng.choice(D.POOLS['first']['val'])} {rng.choice(D.POOLS['last']['val'])}" for _ in range(300)]
    neutral = ["Welcome to {}!", "Server {} restarted at 03:00", "Download {} to continue.", "{} announced quarterly results."]
    fp = Counter(); tot = 0
    for nm in names:
        for fr in neutral:
            txt = fr.format(nm); s = txt.index(nm)
            r = P.predict_pairs([("json_body.message", txt)])[0]
            tot += 1; fp["tagged_person_or_user"] += any(sc >= th and a < s + len(nm) and b > s for a, b, l, sc in r)
    out["A2_entity_in_neutral_frame"] = {"cases": tot, "tagged_fraction": round(fp["tagged_person_or_user"] / tot, 3)}

    # ---- B. unseen / wrong / absent keys
    fv = [e for e in val if e.kind == "field_person" and e.spans]
    def with_key(e, loc):
        return type(e)(e.id, e.split, e.family, e.kind, e.template, e.skeleton, loc, e.text, e.spans)
    def rec(exs):
        pr = preds(P, exs, th); m = entity_metrics({e.id: e.spans for e in exs}, pr); return round(m["micro"]["recall"], 3)
    trkeys = D.KEYS["user"]["common"] + D.KEYS["user"]["train"]
    seen = [e for e in fv if all(t in vocab.words for t in location_tokens(e.location))]
    unseen = [e for e in fv if any(t not in vocab.words for t in location_tokens(e.location))]
    wrong = [with_key(e, rng.choice(trkeys)) for e in fv]
    pw = preds(P, wrong, th)
    flips = sum(1 for e in wrong if any(l == "USERNAME" for _, _, l in pw[e.id])) / len(wrong)
    out["B_keys"] = {"field_person_n": len(fv), "recall_all_key_tokens_in_vocab": rec(seen), "n_seen": len(seen),
                     "recall_some_key_token_unseen": rec(unseen), "n_unseen": len(unseen),
                     "recall_key_replaced_by_neutral_word": rec([with_key(e, "json_body.field") for e in fv]),
                     "recall_key_removed_to_text_only": rec([with_key(e, "x") for e in fv]),
                     "person_value_under_username_key_labelled_USERNAME": round(flips, 3)}
    ufv = [e for e in val if e.kind == "field_user" and e.spans]
    out["B_keys"]["field_user_recall_seen_keys"] = rec([e for e in ufv if all(t in vocab.words for t in location_tokens(e.location))])
    out["B_keys"]["field_user_recall_unseen_keys"] = rec([e for e in ufv if any(t not in vocab.words for t in location_tokens(e.location))])
    uk = D.KEYS["neg"]["common"] + D.KEYS["neg"]["train"]

    # ---- C/D. error taxonomy on VAL + CALIB (counts only)
    tax = {}
    for sp in ("val", "calib"):
        exs = ds[sp]; pr = preds(P, exs, th); c = Counter(); fpc = Counter(); fnc = Counter(); script = Counter(); scr_tot = Counter()
        for e in exs:
            g = set(e.spans); q = set(pr[e.id])
            for (s, t, l) in q - g:
                ov = [x for x in g if x[0] < t and x[1] > s]
                if any(x[2] != l and (x[0], x[1]) == (s, t) for x in ov): c["FP_label_confusion_same_span"] += 1
                elif ov: c["FP_boundary_overlap_with_gold"] += 1
                else:
                    c["FP_no_gold_overlap"] += 1
                    w = e.text[s:t].split()[0].lower().strip(",.!:") if e.text[s:t].split() else ""
                    toks = {x.text for x in tokenize(e.text[s:t])}
                    if w in GREET: fpc["greeting_or_cue_word"] += 1
                    elif any(x in {y for c_ in ("city", "company", "product", "stem", "word") for y in D.POOLS[c_][sp]} for x in [e.text[s:t]]): fpc["city_company_product_file_word"] += 1
                    elif e.kind in ("field_neg",): fpc["negative_field_value"] += 1
                    else: fpc["other"] += 1
            for (s, t, l) in g - q:
                ov = [x for x in q if x[0] < t and x[1] > s]
                if any((x[0], x[1]) == (s, t) and x[2] != l for x in ov): c["FN_label_confusion_same_span"] += 1
                elif ov: c["FN_boundary_overlap"] += 1
                else: c["FN_missed_entirely"] += 1
                script["non_ascii" if not e.text[s:t].isascii() else "ascii"] += 1
                fnc["lower" if e.text[s:t].islower() else "upper" if e.text[s:t].isupper() else "cased"] += 1
            for (s, t, l) in g:
                scr_tot["non_ascii" if not e.text[s:t].isascii() else "ascii"] += 1
        tax[sp] = {"counts": dict(c), "fp_pure_breakdown": dict(fpc), "fn_by_script": dict(script), "support_by_script": dict(scr_tot), "fn_by_case": dict(fnc)}
    out["CD_error_taxonomy"] = tax

    # ---- E. variance sources: per-template recall spread on VAL+CALIB
    byt = defaultdict(lambda: [0, 0])
    for sp in ("val", "calib"):
        pr = preds(P, ds[sp], th)
        for e in ds[sp]:
            if e.kind.startswith("field_"): continue
            for sp_ in e.spans:
                byt[(sp, e.template)][1] += 1; byt[(sp, e.template)][0] += sp_ in pr[e.id]
    rr = {f"{k[0]}|{k[1][:40]}": round(v[0] / v[1], 2) for k, v in byt.items() if v[1] >= 15}
    out["E_template_recall"] = {"templates_with_n>=15": len(rr), "min": min(rr.values()), "max": max(rr.values()),
                                "std": round(pstdev(rr.values()), 3),
                                "templates_below_0.5": sum(1 for v in rr.values() if v < 0.5), "per_template": rr}
    sweep = {}
    for sp in ("val", "calib"):
        sweep[sp] = {f"{t:.2f}": round(entity_metrics({e.id: e.spans for e in ds[sp]}, preds(P, ds[sp], t))["micro"]["f1"], 3) for t in (0.1, 0.25, 0.5, 0.75)}
    out["E_threshold_f1"] = sweep
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(out, open(a.out, "w"), indent=1, sort_keys=True)
    print(json.dumps({k: v for k, v in out.items() if k not in ("E_template_recall", "CD_error_taxonomy")}, indent=1, sort_keys=True))
    print(json.dumps(out["CD_error_taxonomy"], indent=1, sort_keys=True)); print({k: v for k, v in out["E_template_recall"].items() if k != "per_template"})


if __name__ == "__main__":
    main()
