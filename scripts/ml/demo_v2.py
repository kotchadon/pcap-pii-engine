#!/usr/bin/env python
"""Small reproducible V2 inference example: one person name, one username, one hard negative.

  python scripts/ml/demo_v2.py [--checkpoint src/packet_pii/ml/artifacts/bilstm_v2] [--show-text]

Output is offsets / labels / scores only unless --show-text. Scores are RAW model scores (uncalibrated), not probabilities.
"""
import argparse, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from packet_pii.ml import FieldInput
from packet_pii.ml.infer import BiLSTMDetector
from packet_pii.ml.input_policy import run_with_policy

HERE = os.path.dirname(__file__)
CASES = [
    ("person name", FieldInput(0, "json_body.shipping.recipient", "Priyanka Venkataraman")),
    ("person in prose (KNOWN MISS, see V2_EVALUATION)", FieldInput(1, "body.text", "Thanks for the quick turnaround, Mateus.")),
    ("username", FieldInput(2, "json_body.audit.actor", "night_owl_77")),
    ("username in log", FieldInput(3, "body.text", "Accepted password for kfitzgerald from 10.1.2.3 port 52814 ssh2")),
    ("hard negative (company)", FieldInput(4, "json_body.invoice.billed_to", "Johnson & Johnson")),
    ("hard negative: city named like a person (KNOWN FALSE POSITIVE)", FieldInput(5, "json_body.geo.place", "Madison")),
    ("excluded by input policy (secret-bearing key)", FieldInput(6, "json_body.password", "Maria Garcia")),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkpoint", default=os.path.join(HERE, "..", "..", "src", "packet_pii", "ml", "artifacts", "bilstm_v2"))
    ap.add_argument("--show-text", action="store_true")
    a = ap.parse_args()
    det = BiLSTMDetector(a.checkpoint)
    res = run_with_policy(det, [f for _, f in CASES])
    print(f"model_version={det.model_version} min_score={det.min_score} (raw, uncalibrated scores)")
    for name, f in CASES:
        spans = [s for s in res.spans if s.field_index == f.field_index]
        skip = res.skipped.get(f.field_index)
        if skip:
            print(f"[{f.field_index}] {name}: SKIPPED by input policy {skip}")
            continue
        desc = "; ".join(f"{s.label.value}[{s.start},{s.end}) score={s.score:.3f}" + (f" text={f.text[s.start:s.end]!r}" if a.show_text else "") for s in spans)
        print(f"[{f.field_index}] {name}: {desc or 'no contextual finding'}")


if __name__ == "__main__":
    main()
