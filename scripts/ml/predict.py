#!/usr/bin/env python
"""Run the BiLSTM detector (default: V2 ensemble; pass --checkpoint .../bilstm_v1 for V1) on one field. Prints offsets/labels/scores only (no text) unless --show-text.

  python scripts/ml/predict.py --checkpoint src/packet_pii/ml/artifacts/bilstm_v1 \
      --location json_body.message --text "Hello, my name is Zoë Müller"
"""
import argparse, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from packet_pii.ml import FieldInput, run_detector
from packet_pii.ml.infer import BiLSTMDetector


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkpoint", default=os.path.join(os.path.dirname(__file__), "..", "..", "src", "packet_pii", "ml", "artifacts", "bilstm_v2"))
    ap.add_argument("--location", required=True)
    ap.add_argument("--text", required=True)
    ap.add_argument("--min-score", type=float, default=None)
    ap.add_argument("--show-text", action="store_true")
    a = ap.parse_args()
    det = BiLSTMDetector(a.checkpoint, a.min_score)
    spans = run_detector(det, [FieldInput(0, a.location, a.text)])
    print(f"model_version={det.model_version} min_score={det.min_score} spans={len(spans)}")
    for s in spans:
        extra = f" text={a.text[s.start:s.end]!r}" if a.show_text else ""
        print(f"{s.label.value} [{s.start},{s.end}) score={s.score:.4f} ({s.score_type.value}){extra}")


if __name__ == "__main__":
    main()
