"""Report verbatim overlap between a ground-truth manifest's gold strings and the V2 model's training/evaluation data.

Independence hygiene, run BEFORE a model is evaluated on a fixture: gold strings that appear verbatim as labelled spans in the
V2 train / val / calib / challenge sets would make the fixture less independent. Compares gold strings (rebuilt from the
generator's scenario table, since the manifest stores only hashes) against every labelled span, case-insensitively.

Usage: python scripts/groundtruth/check_overlap.py
"""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'examples'))
import generate_groundtruth_fixture as fixture  # noqa: E402

DATASETS = [ROOT / 'src/packet_pii/ml/datasets/v2' / f'{name}.jsonl.gz' for name in ('train', 'val', 'calib')] + \
           [ROOT / 'src/packet_pii/ml/datasets/challenge_v1.jsonl.gz']


def gold_strings() -> set:
    _, fields = fixture.build()
    return {f['text'][a:b] for f in fields for a, b, _ in f['spans']}


def model_strings() -> dict:
    seen = {}
    for path in DATASETS:
        with gzip.open(path, 'rt', encoding='utf-8') as handle:
            for line in handle:
                row = json.loads(line)
                for a, b, _ in row['spans']:
                    seen.setdefault(row['text'][a:b].casefold(), path.stem)
    return seen


def main() -> int:
    gold, known = gold_strings(), model_strings()
    overlap = sorted((g, known[g.casefold()]) for g in gold if g.casefold() in known)
    print(f'gold strings: {len(gold)}; labelled spans in V2 data: {len(known)}; verbatim overlap: {len(overlap)}')
    for text, dataset in overlap:
        print(f'  OVERLAP {text!r} (also in {dataset})')
    return 1 if overlap else 0


if __name__ == '__main__':
    raise SystemExit(main())
