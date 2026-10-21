"""Synthetic rule validation for the identity/demographic categories (taxonomy v1).

Runs the real ``packet_pii.detect.detect_fields`` over hand-labelled fictional field sets and scores it at FIELD level:
a unit is (message id, field location, category). Labels come only from the case file. Results are synthetic
rule-validation results for newly introduced categories, NOT real-world or deployment accuracy, and are separate from
the frozen BiLSTM V2 exact-span benchmarks.

Usage: python scripts/evaluate_identity_rules.py [--cases PATH] [--out PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from packet_pii.detect import detect_fields  # noqa: E402
from packet_pii.identity_rules import IDENTITY_CATEGORIES  # noqa: E402

DEFAULT_CASES = ROOT / 'examples' / 'identity_validation' / 'cases_v1.json'
DEFAULT_OUT = ROOT / 'docs' / 'integration' / 'results' / 'identity_rules_validation_v1.json'


def _ratio(num: int, den: int):
    return round(num / den, 4) if den else None


def _metrics(tp: int, fp: int, fn: int) -> dict:
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = (round(2 * precision * recall / (precision + recall), 4)
          if precision is not None and recall is not None and precision + recall else None)
    return {'tp': tp, 'fp': fp, 'fn': fn, 'precision': precision, 'recall': recall, 'f1': f1}


def evaluate(cases: dict, threshold: float = 0.8) -> dict:
    tp, fp, fn = Counter(), Counter(), Counter()
    confusion = Counter()
    errors = []
    subsets = {'all': Counter(), 'excluding_hard': Counter()}
    for message in cases['messages']:
        fields = [tuple(f) for f in message['fields']]
        gold = {(loc, cat) for loc, cat in message['expected']}
        pred = {(d.location, d.pii_type) for d in detect_fields(fields, threshold=threshold)
                if d.pii_type in IDENTITY_CATEGORIES}
        hard = 'hard' in message.get('tags', ())
        for loc, cat in gold | pred:
            outcome = 'tp' if (loc, cat) in gold and (loc, cat) in pred else 'fp' if (loc, cat) in pred else 'fn'
            {'tp': tp, 'fp': fp, 'fn': fn}[outcome][cat] += 1
            subsets['all'][outcome] += 1
            if not hard:
                subsets['excluding_hard'][outcome] += 1
            if outcome != 'tp':
                errors.append({'message': message['id'], 'location': loc, 'category': cat, 'error': outcome,
                               'hard_case': hard})
        gold_by_loc, pred_by_loc = dict(gold), dict(pred)
        for loc in set(gold_by_loc) | set(pred_by_loc):
            confusion[(gold_by_loc.get(loc, 'NONE'), pred_by_loc.get(loc, 'NONE'))] += 1
    per_category = {cat: _metrics(tp[cat], fp[cat], fn[cat]) for cat in IDENTITY_CATEGORIES}
    return {
        'label': 'Synthetic rule-validation results for newly introduced categories (not real-world accuracy)',
        'dataset': cases['name'],
        'evaluation_unit': cases['evaluation_unit'],
        'threshold': threshold,
        'messages': len(cases['messages']),
        'fields': sum(len(m['fields']) for m in cases['messages']),
        'hard_case_messages': sum('hard' in m.get('tags', ()) for m in cases['messages']),
        'micro': {name: _metrics(c['tp'], c['fp'], c['fn']) for name, c in subsets.items()},
        'per_category': per_category,
        'confusion_gold_vs_predicted': [{'gold': g, 'predicted': p, 'count': n}
                                        for (g, p), n in sorted(confusion.items()) if g != p],
        'errors': sorted(errors, key=lambda e: (e['message'], e['location'], e['category'])),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--cases', default=str(DEFAULT_CASES))
    parser.add_argument('--out', default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)
    result = evaluate(json.loads(Path(args.cases).read_text(encoding='utf-8')))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(result['micro'], indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
