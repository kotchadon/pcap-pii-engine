"""Deterministic, fully fictional reproduction case for the automated context-matched probe assessment.

Builds a small structural context summary from made-up field *shapes* (no real capture, no real values), generates and
freezes the probe suite, and optionally runs the committed V2 checkpoint on it.

    python scripts/probe/reproduce.py                 # writes examples/probe/*.json (suite metadata only, no model)
    python scripts/probe/reproduce.py --model         # also runs V2 and writes docs/ml/results/probe_reproduction_v2.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from packet_pii.quality import AssessmentBudget, ContextSampler, DEFAULT_SEED, assess_summary, generate_suite  # noqa: E402

# Fictional messages: (direction, method, content-type, [(location, text), ...]). Only the *shape* of each text matters to the summary.
MESSAGES = (
    ('request', 'POST', 'application/json', [('json_body.profile.displayName', 'Aa Bb'), ('json_body.profile.bio', 'x y z w q r s'),
                                             ('json_body.timezone', 'Aa/Bb'), ('json_body.order_id', 'AAA-11111')]),
    ('request', 'POST', 'application/json', [('json_body.author', 'Aa Bb'), ('json_body.body', 'x y z w q r s t')]),
    ('request', 'POST', 'application/x-www-form-urlencoded', [('form.username', 'aaaa_bbbb11'), ('form.remember', '1')]),
    ('request', 'GET', None, [('query_parameter.user', 'aaaa_bbbb11'), ('query_parameter.q', 'aa bb')]),
    ('response', None, 'application/json', [('json_body.data.attributes.message', 'x y z w q'), ('json_body.status', 'ok')]),
)


def reproduction_summary() -> dict:
    sampler = ContextSampler()
    for n, (direction, method, ctype, fields) in enumerate(MESSAGES):
        sampler.observe_message({'message_type': direction, 'fields': fields,
                                 'http': {'method': method, 'content_type': ctype, 'content_encoding': None, 'transfer_encoding': None}})
    return sampler.summary()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', action='store_true', help='run the committed V2 checkpoint on the frozen suite')
    parser.add_argument('--out-dir', default=str(ROOT / 'examples' / 'probe'))
    args = parser.parse_args()
    summary, budget = reproduction_summary(), AssessmentBudget()
    suite = generate_suite(summary, budget, DEFAULT_SEED)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'reproduction_summary.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    (out / 'reproduction_suite_meta.json').write_text(json.dumps({**suite.meta, 'budget': budget.public()}, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    print('suite', suite.meta['probes'], 'probes, hash', suite.hash)
    if args.model:
        from packet_pii.hybrid import load_experimental_bilstm
        result = assess_summary(load_experimental_bilstm(str(ROOT / 'src/packet_pii/ml/artifacts/bilstm_v2')), summary, budget)
        target = ROOT / 'docs' / 'ml' / 'results' / 'probe_reproduction_v2.json'
        target.write_text(json.dumps(result, indent=1, ensure_ascii=False) + '\n', encoding='utf-8')
        print(result['status'], result['headline'], result['probes'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
