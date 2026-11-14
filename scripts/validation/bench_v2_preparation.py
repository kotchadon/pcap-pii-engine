#!/usr/bin/env python3
"""Bounded microbenchmark on tensors/log probabilities from genuine V2, not random weights."""
import argparse
import importlib.util
import json
from pathlib import Path
import statistics
import sys
import time


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline-root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():p.error('output exists')
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / 'src'))
    import torch
    from packet_pii.ml import bilstm
    torch.set_num_threads(2)
    old_bilstm = module('packet_pii.ml._baseline_bilstm', a.baseline_root / 'src/packet_pii/ml/bilstm.py')
    old_spans = module('packet_pii.ml._baseline_spans', a.baseline_root / 'src/packet_pii/ml/spans.py')
    fixture = module('micro_fixture', root / 'scripts/ml/bench_v2_inference.py')
    predictor, meta = bilstm.load_predictor(str(root / 'src/packet_pii/ml/artifacts/bilstm_v2'))
    if meta['model_version'] != 'bilstm-v2-d1f9e9fb9a2b':raise RuntimeError('frozen V2 required')
    batches, rows = [], []
    collate, decode = bilstm.collate, bilstm.viterbi_decode
    def collect_batch(batch, max_seq):
        batches.append((batch, max_seq))
        return collate(batch, max_seq)
    def collect_rows(values):
        rows.append(values)
        return decode(values)
    try:
        bilstm.collate, bilstm.viterbi_decode = collect_batch, collect_rows
        predictor.predict_pairs(fixture.synthetic_pairs(256))
    finally:
        bilstm.collate, bilstm.viterbi_decode = collate, decode
    for batch, max_seq in batches:
        old, new = old_bilstm.collate(batch, max_seq), collate(batch, max_seq)
        assert all(torch.equal(old[k], new[k]) for k in old)
    assert all(old_spans.viterbi_decode(r) == decode(r) for r in rows)
    results = {}
    for name, baseline, candidate, inputs in (
        ('collate', old_bilstm.collate, collate, batches),
        ('viterbi_decode', old_spans.viterbi_decode, decode, [(r,) for r in rows])):
        samples = {'baseline': [], 'candidate': []}
        # Alternate order to reduce systematic warmup/order bias; no tensor profiling.
        for iteration in range(3):
            order = [('baseline', baseline), ('candidate', candidate)]
            for label, function in (order if iteration % 2 == 0 else order[::-1]):
                start = time.perf_counter()
                for args in inputs:function(*args)
                samples[label].append(time.perf_counter() - start)
        results[name] = {'calls_per_sample': len(inputs), 'seconds': samples,
                         'median_seconds': {k: statistics.median(v) for k, v in samples.items()}}
    a.output.write_text(json.dumps({'model_version': meta['model_version'], 'torch': torch.__version__,
                                    'threads': 2, 'exact_equivalence': True, 'results': results}, indent=2) + '\n')
    print(json.dumps(results))


if __name__ == '__main__':main()
