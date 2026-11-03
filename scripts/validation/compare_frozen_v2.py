#!/usr/bin/env python3
"""Compare genuine frozen V2 in isolated CPU processes; outputs contain no field text.

Both sources consume the candidate's verified frozen assets and identical fictional
inputs. Raw scores must be bit-identical for this CPU preparation/decoder change.
This is model-only equivalence and throughput, not capture accuracy or M3 acceptance.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import sys
import tempfile
import time


def load_module(path):
    spec = importlib.util.spec_from_file_location('fixture', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def worker(spec):
    root, assets = Path(spec['root']), Path(spec['assets'])
    sys.path.insert(0, str(root / 'src'))
    import torch
    from packet_pii.ml.bilstm import load_predictor
    torch.set_num_threads(spec['threads'])
    fixture = load_module(assets / 'scripts/ml/bench_v2_inference.py')
    pairs = fixture.synthetic_pairs(spec['pairs'])
    if spec['frozen']:
        pairs += fixture.frozen_pairs()
    checkpoint = assets / 'src/packet_pii/ml/artifacts/bilstm_v2'
    start = time.perf_counter()
    predictor, meta = load_predictor(str(checkpoint), spec['batch_size'], max_batch_tokens=spec['token_cap'])
    load_time = time.perf_counter() - start
    if meta['model_version'] != 'bilstm-v2-d1f9e9fb9a2b':
        raise RuntimeError('frozen V2 required')
    times, peaks, reference = [], [], None
    for _ in range(spec['repeat'] + 1):
        start = time.perf_counter()
        predictions = predictor.predict_pairs(pairs)
        times.append(time.perf_counter() - start)
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peaks.append(int(peak if sys.platform == 'darwin' else peak * 1024))
        if reference is None:
            reference = predictions
        elif reference != predictions:
            raise RuntimeError('predictions changed across repeats')
    return {'platform': platform.platform(), 'architecture': platform.machine(), 'python': platform.python_version(),
            'torch': torch.__version__, 'threads': spec['threads'], 'batch_size': spec['batch_size'],
            'max_batch_tokens': spec['token_cap'], 'model_version': meta['model_version'], 'min_score': meta['min_score'],
            'source_sha256': {name: hashlib.sha256((root / 'src/packet_pii/ml' / name).read_bytes()).hexdigest()
                              for name in ('bilstm.py', 'spans.py', 'encoding.py')},
            'weights_sha256': {p.parent.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in checkpoint.glob('*/model.pt')},
            'input_sha256': hashlib.sha256(json.dumps(pairs, ensure_ascii=False).encode()).hexdigest(),
            'fields': len(pairs), 'model_load_seconds': load_time, 'cold_seconds': times[0],
            'warm_seconds': times[1:], 'warm_median_seconds': statistics.median(times[1:]),
            'lifetime_peak_rss_bytes_by_iteration': peaks, 'predictions': reference}


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        spec = json.loads(Path(sys.argv[2]).read_text())
        Path(spec['result']).write_text(json.dumps(worker(spec)))
        return 0
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline-root', type=Path, required=True)
    p.add_argument('--candidate-root', type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--threads', type=int, default=2)
    p.add_argument('--repeat', type=int, default=3)
    p.add_argument('--pairs', type=int, default=256)
    p.add_argument('--include-frozen', action='store_true')
    p.add_argument('--batch-size', type=int, default=64)
    p.add_argument('--token-cap', type=int, default=4096)
    args = p.parse_args()
    if args.output.exists():p.error('output exists')
    if not 1 <= args.repeat <= 3 or not 1 <= args.threads <= 8 or not 32 <= args.pairs <= 2048:
        p.error('repeat 1..3; threads 1..8; pairs 32..2048')
    if not 1 <= args.batch_size <= 512 or not 192 <= args.token_cap <= 8192:
        p.error('batch-size 1..512; token-cap 192..8192')
    results = []
    with tempfile.TemporaryDirectory(prefix='trace-v2-compare-') as directory:
        directory = Path(directory)
        for name, root in (('baseline', args.baseline_root), ('candidate', args.candidate_root)):
            spec = {'root': str(root.resolve()), 'assets': str(args.candidate_root.resolve()), 'threads': args.threads,
                    'repeat': args.repeat, 'pairs': args.pairs, 'frozen': args.include_frozen,
                    'batch_size': args.batch_size, 'token_cap': args.token_cap, 'result': str(directory / (name + '.json'))}
            spec_path = directory / 'spec.json'
            spec_path.write_text(json.dumps(spec))
            subprocess.run([sys.executable, __file__, '--worker', str(spec_path)], check=True, timeout=300)
            results.append(json.loads(Path(spec['result']).read_text()))
    old, new = results
    old_predictions, new_predictions = old.pop('predictions'), new.pop('predictions')
    labels = lambda rows: [[span[:3] for span in field] for field in rows]
    accepted = lambda rows, threshold: [[s[:3] for s in f if s[3] >= threshold] for f in rows]
    same_labels = labels(old_predictions) == labels(new_predictions)
    differences = [abs(a[3] - b[3]) for x, y in zip(old_predictions, new_predictions) for a, b in zip(x, y)] if same_labels else []
    equivalence = {'same_inputs': old['input_sha256'] == new['input_sha256'],
                   'same_weights': old['weights_sha256'] == new['weights_sha256'],
                   'same_model_version': old['model_version'] == new['model_version'],
                   'same_configured_threshold': old['min_score'] == new['min_score'],
                   'same_labels_spans_field_order': same_labels,
                   'same_threshold_decisions': accepted(old_predictions, old['min_score']) == accepted(new_predictions, new['min_score']),
                   'raw_scores_bit_identical': old_predictions == new_predictions,
                   'max_raw_score_difference': max(differences, default=0.) if same_labels else None,
                   'unthresholded_spans': sum(map(len, old_predictions))}
    output = {'baseline': old, 'candidate': new, 'equivalence': equivalence,
              'warm_median_reduction_percent': 100 * (1 - new['warm_median_seconds'] / old['warm_median_seconds']),
              'scope': 'Isolated model-only CPU runs; excludes capture processing and report indexing.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'reduction_percent': output['warm_median_reduction_percent'], 'equivalence': equivalence}))
    return 0 if all(equivalence[k] for k in ('same_inputs','same_weights','same_model_version','same_configured_threshold',
                                            'same_labels_spans_field_order','same_threshold_decisions','raw_scores_bit_identical')) else 1


if __name__ == '__main__':
    raise SystemExit(main())
