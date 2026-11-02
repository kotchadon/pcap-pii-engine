#!/usr/bin/env python3
"""Bounded, local-only genuine V2 diagnostics. Instrumented times are not throughput results."""
import argparse
import cProfile
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import pstats
import resource
import statistics
import sys
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--pairs', type=int, default=256)
    p.add_argument('--threads', type=int, default=2)
    p.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[2])
    args = p.parse_args()
    if not 32 <= args.pairs <= 2048 or not 1 <= args.threads <= 8:
        p.error('pairs must be 32..2048 and threads 1..8')
    if args.output.exists():
        p.error('output exists')
    root = args.source_root.resolve()
    sys.path.insert(0, str(root / 'src'))
    import torch
    from packet_pii.ml.bilstm import load_predictor
    torch.set_num_threads(args.threads)
    fixture_spec = importlib.util.spec_from_file_location('fixture', root / 'scripts/ml/bench_v2_inference.py')
    fixture = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(fixture)
    pairs = fixture.synthetic_pairs(args.pairs)
    checkpoint = root / 'src/packet_pii/ml/artifacts/bilstm_v2'
    tick = time.perf_counter()
    predictor, meta = load_predictor(str(checkpoint))  # verifies every weight checksum
    load_seconds = time.perf_counter() - tick
    if meta['model_version'] != 'bilstm-v2-d1f9e9fb9a2b':
        raise RuntimeError('not the frozen V2 ensemble')
    timings, cpu_times, peaks = [], [], []
    reference = None
    for _ in range(4):  # one cold invocation, three warm; never a training loop
        tick = time.perf_counter()
        cpu_tick = time.process_time()
        result = predictor.predict_pairs(pairs)
        timings.append(time.perf_counter() - tick)
        cpu_times.append(time.process_time() - cpu_tick)
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peaks.append(int(peak if sys.platform == 'darwin' else peak * 1024))
        if reference is None:
            reference = result
        elif result != reference:
            raise AssertionError('non-repeatable predictions')
    from packet_pii.ml import bilstm
    stages = {}
    originals = {}
    module_originals = []
    padding = {'actual_positions': 0, 'padded_positions': 0, 'batches': 0,
               'nonempty_character_rows':0,'unique_nonempty_character_rows':0,'equal_length_batches':0}
    def timer(name, function):
        def measured(*a, **kw):
            tick = time.perf_counter()
            value = function(*a, **kw)
            stages[name] = stages.get(name, 0.) + time.perf_counter() - tick
            if name == 'collate':
                padding['actual_positions'] += sum(len(e) for e in a[0])
                padding['padded_positions'] += value['word'].numel()
                padding['batches'] += 1
                rows = [tuple(row) for row in value['chars'].reshape(-1,value['chars'].shape[-1]).tolist() if any(row)]
                padding['nonempty_character_rows'] += len(rows)
                padding['unique_nonempty_character_rows'] += len(set(rows))
                padding['equal_length_batches'] += int(bool((value['lengths']==value['word'].shape[1]).all()))
            return value
        return measured
    try:
        # Synchronous CPU forwards only: module times overlap _forward and must
        # not be added to it. No values, token strings or weights enter output.
        for model in predictor.models:
            for name, module in model.named_children():
                modules = list(module) if name == 'conv_extra' else [module]
                for child in modules:
                    module_originals.append((child, child.forward))
                    child.forward = timer('module_' + ('conv' if name == 'conv_extra' else name), child.forward)
        names = ['tokenize', 'encode', 'collate', '_forward', 'viterbi_decode', 'tags_to_spans']
        if hasattr(bilstm, '_character_plan'):names.append('_character_plan')
        for name in names:
            originals[name] = getattr(bilstm, name)
            setattr(bilstm, name, timer(name, originals[name]))
        tick = time.perf_counter()
        assert predictor.predict_pairs(pairs) == reference
        stages['whole_invocation'] = time.perf_counter() - tick
    finally:
        for module, original in module_originals:
            module.forward = original
        for name, function in originals.items():
            setattr(bilstm, name, function)
    prof = cProfile.Profile()
    prof.enable()
    profiled = predictor.predict_pairs(pairs)
    prof.disable()
    assert profiled == reference
    stats = pstats.Stats(prof)
    rows = [{'file': Path(k[0]).name, 'line': k[1], 'function': k[2], 'calls': v[1],
             'self_seconds': v[2], 'cumulative_seconds': v[3]} for k, v in stats.stats.items()]
    # Only 32 fields: no whole-capture tensor tracing or raw field values in traces.
    with torch.profiler.profile(activities=[torch.profiler.ProfilerActivity.CPU],
                                profile_memory=True, record_shapes=False) as tp:
        predictor.predict_pairs(pairs[:32])
    operators = [{'operator': e.key, 'calls': e.count, 'self_cpu_us': e.self_cpu_time_total,
                  'self_cpu_memory_bytes': e.self_cpu_memory_usage} for e in tp.key_averages()]
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    output = dict(platform=platform.platform(), architecture=platform.machine(), python=platform.python_version(),
                  torch=torch.__version__, threads=args.threads, model_version=meta['model_version'],
                  weights={str(f.relative_to(checkpoint)): hashlib.sha256(f.read_bytes()).hexdigest()
                           for f in sorted(checkpoint.glob('*/model.pt'))}, pairs=len(pairs),
                  input_sha256=hashlib.sha256(json.dumps(pairs, ensure_ascii=False).encode()).hexdigest(),
                  prediction_sha256=hashlib.sha256(json.dumps(reference).encode()).hexdigest(),
                  model_load_seconds=load_seconds, cold_seconds=timings[0], warm_seconds=timings[1:],
                  process_cpu_seconds=cpu_times,
                  average_cpu_cores=[cpu / wall for cpu, wall in zip(cpu_times, timings)],
                  lifetime_peak_rss_before_profiler_bytes=peaks,
                  warm_median_seconds=statistics.median(timings[1:]),
                  timed_stages_seconds=stages, padding=padding,
                  lifetime_peak_rss_includes_profiler_bytes=int(peak if sys.platform == 'darwin' else peak * 1024),
                  cprofile_total_seconds=stats.total_tt,
                  cprofile_top=sorted(rows, key=lambda r: r['cumulative_seconds'], reverse=True)[:70],
                  torch_top=sorted(operators, key=lambda r: r['self_cpu_us'], reverse=True)[:40],
                  notes='Fictional model-only workload; no capture throughput or accuracy claim. Nested cumulative times overlap; diagnostic whole-call timing includes row-counting overhead. Cold/warm timings precede all instrumentation.')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'warm_median_seconds': output['warm_median_seconds']}))


if __name__ == '__main__':
    main()
