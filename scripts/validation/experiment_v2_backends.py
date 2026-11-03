#!/usr/bin/env python3
"""Opt-in, bounded genuine V2 backend experiments. Never changes production settings.

Run each variant in its own process. An exact reference is always evaluated first;
quantized/dense outputs are candidates, never accepted model accuracy. No raw input
or prediction values are emitted. Compilation should be invoked by a process with
an external timeout; one compiler worker is permitted.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import resource
import statistics
import sys
import time


def compare(reference, candidate, threshold):
    labels = lambda rows: [[s[:3] for s in field] for field in rows]
    decisions = lambda rows: [[s[:3] for s in field if s[3] >= threshold] for field in rows]
    same = labels(reference) == labels(candidate)
    return dict(same_labels_spans_order=same,
                same_threshold_decisions=decisions(reference) == decisions(candidate),
                raw_scores_bit_identical=reference == candidate,
                max_raw_score_difference=max((abs(a[3]-b[3]) for f,g in zip(reference,candidate)
                                              for a,b in zip(f,g)), default=0.) if same else None)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--variant', choices=('dense-equal-length', 'dynamic-int8', 'compile'), required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--pairs', type=int, default=256)
    p.add_argument('--threads', type=int, default=2)
    args = p.parse_args()
    if not 32 <= args.pairs <= 256 or not 1 <= args.threads <= 8:
        p.error('pairs 32..256; threads 1..8')
    if args.output.exists():p.error('output exists')
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / 'src'))
    import torch
    from torch.nn.utils.rnn import PackedSequence
    from packet_pii.ml.bilstm import load_predictor
    torch.set_num_threads(args.threads)
    fixture_spec = importlib.util.spec_from_file_location('fixture', root/'scripts/ml/bench_v2_inference.py')
    fixture = importlib.util.module_from_spec(fixture_spec); fixture_spec.loader.exec_module(fixture)
    pairs = fixture.synthetic_pairs(args.pairs)
    checkpoint = root/'src/packet_pii/ml/artifacts/bilstm_v2'
    predictor, meta = load_predictor(str(checkpoint))
    if meta['model_version'] != 'bilstm-v2-d1f9e9fb9a2b':raise RuntimeError('genuine frozen V2 required')
    tick = time.perf_counter(); reference = predictor.predict_pairs(pairs)
    baseline_cold = time.perf_counter()-tick
    baseline = []
    for _ in range(3):
        tick = time.perf_counter(); assert predictor.predict_pairs(pairs) == reference
        baseline.append(time.perf_counter()-tick)
    record = dict(variant=args.variant, platform=platform.platform(), torch=torch.__version__,
                  threads=args.threads, pairs=len(pairs), model_version=meta['model_version'],
                  threshold=meta['min_score'],
                  input_sha256=hashlib.sha256(json.dumps(pairs,ensure_ascii=False).encode()).hexdigest(),
                  weights_sha256={f.parent.name:hashlib.sha256(f.read_bytes()).hexdigest()
                                  for f in checkpoint.glob('*/model.pt')},
                  baseline_cold_seconds=baseline_cold, baseline_warm_seconds=baseline,
                  notes='Experimental only; timings sequential in one process. No M3/full-scan claim; no defaults or assets changed.')
    tick = time.perf_counter()
    try:
        if args.variant == 'dense-equal-length':
            for model in predictor.models:
                original = model.lstm.forward
                def dense(packed, hx=None, original=original):
                    if (hx is None and isinstance(packed, PackedSequence)
                            and bool(torch.all(packed.batch_sizes == packed.batch_sizes[0]))):
                        steps, batch = len(packed.batch_sizes), int(packed.batch_sizes[0])
                        x = packed.data.reshape(steps,batch,-1).transpose(0,1)
                        y, state = original(x)
                        return PackedSequence(y.transpose(0,1).reshape(steps*batch,-1),
                                              packed.batch_sizes,packed.sorted_indices,packed.unsorted_indices), state
                    return original(packed,hx)
                model.lstm.forward = dense
        elif args.variant == 'dynamic-int8':
            predictor.models = [torch.ao.quantization.quantize_dynamic(
                m, {torch.nn.LSTM,torch.nn.Linear}, dtype=torch.qint8) for m in predictor.models]
            predictor.model = predictor.models[0]
        else:
            import torch._inductor.config
            torch._inductor.config.compile_threads = 1
            for model in predictor.models:
                model.forward = torch.compile(model.forward, fullgraph=True)
        record['preparation_seconds'] = time.perf_counter()-tick
        tick = time.perf_counter(); candidate = predictor.predict_pairs(pairs)
        record['candidate_cold_seconds'] = time.perf_counter()-tick
        warm = []
        for _ in range(3):
            tick = time.perf_counter(); repeated = predictor.predict_pairs(pairs)
            warm.append(time.perf_counter()-tick)
            if repeated != candidate:raise RuntimeError('nonrepeatable experiment')
        record.update(status='measured', candidate_warm_seconds=warm,
                      warm_median_reduction_percent=100*(1-statistics.median(warm)/statistics.median(baseline)),
                      equivalence=compare(reference,candidate,meta['min_score']))
    except Exception as exc:
        # Exception messages can contain graph/input details. Publish only type.
        record.update(status='unsupported_or_failed',error_type=type(exc).__name__,
                      attempted_seconds=time.perf_counter()-tick)
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    record['lifetime_peak_rss_includes_reference_bytes'] = int(peak if sys.platform=='darwin' else peak*1024)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'output':str(args.output),'status':record['status'],'equivalence':record.get('equivalence')}))
    return 0 if record['status']=='measured' else 2


if __name__ == '__main__':raise SystemExit(main())
