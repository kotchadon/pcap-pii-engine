"""Rules-only detect_fields() micro-benchmark: current tree vs. a baseline git ref (no PCAP reconstruction, no ML).

Usage: python scripts/bench_identity_rules.py [--baseline-ref main] [--fields 200000] [--repeat 5]
Synthetic fictional field lists; reports best-of-N wall time and tracemalloc peak.
"""
from __future__ import annotations

import argparse
import importlib.util
import random
import subprocess
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))


def synthetic_messages(total_fields: int, seed: int = 7, per_message: int = 40):
    rng = random.Random(seed)
    keys = ['json_body.user.name', 'json_body.items[{i}].sku', 'json_body.items[{i}].price', 'query_parameter.page',
            'header.user-agent', 'header.accept', 'json_body.message', 'json_body.stage', 'form.comment',
            'json_body.event.timestamp', 'json_body.session_id', 'json_body.email', 'json_body.device.os',
            'json_body.device.ifa', 'json_body.user.age', 'json_body.user.gender', 'json_body.user_id',
            'json_body.request_id', 'json_body.metrics.retry_count', 'json_body.context.app.version']
    values = ['Ana Example', 'SKU-88127', '19.99', '3', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4)', '*/*',
              'hello world, nothing to see', 'beta', 'ok', '2024-05-01T12:00:00Z', 'b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e',
              'ana@example.org', 'iOS 17.4', 'E621E1F8-C36C-495A-93FC-0C247A3E6E5F', '27', 'female', '58201934']
    messages, made = [], 0
    while made < total_fields:
        n = min(per_message, total_fields - made)
        messages.append([(rng.choice(keys).format(i=rng.randint(0, 50)), rng.choice(values)) for _ in range(n)])
        made += n
    return messages


def load_baseline(ref: str):
    source = subprocess.run(['git', 'show', f'{ref}:src/packet_pii/detect.py'], cwd=ROOT, check=True,
                            capture_output=True, text=True).stdout
    directory = Path(tempfile.mkdtemp())
    (directory / 'baseline_detect.py').write_text(source, encoding='utf-8')
    spec = importlib.util.spec_from_file_location('baseline_detect', directory / 'baseline_detect.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules['baseline_detect'] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module.detect_fields


def measure(detect, messages, repeat):
    best = float('inf')
    for _ in range(repeat):
        started = time.perf_counter()
        for fields in messages:
            detect(fields)
        best = min(best, time.perf_counter() - started)
    tracemalloc.start()
    for fields in messages:
        detect(fields)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return best, peak


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline-ref', default='main')
    parser.add_argument('--fields', type=int, default=200_000)
    parser.add_argument('--repeat', type=int, default=5)
    args = parser.parse_args(argv)
    from packet_pii.detect import detect_fields
    messages = synthetic_messages(args.fields)
    base_t, base_mem = measure(load_baseline(args.baseline_ref), messages, args.repeat)
    new_t, new_mem = measure(detect_fields, messages, args.repeat)
    print(f'fields={args.fields} messages={len(messages)} best_of={args.repeat}')
    print(f'baseline ({args.baseline_ref}): {base_t:.3f}s  peak={base_mem / 1e6:.2f}MB')
    print(f'current:            {new_t:.3f}s  peak={new_mem / 1e6:.2f}MB')
    print(f'relative overhead:  {100 * (new_t - base_t) / base_t:+.1f}%')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
