#!/usr/bin/env python3
"""V2 inference acceleration benchmark and original-versus-optimised output comparison.

The baseline is the *original source tree* of ``--baseline-ref`` (default ``origin/main``) exported with ``git archive``;
the candidate is this working tree. Every configuration runs in its own subprocess with a fixed thread count, so timing
and peak RSS are not contaminated by earlier runs. No checkpoint, threshold, dataset or committed result is modified.

  model-only : the same fixed (location, text) pairs through ``SpanPredictor.predict_pairs`` (baseline batch 64 vs.
               candidate batch 64/128/256/512): time, throughput, peak RSS, exact span/label/threshold comparison and
               floating-point score differences.
  full scan  : a deterministic synthetic capture through ``analyze()`` (baseline vs. candidate without cache vs.
               candidate with the prediction cache): wall time, model time, peak RSS, coverage/skip counters, findings
               comparison.

Usage:
  python scripts/ml/bench_v2_inference.py --out results.json [--threads 4] [--scan-mib 2] [--repeat 3]
  python scripts/ml/bench_v2_inference.py --out stress.json --skip-model --scan-mib 52
Inputs are fictional. Results are hardware-specific; record the machine with the numbers.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import random
import resource
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
V2_DIR = ROOT / 'src' / 'packet_pii' / 'ml' / 'artifacts' / 'bilstm_v2'
FROZEN_INPUTS = [ROOT / 'src/packet_pii/ml/datasets/v2/val.jsonl.gz', ROOT / 'src/packet_pii/ml/datasets/challenge_v1.jsonl.gz']
BATCH_SIZES = (64, 128, 256, 512)
NEAR_THRESHOLD = 1e-4


# ------------------------------------------------------------------ fixed inputs (never derived from model output)
FIRST = ['Ana', 'Wei', 'Priya', 'Lucas', 'Fatima', 'Olivia', 'Mary-Jane', 'Siobhán', 'Zoë', 'José', 'Aiko', 'Noah', 'Chen',
         'Amara', 'Liam', 'Sofia', 'Omar', 'Ingrid', 'Kofi', 'Mei']
LAST = ['Garcia', 'Chen', 'Patel', 'Silva', 'Khan', "O'Connor", 'Ångström', 'Watson-Parker', 'Nakamura', 'Okafor', 'Müller',
        'Rossi', 'Dubois', 'Kowalski', 'Haddad', 'Lindqvist']
WORDS = ['order', 'delivery', 'was', 'late', 'thanks', 'please', 'call', 'tomorrow', 'refund', 'blue', 'size', 'parcel',
         'invoice', 'support', 'ticket', 'update', 'address', 'changed', 'today', 'ok']


def synthetic_pairs(n: int, seed: int = 20251021) -> list[tuple[str, str]]:
    """HTTP-body-like fields: names, usernames, free text, Unicode, hyphenation, malformed bytes, long chunked text."""
    r = random.Random(seed)
    out = []
    for i in range(n):
        name = f'{r.choice(FIRST)} {r.choice(LAST)}'
        k = r.random()
        if k < .2:
            out.append(('json_body.user.full_name', name))
        elif k < .3:
            out.append(('json_body.username', f'{r.choice(FIRST).lower()}_{r.randint(1, 999)}'))
        elif k < .55:
            words = [r.choice(WORDS) for _ in range(r.randint(4, 40))]
            words.insert(r.randint(0, len(words)), name)
            out.append(('json_body.comment', ' '.join(words)))
        elif k < .7:
            out.append((f'json_body.items[{r.randint(0, 9)}].name', f'Item {r.randint(1, 500)} {r.choice(WORDS)}'))
        elif k < .78:
            out.append(('query_parameter.q', f'{name} {r.randint(1, 99)}'))
        elif k < .84:
            out.append(('json_body.note', ' '.join(f'{r.choice(WORDS)} {r.choice(FIRST)}' for _ in range(r.randint(120, 400)))))
        elif k < .9:
            out.append(('json_body.blob', f'{r.choice(FIRST)}�{r.randint(0, 9)}� {r.choice(WORDS)}'))
        else:
            out.append(('json_body.full_name', name))  # deliberately frequent repeats
    return out


def frozen_pairs() -> list[tuple[str, str]]:
    pairs = []
    for path in FROZEN_INPUTS:
        with gzip.open(path, 'rt', encoding='utf-8') as fh:
            pairs.extend((row['location'], row['text']) for row in map(json.loads, fh))
    return pairs


# ------------------------------------------------------------------ deterministic synthetic capture
def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def _frame(src: bytes, dst: bytes, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b'') -> bytes:
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff, 0x50, flags, 65535, 0, 0) + payload
    tcp = tcp[:16] + struct.pack('!H', _checksum(src + dst + struct.pack('!BBH', 0, 6, len(tcp)) + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', _checksum(ip)) + ip[12:]
    return bytes.fromhex('0200000000020200000000010800') + ip + tcp


def generate_capture(path: Path, target_mib: float, seed: int = 52) -> dict:
    """POST/JSON API traffic with a realistic mix of repeated (profile, catalogue) and unique (comments, notes) fields."""
    r = random.Random(seed)
    people = [f'{r.choice(FIRST)} {r.choice(LAST)}' for _ in range(400)]
    users = [f'{p.split()[0].lower()}_{r.randint(1, 9999)}' for p in people]
    items = [f'Item {i} {r.choice(WORDS)}' for i in range(200)]
    src, dst = bytes([192, 0, 2, 10]), bytes([198, 51, 100, 20])
    target, written, messages, packets = int(target_mib * 1024 * 1024), 24, 0, 0
    with path.open('wb') as out:
        out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))

        def emit(frame):
            nonlocal written, packets
            out.write(struct.pack('<IIII', 1_760_000_000 + packets // 1_000_000, packets % 1_000_000, len(frame), len(frame)))
            out.write(frame)
            written += 16 + len(frame)
            packets += 1
        while written < target:
            p = r.randrange(len(people))
            body = {'user': {'full_name': people[p], 'username': users[p], 'city': r.choice(['Lisbon', 'Osaka', 'Leeds'])},
                    'items': [{'name': r.choice(items), 'qty': r.randint(1, 5)} for _ in range(r.randint(1, 3))],
                    'comment': ' '.join([r.choice(WORDS) for _ in range(r.randint(3, 25))] + [r.choice(people)]),
                    'status': r.choice(['ok', 'pending', 'shipped']), 'order_id': str(r.randrange(10 ** 9))}
            if messages % 25 == 0:
                body['note'] = ' '.join(f'{r.choice(WORDS)} {r.choice(people)}' for _ in range(r.randint(60, 160)))
            raw = json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode()
            request = (b'POST /api/orders HTTP/1.1\r\nHost: shop.example.test\r\nContent-Type: application/json\r\n'
                       + f'Content-Length: {len(raw)}\r\n\r\n'.encode() + raw)
            response = b'HTTP/1.1 204 No Content\r\n\r\n'
            sport = 10000 + messages % 50000
            base = (messages * 7919) & 0x7fffffff
            emit(_frame(src, dst, sport, 80, base, 0, 0x02))
            emit(_frame(dst, src, 80, sport, 5000, base + 1, 0x12))
            for offset in range(0, len(request), 1400):
                emit(_frame(src, dst, sport, 80, base + 1 + offset, 5001, 0x18, request[offset:offset + 1400]))
            emit(_frame(dst, src, 80, sport, 5001, base + 1 + len(request), 0x18, response))
            emit(_frame(src, dst, sport, 80, base + 1 + len(request), 5001 + len(response), 0x11))
            emit(_frame(dst, src, 80, sport, 5001 + len(response), base + 2 + len(request), 0x11))
            messages += 1
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'path': str(path), 'bytes': written, 'mib': round(written / 2 ** 20, 2), 'packets': packets,
            'http_requests': messages, 'sha256': digest, 'seed': seed}


# ------------------------------------------------------------------ worker (one configuration per process)
def _getrusage_maxrss_mib() -> float:
    """``ru_maxrss`` - NOTE: on Linux it is inherited across fork+exec, so a child reports at least its parent's RSS at
    spawn time. The engine's own memory guard reads this value. Reported for transparency, not used as the peak."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(peak / (2 ** 20 if sys.platform == 'darwin' else 1024), 1)  # macOS reports bytes, Linux KiB


def _proc_status_mib(field: str) -> float | None:
    try:
        with open('/proc/self/status') as fh:
            for line in fh:
                if line.startswith(field + ':'):
                    return round(int(line.split()[1]) / 1024, 1)
    except OSError:
        return None
    return None


def _rss_mib() -> float | None:
    value = _proc_status_mib('VmRSS')
    if value is None and sys.platform == 'darwin':  # no /proc on macOS
        try:
            out = subprocess.run(['ps', '-o', 'rss=', '-p', str(os.getpid())], capture_output=True, text=True).stdout
            value = round(int(out.strip()) / 1024, 1)
        except (OSError, ValueError):
            return None
    return value


def _peak_rss_mib() -> float:
    """This process's own peak: Linux ``VmHWM`` (reset by exec, exact); elsewhere ``ru_maxrss``."""
    hwm = _proc_status_mib('VmHWM')
    return hwm if hwm is not None else _getrusage_maxrss_mib()


class _MallInfo2:
    """glibc ``mallinfo2`` (all arenas). ``uordblks`` = bytes in live allocations, ``fordblks`` = free bytes the allocator
    still holds (fragmentation / not yet returned), ``hblkhd`` = live mmapped blocks. Unavailable (None) off glibc."""
    _fn = None

    @classmethod
    def read(cls) -> dict | None:
        import ctypes
        if cls._fn is None:
            try:
                class MI2(ctypes.Structure):
                    _fields_ = [(n, ctypes.c_size_t) for n in ('arena', 'ordblks', 'smblks', 'hblks', 'hblkhd', 'usmblks',
                                                               'fsmblks', 'uordblks', 'fordblks', 'keepcost')]
                fn = ctypes.CDLL(None).mallinfo2
                fn.restype = MI2
                cls._fn = fn
            except (AttributeError, OSError):
                cls._fn = False
        if not cls._fn:
            return None
        m = cls._fn()
        mib = lambda v: round(v / 2 ** 20, 1)  # noqa: E731
        return {'live_heap_mib': mib(m.uordblks), 'live_mmap_mib': mib(m.hblkhd), 'free_held_mib': mib(m.fordblks),
                'arena_mib': mib(m.arena)}


class _Sampler:
    """Samples RSS every ``interval`` s and keeps the allocator/Python-object state observed at the RSS peak."""

    def __init__(self, interval: float = 0.5):
        import threading
        self.interval, self.peak = interval, {'rss_mib': 0.0}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self):
        while not self._stop.wait(self.interval):
            rss = _rss_mib() or 0.0
            if rss > self.peak['rss_mib']:
                self.peak = {'rss_mib': rss, 'malloc': _MallInfo2.read(), 'python_blocks': sys.getallocatedblocks()}

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()


def _cache_bytes(cache) -> int:
    if not cache:
        return 0
    total = sys.getsizeof(cache)
    for key, spans in cache.items():
        total += sys.getsizeof(key) + sys.getsizeof(spans)
        for span in spans:
            total += sys.getsizeof(span) + sys.getsizeof(span[3])  # tuple + score float; strings are shared constants
    return total


def worker(spec: dict) -> dict:
    sys.path.insert(0, spec['src'])
    import torch
    torch.set_num_threads(spec['threads'])
    if os.environ.get('TRACE_BENCH_DISABLE_MKLDNN') == '1':  # emulate builds without oneDNN (generic conv path)
        torch.backends.mkldnn.enabled = False
    if spec['kind'] == 'model':
        from packet_pii.ml.bilstm import load_predictor
        options = {} if spec['legacy_api'] else {'length_bucketing': spec['bucketing']}
        predictor, meta = load_predictor(str(V2_DIR), spec['batch_size'], **options)
        pairs = [tuple(p) for p in json.loads(Path(spec['pairs']).read_text(encoding='utf-8'))]
        rss_loaded, times, result = _rss_mib(), [], None
        predictor.predict_pairs(pairs[:64])  # warm-up
        for _ in range(spec['repeat']):
            started = time.perf_counter()
            result = predictor.predict_pairs(pairs)
            times.append(time.perf_counter() - started)
        Path(spec['out']).write_text(json.dumps(result), encoding='utf-8')
        return {'seconds_best': round(min(times), 3), 'seconds_all': [round(t, 3) for t in times],
                'fields_per_second': round(len(pairs) / min(times), 1), 'peak_rss_mib': _peak_rss_mib(),
                'rss_after_load_mib': rss_loaded, 'min_score': meta['min_score']}
    import gc
    from packet_pii import ml_runner
    from packet_pii.engine import analyze, analyze_to_report
    from packet_pii.ml.infer import BiLSTMDetector
    from packet_pii.ml_runner import MLWorkBudget
    if spec.get('cache_entries') is not None:  # candidate only: pin the cache configuration for this process
        ml_runner.PREDICTION_CACHE_ENABLED = spec['cache_entries'] > 0
        ml_runner.PREDICTION_CACHE_MAX_ENTRIES = max(1, spec['cache_entries'])
    runners = []
    if hasattr(ml_runner.MLBatchRunner, 'prediction_cache_enabled'):
        original_init = ml_runner.MLBatchRunner.__init__

        def spy(self, *a, **k):
            original_init(self, *a, **k)
            runners.append(self)
        ml_runner.MLBatchRunner.__init__ = spy
    detector = BiLSTMDetector(str(V2_DIR), **({'batch_size': spec['batch_size']} if spec.get('batch_size') else {}))
    if spec['mode'] == 'candidate_no_cache':
        inner = detector

        class NoCache:  # hides the cache opt-in; identical predictions
            model_version = inner.model_version

            def predict_fields(self, fields):
                return inner.predict_fields(fields)
        detector = NoCache()
    if spec.get('shared_detector') and hasattr(ml_runner, 'shared'):
        detector = ml_runner.shared(detector)  # the dashboard/job wrapper (PR #28 architecture)
    started = time.perf_counter()
    target = Path(spec['out']).with_suffix('.report.json')
    with _Sampler() as sampler:
        stage_times = {}
        if spec.get('report_to_disk'):  # full product path: disk-backed rows, evidence arrays, atomic JSON publication
            report = analyze_to_report(spec['pcap'], target, ml_detector=detector, ml_budget=MLWorkBudget(**spec['budget']),
                                       profile=spec.get('profile', 'standard'), timings=stage_times)
        else:
            report = analyze(spec['pcap'], ml_detector=detector, ml_budget=MLWorkBudget(**spec['budget']),
                             profile=spec.get('profile', 'standard'), timings=stage_times)
    wall = time.perf_counter() - started
    report_summary = report['summary']
    peak = _peak_rss_mib()  # scan peak, read before the benchmark's own findings serialisation inflates it
    runner = runners[-1] if runners else None
    cache = {} if runner is None else {
        'enabled': runner.prediction_cache_enabled, 'limit': runner._cache_limit, 'entries_at_end': len(runner._cache or ()),
        'hits': runner.cache_hits, 'model_inferred': runner.model_evaluations, 'evictions': runner.cache_evictions,
        'hit_rate': round(runner.cache_hits / max(1, runner.cache_hits + runner.model_evaluations), 4),
        'measured_cache_object_mib': round(_cache_bytes(runner._cache) / 2 ** 20, 2)}
    memory = {'peak_rss_mib_process_hwm': peak, 'getrusage_maxrss_mib_inherited': _getrusage_maxrss_mib(),
              'at_sampled_peak': sampler.peak,
              'after_scan_report_alive': {'rss_mib': _rss_mib(), 'malloc': _MallInfo2.read(), 'python_blocks': sys.getallocatedblocks()}}
    if spec.get('report_to_disk'):
        memory['report_bytes'] = target.stat().st_size
        findings_json = json.dumps(json.loads(target.read_text(encoding='utf-8'))['findings'])
        target.unlink()
    else:
        findings_json = json.dumps(report['findings'])
    runners.clear()
    runner = None
    del report
    gc.collect()
    memory['after_release_and_gc'] = {'rss_mib': _rss_mib(), 'malloc': _MallInfo2.read(), 'python_blocks': sys.getallocatedblocks()}
    try:
        import ctypes
        ctypes.CDLL(None).malloc_trim(0)
        memory['after_malloc_trim'] = {'rss_mib': _rss_mib(), 'malloc': _MallInfo2.read()}
    except (AttributeError, OSError):
        pass
    Path(spec['out']).write_text(findings_json, encoding='utf-8')
    keys = ('fields_extracted', 'http_messages', 'rules_findings', 'ml_findings', 'ml_fields_eligible', 'ml_fields_evaluated',
            'ml_fields_skipped', 'ml_fields_skipped_by_reason', 'ml_fields_excluded_by_policy', 'ml_fields_empty',
            'ml_coverage_status', 'ml_coverage_ratio', 'ml_inference_batches', 'ml_processing_time_seconds',
            'ml_fields_model_inferred', 'ml_prediction_cache_hits', 'ml_prediction_cache_enabled', 'ml_predictions_by_label')
    summary = {k: report_summary.get(k) for k in keys}
    model = report_summary['ml_processing_time_seconds']
    return {'wall_seconds': round(wall, 2), 'model_seconds': round(model, 2), 'non_model_seconds': round(wall - model, 2),
            'peak_rss_mib': peak, 'memory': memory, 'cache': cache, 'env': spec.get('env') or {},
            'stage_seconds': {k: round(v, 3) for k, v in stage_times.items()}, 'summary': summary}


def run_worker(spec: dict) -> dict:
    env = {**os.environ, **(spec.get('env') or {})}
    proc = subprocess.run([sys.executable, __file__, '--worker', json.dumps(spec)], capture_output=True, text=True, env=env)
    if proc.returncode and spec.get('kind') == 'scan':
        return {'failed': True, 'error_tail': proc.stderr.strip().splitlines()[-1][:300] if proc.stderr.strip() else ''}
    if proc.returncode:
        raise SystemExit(f'worker failed ({spec.get("kind")}/{spec.get("mode", spec.get("batch_size"))}):\n{proc.stderr[-2000:]}')
    return json.loads(proc.stdout.strip().splitlines()[-1])


# ------------------------------------------------------------------ comparisons
def compare_predictions(old: list, new: list, threshold: float) -> dict:
    span_diff = inclusion_diff = scores = bitwise = near = 0
    max_diff = 0.0
    for a, b in zip(old, new, strict=True):
        if [x[:3] for x in a] != [x[:3] for x in b]:
            span_diff += 1
        if [x[:3] for x in a if x[3] >= threshold] != [x[:3] for x in b if x[3] >= threshold]:
            inclusion_diff += 1
        for x, y in zip(a, b):
            scores += 1
            bitwise += x[3] == y[3]
            max_diff = max(max_diff, abs(x[3] - y[3]))
            near += abs(x[3] - threshold) < NEAR_THRESHOLD or abs(y[3] - threshold) < NEAR_THRESHOLD
    return {'fields': len(old), 'fields_with_span_or_label_difference': span_diff,
            'fields_with_threshold_inclusion_difference': inclusion_diff, 'raw_spans_compared': scores,
            'scores_bitwise_identical': bitwise, 'max_abs_score_difference': max_diff,
            f'scores_within_{NEAR_THRESHOLD:g}_of_threshold': near, 'threshold': threshold}


def compare_findings(old: list, new: list) -> dict:
    """Compare findings in order. Keys the baseline does not emit at all (additive report schema, e.g. ``evidence``
    added after the baseline commit) are reported in ``candidate_only_keys`` and excluded from the identity check;
    every key the baseline does emit must match exactly, except model ``confidence`` (reported separately)."""
    old_keys = set().union(*(f.keys() for f in old)) if old else set()
    new_keys = set().union(*(f.keys() for f in new)) if new else set()
    extra = sorted(new_keys - old_keys)
    project = lambda rows: [{k: v for k, v in f.items() if k != 'confidence' and k in old_keys} for f in rows]  # noqa: E731
    diffs = [abs(a['confidence'] - b['confidence']) for a, b in zip(old, new) if a.get('detector') == 'bilstm']
    return {'findings': [len(old), len(new)], 'identical_except_confidence': project(old) == project(new),
            'candidate_only_keys': extra, 'baseline_only_keys': sorted(old_keys - new_keys),
            'rule_findings_identical': project([f for f in old if f.get('detector') != 'bilstm'])
                                       == project([f for f in new if f.get('detector') != 'bilstm']),
            'max_abs_model_confidence_difference': max(diffs, default=0.0)}


def export_baseline(ref: str, into: Path) -> Path:
    archive = subprocess.run(['git', 'archive', ref, 'src'], cwd=ROOT, check=True, capture_output=True).stdout
    tar_path = into / 'baseline.tar'
    tar_path.write_bytes(archive)
    with tarfile.open(tar_path) as tar:
        tar.extractall(into, filter='data')
    return into / 'src'


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--worker')
    ap.add_argument('--out', type=Path)
    ap.add_argument('--baseline-ref', default='origin/main')
    ap.add_argument('--threads', type=int, default=min(4, os.cpu_count() or 1))
    ap.add_argument('--repeat', type=int, default=3)
    ap.add_argument('--synthetic-fields', type=int, default=6000)
    ap.add_argument('--scan-mib', type=float, default=2.0)
    ap.add_argument('--scan-max-seconds', type=float, default=7200.0, help='ML time budget for the scans (7200 = ceiling)')
    ap.add_argument('--skip-model', action='store_true')
    ap.add_argument('--skip-scan', action='store_true')
    ap.add_argument('--scan-modes', default='baseline,candidate_no_cache,candidate_cache')
    ap.add_argument('--disable-mkldnn', action='store_true',
                    help='run every worker with torch.backends.mkldnn disabled (generic convolution path; label results)')
    ap.add_argument('--gate', action='store_true', help='evaluate the regression gate for every candidate scan run; '
                    'exit 1 if any criterion fails')
    ap.add_argument('--gate-rss-ratio', type=float, default=1.10)
    ap.add_argument('--gate-rss-slack-mib', type=float, default=32.0)
    ap.add_argument('--gate-wall-ratio', type=float, default=1.05)
    ap.add_argument('--summary-md', type=Path, help='also write a human-readable Markdown summary')
    ap.add_argument('--scan-profile', default='standard', help="analysis profile; use 'large' for ~52 MiB captures")
    ap.add_argument('--scan-report-to-disk', action='store_true', help='use analyze_to_report (disk-backed report)')
    ap.add_argument('--scan-shared-detector', action='store_true', help='wrap the detector with ml_runner.shared() if present')
    ap.add_argument('--scan-batch-size', type=int, default=None, help='candidate predictor batch size (default: library default)')
    ap.add_argument('--scan-batch-fields', type=int, default=None, help='MLWorkBudget.batch_fields for every scan (existing knob)')
    args = ap.parse_args(argv)
    if args.worker:
        print(json.dumps(worker(json.loads(args.worker))))
        return 0
    if args.disable_mkldnn:
        os.environ['TRACE_BENCH_DISABLE_MKLDNN'] = '1'  # inherited by every worker
    if not args.out:
        ap.error('--out is required')
    from importlib.metadata import PackageNotFoundError, version  # never import torch here: children inherit our RSS
    try:
        torch_version = version('torch')
    except PackageNotFoundError:
        torch_version = None
    work = Path(tempfile.mkdtemp(prefix='trace-bench-'))
    baseline_src = export_baseline(args.baseline_ref, work)
    commit = lambda ref: subprocess.run(['git', 'rev-parse', ref], cwd=ROOT, capture_output=True, text=True).stdout.strip()  # noqa: E731
    results = {'label': 'V2 inference acceleration benchmark (synthetic and frozen fictional inputs)',
               'machine': {'platform': platform.platform(), 'machine': platform.machine(), 'processor': platform.processor(),
                           'cpu_count': os.cpu_count(), 'python': platform.python_version(), 'torch': torch_version,
                           'threads': args.threads},
               'baseline': {'ref': args.baseline_ref, 'commit': commit(args.baseline_ref)},
               'candidate': {'commit': commit('HEAD'), 'dirty': bool(subprocess.run(['git', 'status', '--porcelain', 'src'], cwd=ROOT,
                                                                                      capture_output=True, text=True).stdout.strip())}}
    if not args.skip_model:
        results['model_only'] = {}
        for name, pairs in (('frozen_v2_val_and_challenge', frozen_pairs()), ('synthetic_http_fields', synthetic_pairs(args.synthetic_fields))):
            pairs_file = work / f'{name}.json'
            pairs_file.write_text(json.dumps(pairs, ensure_ascii=False), encoding='utf-8')
            base = dict(kind='model', threads=args.threads, pairs=str(pairs_file), repeat=args.repeat)
            ref = run_worker({**base, 'src': str(baseline_src), 'legacy_api': True, 'batch_size': 64, 'out': str(work / f'{name}.base.json')})
            old = json.loads((work / f'{name}.base.json').read_text())
            section = {'inputs': len(pairs), 'unique_inputs': len(set(pairs)), 'baseline_batch_64': ref, 'candidate': {}}
            for bs in BATCH_SIZES:
                out = work / f'{name}.{bs}.json'
                res = run_worker({**base, 'src': str(ROOT / 'src'), 'legacy_api': False, 'bucketing': True, 'batch_size': bs, 'out': str(out)})
                res['speedup_vs_baseline'] = round(ref['seconds_best'] / res['seconds_best'], 2)
                res['comparison'] = compare_predictions(old, json.loads(out.read_text()), ref['min_score'])
                section['candidate'][f'batch_{bs}'] = res
                print(f'[model] {name} batch {bs}: x{res["speedup_vs_baseline"]} '
                      f'span_diffs={res["comparison"]["fields_with_span_or_label_difference"]} '
                      f'max|d|={res["comparison"]["max_abs_score_difference"]:.2g}', flush=True)
            results['model_only'][name] = section
    if not args.skip_scan:
        pcap = work / 'synthetic_scan.pcap'
        capture = generate_capture(pcap, args.scan_mib)
        budget = {'max_fields': 1_000_000, 'max_characters': 200_000_000, 'max_seconds': args.scan_max_seconds}
        if args.scan_batch_fields:
            budget['batch_fields'] = args.scan_batch_fields
        scans, findings = {'capture': capture, 'ml_budget': budget, 'analysis_profile': args.scan_profile,
                           'report_to_disk': args.scan_report_to_disk, 'shared_detector': args.scan_shared_detector, 'runs': {}}, {}
        for mode in args.scan_modes.split(','):
            # 'baseline' | 'candidate_no_cache' | 'candidate_cache' | 'cache=<entries>[@arena2]' (0 = cache disabled)
            src = baseline_src if mode == 'baseline' else ROOT / 'src'
            out = work / f'scan.{mode.replace("=", "_").replace("@", "_")}.json'
            entries, env = None, {}
            if mode.startswith('cache='):
                entries_text, _, variant = mode[6:].partition('@')
                entries = int(entries_text)
                if variant == 'arena2':
                    env = {'MALLOC_ARENA_MAX': '2'}
            res = run_worker({'kind': 'scan', 'mode': mode, 'src': str(src), 'threads': args.threads, 'pcap': str(pcap),
                              'budget': budget, 'out': str(out), 'profile': args.scan_profile, 'cache_entries': entries,
                              'env': env, 'batch_size': None if mode == 'baseline' else args.scan_batch_size,
                              'report_to_disk': args.scan_report_to_disk, 'shared_detector': args.scan_shared_detector})
            scans['runs'][mode] = res
            if res.get('failed'):
                print(f'[scan] {capture["mib"]} MiB {mode}: FAILED {res["error_tail"]}', flush=True)
                continue
            findings[mode] = out  # compared from disk afterwards: the parent never holds findings (children inherit RSS)
            print(f'[scan] {capture["mib"]} MiB {mode}: wall {res["wall_seconds"]}s model {res["model_seconds"]}s '
                  f'peak {res["peak_rss_mib"]} MiB', flush=True)
        if 'baseline' in findings:
            base = scans['runs']['baseline']
            for mode in findings:
                if mode != 'baseline':
                    run = scans['runs'][mode]
                    run['comparison_vs_baseline'] = compare_findings(json.loads(findings['baseline'].read_text()),
                                                                     json.loads(findings[mode].read_text()))
                    run['wall_speedup'] = round(base['wall_seconds'] / run['wall_seconds'], 2)
                    run['model_speedup'] = round(base['model_seconds'] / max(run['model_seconds'], 1e-9), 2)
        results['full_scan'] = scans
    results['convolution_path'] = 'generic (mkldnn disabled)' if args.disable_mkldnn else 'default'
    gate_ok = True
    if args.gate and 'full_scan' in results:
        results['gate'] = evaluate_gate(results['full_scan'], args)
        gate_ok = results['gate']['pass']
        print(f"[gate] {'PASS' if gate_ok else 'FAIL'}", json.dumps(results['gate']['runs']), flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    if args.summary_md:
        args.summary_md.write_text(markdown_summary(results), encoding='utf-8')
    print(f'wrote {args.out}')
    return 0 if gate_ok else 1


def evaluate_gate(scans: dict, args) -> dict:
    """Regression gate. Platform-dependent thresholds are explicit and recorded with the result.

    A candidate passes only if: the baseline and the candidate completed; findings are identical except model
    confidence (max |delta| <= 1e-5); eligible/evaluated/skipped ML coverage is identical; peak RSS (own process) <=
    baseline * rss_ratio + rss_slack; wall time <= baseline * wall_ratio. A failed run is never reported as a speed-up.
    """
    criteria = {'rss_ratio': args.gate_rss_ratio, 'rss_slack_mib': args.gate_rss_slack_mib, 'wall_ratio': args.gate_wall_ratio,
                'max_confidence_delta': 1e-5}
    runs, base = {}, scans['runs'].get('baseline')
    for mode, run in scans['runs'].items():
        if mode == 'baseline':
            continue
        checks = {}
        if not base or base.get('failed'):
            checks['baseline_completed'] = False
        elif run.get('failed'):
            checks['candidate_completed'] = False
        else:
            cmp, bs, cs = run.get('comparison_vs_baseline') or {}, base['summary'], run['summary']
            checks['candidate_completed'] = True
            checks['findings_identical_except_confidence'] = bool(cmp.get('identical_except_confidence'))
            checks['no_baseline_fields_missing'] = not cmp.get('baseline_only_keys')
            checks['confidence_delta_within_tolerance'] = cmp.get('max_abs_model_confidence_difference', 1) <= 1e-5
            checks['coverage_identical'] = all(bs.get(k) == cs.get(k) for k in ('ml_fields_eligible', 'ml_fields_evaluated',
                                                                                 'ml_fields_skipped', 'ml_coverage_status'))
            checks['peak_rss_within_bound'] = run['peak_rss_mib'] <= base['peak_rss_mib'] * args.gate_rss_ratio + args.gate_rss_slack_mib
            checks['wall_time_within_bound'] = run['wall_seconds'] <= base['wall_seconds'] * args.gate_wall_ratio
        runs[mode] = {'pass': all(checks.values()), 'checks': checks}
    return {'criteria': criteria, 'runs': runs, 'pass': bool(runs) and all(r['pass'] for r in runs.values())}


def markdown_summary(results: dict) -> str:
    m = results['machine']
    lines = [f"# {results['label']}", '',
             f"- Machine: {m['platform']} ({m['machine']}), {m['cpu_count']} CPUs, Python {m['python']}, torch {m['torch']}, "
             f"{m['threads']} threads; convolution path: {results.get('convolution_path')}",
             f"- Baseline: `{results['baseline']['ref']}` {results['baseline']['commit'][:12]}; candidate "
             f"{results['candidate']['commit'][:12]}{' (uncommitted changes)' if results['candidate']['dirty'] else ''}", '']
    for name, section in (results.get('model_only') or {}).items():
        b = section['baseline_batch_64']
        lines += [f"## Model only: {name} ({section['inputs']} inputs)", '',
                  '| Config | Seconds | Speed-up | Peak RSS MiB | Span diffs | Inclusion diffs | Max abs score delta |',
                  '|---|---|---|---|---|---|---|', f"| baseline batch 64 | {b['seconds_best']} | 1.00 | {b['peak_rss_mib']} | - | - | - |"]
        for cfg, r in section['candidate'].items():
            c = r['comparison']
            lines.append(f"| {cfg} | {r['seconds_best']} | {r['speedup_vs_baseline']} | {r['peak_rss_mib']} | "
                         f"{c['fields_with_span_or_label_difference']} | {c['fields_with_threshold_inclusion_difference']} | "
                         f"{c['max_abs_score_difference']:.2g} |")
        lines.append('')
    scans = results.get('full_scan')
    if scans:
        cap = scans['capture']
        lines += [f"## Full scan: {cap['mib']} MiB synthetic capture (sha256 {cap['sha256'][:16]}, seed {cap['seed']}), "
                  f"profile {scans['analysis_profile']}", '',
                  '| Run | Status | Wall s | Model s | Peak RSS MiB | Evaluated | Model-inferred | Cache hits | Findings identical | Wall x | Model x |',
                  '|---|---|---|---|---|---|---|---|---|---|---|']
        for mode, r in scans['runs'].items():
            if r.get('failed'):
                lines.append(f"| {mode} | FAILED: {r['error_tail']} | - | - | - | - | - | - | - | - | - |")
                continue
            s, cmp = r['summary'], r.get('comparison_vs_baseline') or {}
            lines.append(f"| {mode} | completed | {r['wall_seconds']} | {r['model_seconds']} | {r['peak_rss_mib']} | "
                         f"{s['ml_fields_evaluated']} | {s.get('ml_fields_model_inferred', '-')} | {s.get('ml_prediction_cache_hits', '-')} | "
                         f"{cmp.get('identical_except_confidence', '-')} | {r.get('wall_speedup', '-')} | {r.get('model_speedup', '-')} |")
        lines.append('')
    if 'gate' in results:
        g = results['gate']
        lines += [f"## Regression gate: {'PASS' if g['pass'] else 'FAIL'}", '', f"Criteria: `{json.dumps(g['criteria'])}`", '']
        for mode, r in g['runs'].items():
            failed = [k for k, v in r['checks'].items() if not v]
            lines.append(f"- {mode}: {'pass' if r['pass'] else 'FAIL (' + ', '.join(failed) + ')'}")
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    raise SystemExit(main())
