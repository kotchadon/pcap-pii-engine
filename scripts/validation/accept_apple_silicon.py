#!/usr/bin/env python3
"""Native Apple Silicon acceptance. Missing dependencies/weights are failures.

Run from an installed checkout: python scripts/validation/accept_apple_silicon.py
Requires pytest, psutil and torch. No installs, downloads or private captures.
Produces a private local artifact directory. This is a correctness/resource
gate, not proof of a 1 GiB latency target or of all possible M3 workloads.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-m3', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    os.chdir(root)
    if sys.platform != 'darwin' or platform.machine() != 'arm64':
        raise SystemExit('BLOCKED: native arm64 macOS required')
    chip = subprocess.check_output(['sysctl', '-n', 'machdep.cpu.brand_string'], text=True).strip()
    if args.require_m3 and 'Apple M3' not in chip:
        raise SystemExit('BLOCKED: exact M3 requested; found ' + chip)
    import psutil
    import torch
    sys.path.insert(0, str(root / 'src'))
    from packet_pii.memory import current_rss_bytes, peak_rss_bytes
    measured = current_rss_bytes()
    independent = psutil.Process().memory_info().rss
    if measured is None or measured <= 0 or abs(measured-independent) > max(8*2**20, independent*.1):
        raise SystemExit('FAIL: Mach current RSS disagrees with independent native reader')
    checkpoint = root / 'src/packet_pii/ml/artifacts/bilstm_v2'
    ensemble = json.loads((checkpoint / 'ensemble.json').read_text())
    if ensemble['model_version'] != 'bilstm-v2-d1f9e9fb9a2b' or ensemble['min_score'] != .35:
        raise SystemExit('FAIL: frozen V2 identity/threshold changed')
    if len(ensemble['members']) != 3:
        raise SystemExit('FAIL: frozen V2 member count changed')
    for member in ensemble['members']:
        weights = checkpoint / member['dir'] / 'model.pt'
        if not weights.is_file() or hashlib.sha256(weights.read_bytes()).hexdigest() != member['model_sha256']:
            raise SystemExit('BLOCKED: missing or invalid frozen V2 weights: ' + str(weights))
    output = Path(tempfile.mkdtemp(prefix='trace-apple-acceptance-'))
    output.chmod(0o700)
    env = {**os.environ, 'PYTHONPATH': str(root / 'src'), 'OMP_NUM_THREADS': '2', 'MKL_NUM_THREADS': '2'}
    tests = ['tests/test_memory_accounting.py', 'tests/test_ml_memory_control.py',
             'tests/test_ml_tensor_memory.py', 'tests/test_ml_inference_acceleration.py',
             'tests/test_http_investigation.py', 'tests/test_reporting_security.py']
    subprocess.run([sys.executable, '-m', 'pytest', '-q', *tests, '--junitxml='+str(output/'tests.xml')],
                   env=env, check=True)
    import xml.etree.ElementTree as ET
    cases = ET.parse(output/'tests.xml').findall('.//testcase')
    if not cases or any(case.find('skipped') is not None for case in cases):
        raise SystemExit('BLOCKED: required native acceptance tests skipped')
    bench = root/'scripts/validation/bench_performance_memory.py'
    for name, options in [('rules', []), ('hybrid-cache', ['--checkpoint', str(checkpoint)]),
                          ('hybrid-no-cache', ['--checkpoint', str(checkpoint), '--no-cache'])]:
        destination = output/(name+'.json')
        subprocess.run([sys.executable, str(bench), '--source-root', str(root), '--capture',
                        str(output/'fictional2.pcap'), '--output', str(destination), '--repeat', '2', *options],
                       env=env, check=True)
        result = json.loads(destination.read_text())
        for run in result['runs']:
            if run['status'] != 'completed' or run['summary']['analysis_incomplete']:
                raise SystemExit('FAIL: scan failed or partial: '+name)
            if run['current_rss_after_analysis'] > result['memory_budget_bytes']:
                raise SystemExit('FAIL: Standard RSS budget exceeded: '+name)
        if len(result['runs']) != 2:
            raise SystemExit('FAIL: repeated scan did not complete: '+name)
    history = output/'history.json'
    subprocess.run([sys.executable, str(bench), '--source-root', str(root), '--capture',
                    str(output/'fictional2.pcap'), '--output', str(history), '--historical-peak'], env=env, check=True)
    if json.loads(history.read_text())['runs'][0]['status'] != 'completed':
        raise SystemExit('FAIL: historical peak poisoned later scan')
    (output/'platform.json').write_text(json.dumps({'platform': platform.platform(), 'chip': chip,
        'memory_bytes': psutil.virtual_memory().total, 'torch': torch.__version__,
        'rss': measured, 'independent_rss': independent, 'peak': peak_rss_bytes(),
        'mps_evaluated': False, 'coverage': '2 MiB fictional capture; full observed coverage required'}, indent=2))
    print('PASS: scoped native acceptance; artifacts: '+str(output))


if __name__ == '__main__':
    main()
