#!/usr/bin/env python3
"""Measure streamed coverage with real V2 or an explicitly labelled contract stub.

Run each invocation in a fresh process. Stub timing is NOT BiLSTM performance.
Private reports stay local; stdout contains only aggregate measurements.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import platform
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'src'))
from packet_pii.engine import analyze_to_report, _peak_rss_bytes
from packet_pii.hybrid import MLWorkBudget, load_experimental_bilstm


class ContractOnlyDetector:
    model_version = 'contract-only-empty-detector-NOT-BiLSTM'

    def predict_fields(self, fields):
        return []


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture', type=Path)
    p.add_argument('report', type=Path)
    selection = p.add_mutually_exclusive_group(required=True)
    selection.add_argument('--ml-checkpoint')
    selection.add_argument('--contract-detector', action='store_true')
    p.add_argument('--profile', choices=('standard', 'large', 'stress'), default='standard')
    p.add_argument('--ml-budget-profile', choices=('standard', 'extended'), default='standard')
    a = p.parse_args()
    # Missing checkpoint raises: no automatic stub or rules fallback.
    detector = ContractOnlyDetector() if a.contract_detector else load_experimental_bilstm(a.ml_checkpoint)
    budget = MLWorkBudget.for_profile(a.ml_budget_profile)
    digest = hashlib.sha256()
    with a.capture.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            digest.update(block)
    started = time.perf_counter()
    receipt = analyze_to_report(a.capture, a.report, ml_detector=detector,
                                ml_work_budget=budget, profile=a.profile)
    elapsed, peak = time.perf_counter()-started, _peak_rss_bytes()
    s = receipt['summary']
    assert s['fields_extracted'] == s['ml_fields_excluded_by_policy']+s['ml_fields_empty']+s['ml_fields_eligible']
    assert s['ml_fields_eligible'] == s['ml_fields_evaluated']+s['ml_fields_skipped']
    print(json.dumps(dict(platform=platform.platform(), python=platform.python_version(),
        measurement='contract stub; NOT model performance' if a.contract_detector else 'authentic checkpoint inference',
        model_version=detector.model_version, capture_bytes=a.capture.stat().st_size,
        capture_sha256=digest.hexdigest(), budget=asdict(budget), profile=a.profile,
        report_bytes=receipt['output_bytes'], full_scan_seconds=elapsed, peak_rss_mib=peak/2**20,
        coverage=s['ml_fields_evaluated']/s['ml_fields_eligible'] if s['ml_fields_eligible'] else None,
        summary=s), indent=2))


if __name__ == '__main__':
    main()
