"""Benchmark regression gate and finding comparison (pure logic; no model or capture needed)."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bench_gate', ROOT / 'scripts' / 'ml' / 'bench_v2_inference.py')
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)
ARGS = SimpleNamespace(gate_rss_ratio=1.10, gate_rss_slack_mib=32.0, gate_wall_ratio=1.05)
SUMMARY = {'ml_fields_eligible': 10, 'ml_fields_evaluated': 10, 'ml_fields_skipped': 0, 'ml_coverage_status': 'complete'}
SAME = {'identical_except_confidence': True, 'baseline_only_keys': [], 'max_abs_model_confidence_difference': 1e-6}


def run(wall=10.0, rss=600.0, summary=SUMMARY, cmp=SAME, failed=False):
    if failed:
        return {'failed': True, 'error_tail': 'AnalysisLimitError: Analysis exceeded configured process memory budget'}
    return {'wall_seconds': wall, 'model_seconds': wall / 2, 'peak_rss_mib': rss, 'summary': dict(summary),
            'comparison_vs_baseline': cmp}


def gate(**candidate):
    return bench.evaluate_gate({'runs': {'baseline': run(cmp=None), 'cand': run(**candidate)}}, ARGS)


def test_gate_passes_a_faster_equivalent_candidate():
    assert gate(wall=5.0, rss=620.0)['pass']


def test_failed_candidate_fails_and_is_never_a_speedup():
    result = gate(failed=True)
    assert not result['pass'] and result['runs']['cand']['checks'] == {'candidate_completed': False}
    scans = {'capture': {'mib': 2, 'sha256': '0' * 64, 'seed': 52}, 'analysis_profile': 'standard',
             'runs': {'baseline': run(cmp=None), 'cand': run(failed=True)}}
    md = bench.markdown_summary({'label': 'x', 'machine': {'platform': 'p', 'machine': 'm', 'cpu_count': 4, 'python': '3',
                                 'torch': 't', 'threads': 4}, 'baseline': {'ref': 'r', 'commit': 'c' * 40},
                                 'candidate': {'commit': 'd' * 40, 'dirty': False}, 'full_scan': scans})
    assert '| cand | FAILED: AnalysisLimitError' in md and 'cand | completed' not in md


def test_memory_wall_and_coverage_bounds():
    assert not gate(rss=600 * 1.10 + 33)['pass']             # just over the RSS bound
    assert gate(rss=600 * 1.10 + 31)['pass']
    assert not gate(wall=10.6)['pass']
    assert not gate(summary={**SUMMARY, 'ml_fields_skipped': 1})['pass']
    assert not gate(cmp={**SAME, 'identical_except_confidence': False})['pass']
    assert not gate(cmp={**SAME, 'max_abs_model_confidence_difference': 2e-5})['pass']
    assert not gate(cmp={**SAME, 'baseline_only_keys': ['value']})['pass']


def test_missing_or_failed_baseline_fails_the_gate():
    result = bench.evaluate_gate({'runs': {'baseline': run(failed=True), 'cand': run()}}, ARGS)
    assert not result['pass'] and result['runs']['cand']['checks'] == {'baseline_completed': False}
    assert not bench.evaluate_gate({'runs': {'baseline': run(cmp=None)}}, ARGS)['pass']   # nothing evaluated


def test_compare_findings_is_schema_additive_but_strict_on_baseline_fields():
    old = [{'detector': 'bilstm', 'pii_type': 'PERSON_NAME', 'location': 'a', 'confidence': 0.5},
           {'detector': 'rule', 'pii_type': 'EMAIL', 'location': 'b', 'confidence': 0.98}]
    new = [dict(old[0], confidence=0.5000001, evidence={'x': 1}), dict(old[1], evidence={'y': 2})]
    cmp = bench.compare_findings(old, new)
    assert cmp['identical_except_confidence'] and cmp['candidate_only_keys'] == ['evidence'] and cmp['baseline_only_keys'] == []
    assert abs(cmp['max_abs_model_confidence_difference'] - 1e-7) < 1e-12
    changed = [dict(new[0], location='z'), new[1]]
    assert not bench.compare_findings(old, changed)['identical_except_confidence']
    assert bench.compare_findings(old, [new[0]])['identical_except_confidence'] is False
    assert json.dumps(cmp)
