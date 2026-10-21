"""Analysis-attributable process-memory guard (engine._MemoryGuard).

The previous guard compared the process-lifetime ``ru_maxrss`` with the budget, so any earlier transient peak (model
loading, a previous scan in the same dashboard process, an inherited value after fork+exec on Linux) failed every later
analysis immediately. These tests pin the new rule and that it is never weaker when the analysis starts within budget.
"""
import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import packet_pii.engine as engine
from packet_pii.engine import AnalysisLimitError, AnalysisLimits, analyze, analyze_to_report

ROOT = Path(__file__).resolve().parents[1]
GIB = 2 ** 30


def demo(tmp_path):
    spec = importlib.util.spec_from_file_location('demo_guard', ROOT / 'examples' / 'generate_demo.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    path = tmp_path / 'demo.pcap'
    mod.write_pcap(path)
    return path


def rss(monkeypatch, peak, current):
    """``peak`` may be a callable to model a peak that rises during the analysis."""
    monkeypatch.setattr(engine, '_peak_rss_bytes', peak if callable(peak) else (lambda: peak))
    monkeypatch.setattr(engine, '_current_rss_bytes', current if callable(current) else (lambda: current))


def test_earlier_peak_with_low_current_rss_no_longer_fails_the_analysis(tmp_path, monkeypatch):
    rss(monkeypatch, 2 * GIB, 300 * 2 ** 20)                      # Standard budget is 1 GiB
    assert analyze(demo(tmp_path))['summary']['potential_leaks'] == 7
    target = tmp_path / 'out.json'
    analyze_to_report(demo(tmp_path), target)
    assert target.exists()


def test_peak_raised_by_this_analysis_still_fails_exactly_like_before(tmp_path, monkeypatch):
    calls = {'n': 0}

    def rising():
        calls['n'] += 1
        return 500 * 2 ** 20 if calls['n'] == 1 else 2 * GIB      # within budget at start, over budget afterwards
    rss(monkeypatch, rising, 100 * 2 ** 20)                       # current RSS is irrelevant once the peak rose
    with pytest.raises(AnalysisLimitError, match='process peak reached during this analysis 2048 MiB > 1024 MiB'):
        analyze(demo(tmp_path))


def test_over_budget_current_rss_fails_even_when_the_peak_predates_the_analysis(tmp_path, monkeypatch):
    rss(monkeypatch, 3 * GIB, int(1.5 * GIB))
    target = tmp_path / 'out.json'
    with pytest.raises(AnalysisLimitError, match=r'current process RSS 1536 MiB > 1024 MiB during start'):
        analyze_to_report(demo(tmp_path), target)
    assert not target.exists() and not list(tmp_path.glob('.pcap-pii-*'))


def test_unreadable_current_rss_fails_closed(tmp_path, monkeypatch):
    rss(monkeypatch, 2 * GIB, None)
    with pytest.raises(AnalysisLimitError, match='current RSS unavailable'):
        analyze(demo(tmp_path))


def test_large_profile_budget_is_respected(tmp_path, monkeypatch):
    rss(monkeypatch, 2 * GIB, 2 * GIB)                            # over Standard, under Large (3 GiB)
    with pytest.raises(AnalysisLimitError):
        analyze(demo(tmp_path))
    assert analyze(demo(tmp_path), profile='large')['summary']['potential_leaks'] == 7


def test_guardless_check_keeps_the_strict_lifetime_rule(monkeypatch):
    rss(monkeypatch, 2 * GIB, 100 * 2 ** 20)
    with pytest.raises(AnalysisLimitError):
        engine._check_memory(AnalysisLimits())


def test_diagnostics_contain_numbers_and_stage_only(tmp_path, monkeypatch):
    rss(monkeypatch, 3 * GIB, int(1.5 * GIB))
    with pytest.raises(AnalysisLimitError) as info:
        analyze(demo(tmp_path))
    message = str(info.value)
    assert 'demo' not in message and str(tmp_path) not in message and '@' not in message


def test_current_rss_reading_is_plausible():
    current = engine._current_rss_bytes()
    if current is None:
        pytest.skip('no current-RSS source on this platform; the guard fails closed here')
    assert 10 * 2 ** 20 < current <= engine._peak_rss_bytes() + 64 * 2 ** 20


def test_real_transient_spike_no_longer_blocks_later_standard_scans(tmp_path):
    """Reproduces the reported failure mode in a fresh process: a freed 1.2 GiB allocation used to fail every later scan."""
    if engine._current_rss_bytes() is None:
        pytest.skip('no current-RSS source on this platform; the guard fails closed here')
    script = textwrap.dedent(f'''
        import sys; sys.path.insert(0, {str(ROOT / 'src')!r})
        import importlib.util, pathlib
        from packet_pii import engine
        spec = importlib.util.spec_from_file_location('d', {str(ROOT / 'examples' / 'generate_demo.py')!r})
        d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
        p = pathlib.Path({str(tmp_path)!r}) / 'demo.pcap'; d.write_pcap(p)
        blob = bytearray(1200 * 2 ** 20)
        for i in range(0, len(blob), 4096): blob[i] = 1
        del blob
        try:
            engine._check_memory(engine.AnalysisLimits()); strict = 'passed'
        except engine.AnalysisLimitError:
            strict = 'failed'
        print(strict, engine.analyze(p)['summary']['potential_leaks'])
    ''')
    out = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr[-500:]
    assert out.stdout.split() == ['failed', '7']  # the old lifetime rule would refuse; the analysis now completes
