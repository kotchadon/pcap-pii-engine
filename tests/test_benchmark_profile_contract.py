"""The benchmark must not silently use Standard's 10,000-field limit when validating full Hybrid coverage."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'validation' / 'bench_performance_memory.py'


def _run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True,
                          text=True, timeout=15)


def test_benchmark_exposes_explicit_bounded_ml_profile():
    result = _run('--help')
    assert result.returncode == 0
    assert '--ml-profile' in result.stdout
    assert 'standard' in result.stdout and 'extended' in result.stdout


def test_benchmark_rejects_extended_profile_without_real_model(tmp_path):
    result = _run('--source-root', str(ROOT), '--capture', str(tmp_path / 'fictional.pcap'),
                  '--output', str(tmp_path / 'run.json'), '--ml-profile', 'extended')
    assert result.returncode != 0
    assert 'requires a genuine --checkpoint' in result.stderr
    assert not (tmp_path / 'run.json').exists()


def test_apple_acceptance_requires_genuine_complete_hybrid_not_only_scan_success():
    source = (ROOT / 'scripts' / 'validation' / 'accept_apple_silicon.py').read_text()
    assert "['--checkpoint', str(checkpoint), '--ml-profile', 'extended']" in source
    assert "summary.get('ml_coverage_status')!='complete'" in source
    assert "summary.get('ml_fields_skipped', 0)" in source
    assert "summary['analysis_incomplete']" in source
