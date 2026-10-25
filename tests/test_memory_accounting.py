"""Guard regressions; mock only OS readings, exercise real scans/publication."""
import ctypes
import importlib
import sys
from pathlib import Path

import pytest

import packet_pii.engine as engine

MIB=2**20


def capture(tmp_path):
    import sys
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'examples'))
    from generate_demo import write_pcap
    p=tmp_path/'fixture.pcap';write_pcap(p);return p


def test_historical_peak_does_not_poison_later_small_scan(tmp_path,monkeypatch):
    monkeypatch.setattr(engine,'_peak_rss_bytes',lambda:2048*MIB)
    monkeypatch.setattr(engine,'_current_rss_bytes',lambda:40*MIB,raising=False)
    out=tmp_path/'report.json'
    receipt=engine.analyze_to_report(capture(tmp_path),out)
    assert receipt['summary']['packets_captured']==8 and out.is_file()


@pytest.mark.parametrize('current',[None,1200*MIB])
def test_unreadable_or_real_overbudget_rss_fails_atomically(tmp_path,monkeypatch,current):
    monkeypatch.setattr(engine,'_peak_rss_bytes',lambda:2048*MIB)
    monkeypatch.setattr(engine,'_current_rss_bytes',lambda:current,raising=False)
    out=tmp_path/'report.json';out.write_text('previous')
    with pytest.raises(engine.AnalysisLimitError,match='memory'):
        engine.analyze_to_report(capture(tmp_path),out,overwrite=True)
    assert out.read_text()=='previous'


def test_new_native_peak_above_limit_fails_even_if_current_recovered(monkeypatch):
    peaks=iter([100*MIB,1200*MIB])
    monkeypatch.setattr(engine,'_peak_rss_bytes',lambda:next(peaks))
    monkeypatch.setattr(engine,'_current_rss_bytes',lambda:40*MIB,raising=False)
    guard=engine._MemoryGuard(engine.AnalysisLimits())
    with pytest.raises(engine.AnalysisLimitError,match='memory'):guard.check('model')


def test_current_excess_not_hidden_by_inconsistent_low_peak(monkeypatch):
    monkeypatch.setattr(engine,'_peak_rss_bytes',lambda:100*MIB)
    monkeypatch.setattr(engine,'_current_rss_bytes',lambda:1200*MIB,raising=False)
    guard=engine._MemoryGuard(engine.AnalysisLimits())
    with pytest.raises(engine.AnalysisLimitError,match='memory'):guard.check('start')


def test_mach_reader_uses_native_layout_and_validates_result():
    memory=importlib.import_module('packet_pii.memory')
    def kernel(task,flavor,info,count):
        assert task==91 and flavor==20
        words=ctypes.cast(count,ctypes.POINTER(ctypes.c_uint32))
        assert words[0]==12
        target=ctypes.cast(info,ctypes.POINTER(memory._MachTaskBasicInfo)).contents
        # Different high virtual/peak values catch wrong-field or offset reads.
        target.virtual_size=8*2**40;target.resident_size=123456789;target.resident_size_max=987654321
        return 0
    assert memory._read_mach_rss(kernel,91)==123456789
    assert ctypes.sizeof(memory._MachTaskBasicInfo)==48
    assert memory._read_mach_rss(lambda *a:5,91) is None
    def short(task,flavor,info,count):
        ctypes.cast(count,ctypes.POINTER(ctypes.c_uint32))[0]=2;return 0
    assert memory._read_mach_rss(short,91) is None


def test_live_current_rss_matches_independent_process_reader():
    memory=importlib.import_module('packet_pii.memory')
    measured=memory.current_rss_bytes()
    if sys.platform.startswith('linux'):
        # /proc/self is valid even in runtimes whose getpid namespace differs
        # from procfs; psutil.Process(getpid()) would inspect another process.
        status=Path('/proc/self/status').read_text().splitlines()
        independent=int(next(x for x in status if x.startswith('VmRSS:')).split()[1])*1024
    else:
        psutil=pytest.importorskip('psutil')
        independent=psutil.Process().memory_info().rss
    assert measured is not None and measured>0
    assert abs(measured-independent)<max(8*MIB,independent*.1)


def test_guard_rejects_serialization_peak_before_atomic_publication(tmp_path):
    from packet_pii.reporting import write_private_report
    target=tmp_path/'report.json';target.write_text('previous')
    def reject():raise engine.AnalysisLimitError('memory at publication')
    with pytest.raises(engine.AnalysisLimitError,match='memory'):
        write_private_report({'safe':'data'},target,overwrite=True,before_publish=reject)
    assert target.read_text()=='previous'
    assert not list(tmp_path.glob('*.tmp'))


def test_in_memory_report_budget_traversal_cannot_escape_memory_guard(tmp_path, monkeypatch):
    state = {'peak': 100*MIB, 'current': 40*MIB}
    monkeypatch.setattr(engine, '_peak_rss_bytes', lambda: state['peak'])
    monkeypatch.setattr(engine, '_current_rss_bytes', lambda: state['current'])
    original = engine.json.JSONEncoder.iterencode
    def grow(self, value, *args, **kwargs):
        if isinstance(value, dict) and 'metadata' in value and 'summary' in value:
            state.update(peak=1200*MIB, current=1200*MIB)
        yield from original(self, value, *args, **kwargs)
    monkeypatch.setattr(engine.json.JSONEncoder, 'iterencode', grow)
    with pytest.raises(engine.AnalysisLimitError, match='memory'):
        engine.analyze(capture(tmp_path))
