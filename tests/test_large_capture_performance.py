"""Resource profiles and complete, private large-capture output contracts."""
from dataclasses import replace
import json
from pathlib import Path
import sys
import pytest
from packet_pii.engine import AnalysisLimits, AnalysisLimitError, analyze
from packet_pii.cli import main

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'examples'))
from generate_demo import write_pcap


def capture(tmp_path):
    path=tmp_path/'small.pcap';write_pcap(path);return path


def test_profiles_preserve_standard_and_overrides_are_explicit():
    standard=AnalysisLimits.for_profile('standard')
    assert standard.max_packets==100000 and standard.max_flows==20000
    assert standard.max_capture_bytes==128*2**20 and standard.max_tcp_payload_bytes==64*2**20
    large=AnalysisLimits.for_profile('large',max_packets=600000)
    assert large.max_packets==600000 and large.max_flows==100000
    assert AnalysisLimits.for_profile('stress').max_capture_bytes==512*2**20
    with pytest.raises(ValueError):AnalysisLimits.for_profile('unlimited')
    with pytest.raises(ValueError):AnalysisLimits(max_capture_bytes=2**40)


def test_streamed_report_matches_materialized_report_and_is_private(tmp_path):
    from packet_pii.engine import analyze_to_report
    path=capture(tmp_path);target=tmp_path/'report.json';events=[]
    expected=analyze(path)
    receipt=analyze_to_report(path,target,profile='large',progress=events.append)
    actual=json.loads(target.read_text())
    assert actual['findings']==expected['findings']
    assert actual['flows']==expected['flows']
    for k,v in expected['summary'].items():
        if k!='processing_time_seconds':assert actual['summary'][k]==v
    assert receipt['summary']==actual['summary']
    assert 'findings' not in receipt and receipt['output_bytes']==target.stat().st_size
    assert target.stat().st_mode & 0o777 == 0o600
    assert events[-1]['stage']=='complete'
    assert 'student@example.com' not in json.dumps(events)+target.read_text()
    assert not list(tmp_path.glob('.pcap-pii-*'))


def test_profile_cli_and_override_precedence(tmp_path):
    path=capture(tmp_path);target=tmp_path/'out.json'
    assert main([str(path),'--profile','large','--max-packets','7','-o',str(target)])==1
    assert not target.exists()
    assert main([str(path),'--profile','large','-o',str(target)])==0
    report=json.loads(target.read_text())
    assert report['metadata']['analysis_profile']=='large'
    assert report['metadata']['analysis_limits']['max_packets']==500000


def test_output_budget_failure_preserves_existing_report_and_input(tmp_path):
    from packet_pii.engine import analyze_to_report
    path=capture(tmp_path);before=path.read_bytes();target=tmp_path/'out.json';target.write_text('previous')
    with pytest.raises(AnalysisLimitError,match='report'):
        analyze_to_report(path,target,overwrite=True,limits=AnalysisLimits(max_report_bytes=128))
    assert target.read_text()=='previous' and path.read_bytes()==before
    assert not list(tmp_path.glob('.pcap-pii-*'))


def test_memory_budget_failure_is_clean(tmp_path,monkeypatch):
    import packet_pii.engine as engine
    path=capture(tmp_path);target=tmp_path/'out.json'
    monkeypatch.setattr(engine,'_peak_rss_bytes',lambda:10*2**30)
    with pytest.raises(AnalysisLimitError,match='memory'):
        engine.analyze_to_report(path,target)
    assert not target.exists()
