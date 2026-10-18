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

@pytest.mark.parametrize('bad',[0,-1,True,1.5,'large'])
def test_invalid_resource_overrides_are_rejected(bad):
    with pytest.raises((ValueError,TypeError)):
        AnalysisLimits.for_profile('large',max_report_bytes=bad)


def test_capture_and_payload_exact_boundaries(tmp_path):
    from packet_pii.capture import read_frames,decode_tcp
    path=capture(tmp_path)
    packets=[decode_tcp(f) for f in read_frames(path)]
    total=sum(len(p.payload) for p in packets if p)
    limits=AnalysisLimits(max_capture_bytes=path.stat().st_size,max_packets=8,max_flows=1,
                          max_tcp_payload_bytes=total)
    assert analyze(path,limits=limits)['summary']['packets_captured']==8
    for field in ('max_capture_bytes','max_packets','max_tcp_payload_bytes'):
        with pytest.raises(ValueError):analyze(path,limits=replace(limits,**{field:getattr(limits,field)-1}))


def test_large_profile_reads_above_old_file_limit_without_allocating_it(tmp_path,monkeypatch):
    import packet_pii.capture as module
    path=capture(tmp_path);real=module.os.fstat
    class Stat:
        st_size=129*2**20
        st_mode=0o100600
    monkeypatch.setattr(module.os,'fstat',lambda fd:Stat())
    with pytest.raises(ValueError,match='file-size'):analyze(path)
    assert analyze(path,profile='large')['summary']['packets_captured']==8


@pytest.mark.parametrize('count,unique,field,expected',[(100001,False,'max_packets',1),(20001,True,'max_flows',20001)])
def test_large_profiles_cross_old_packet_and_flow_limits(tmp_path,monkeypatch,count,unique,field,expected):
    import packet_pii.engine as engine
    from packet_pii.capture import RawFrame,TcpPacket
    path=tmp_path/'tiny.pcap';path.write_bytes(b'not read by this mock')
    monkeypatch.setattr(engine,'read_frames',lambda *a,**k:(RawFrame(float(i),101,b'') for i in range(count)))
    monkeypatch.setattr(engine,'decode_tcp',lambda f:TcpPacket(f.timestamp,'192.0.2.1','198.51.100.1',
        1024+int(f.timestamp) if unique else 1234,80,100,16,b''))
    with pytest.raises(AnalysisLimitError):analyze(path)
    report=analyze(path,profile='large')
    assert report['summary']['packets_captured']==count
    assert report['summary']['flows_processed']==expected


def test_reporting_exact_byte_budget_and_failure_cleanup(tmp_path):
    from packet_pii.reporting import write_private_report,ReportLimitError
    path=tmp_path/'report.json';report={'unicode':'é'}
    write_private_report(report,path);size=path.stat().st_size
    write_private_report(report,path,overwrite=True,max_bytes=size)
    before=path.read_bytes()
    with pytest.raises(ReportLimitError):write_private_report(report,path,overwrite=True,max_bytes=size-1)
    assert path.read_bytes()==before
    assert not list(tmp_path.glob('*.tmp'))


def test_finding_limit_and_callback_cancellation_preserve_target(tmp_path):
    from packet_pii.engine import analyze_to_report
    path=capture(tmp_path);target=tmp_path/'out.json';target.write_text('old')
    with pytest.raises(AnalysisLimitError,match='findings'):
        analyze_to_report(path,target,overwrite=True,limits=AnalysisLimits(max_findings=6))
    def cancel(event):
        if event['stage']=='writing_report':raise RuntimeError('cancel')
    with pytest.raises(RuntimeError,match='cancel'):
        analyze_to_report(path,target,overwrite=True,progress=cancel)
    assert target.read_text()=='old'


def test_disk_failure_does_not_replace_report(tmp_path,monkeypatch):
    import packet_pii.reporting as reporting
    from packet_pii.engine import analyze_to_report
    path=capture(tmp_path);target=tmp_path/'report.json';target.write_text('old')
    def full(*a,**k):raise OSError('disk full')
    monkeypatch.setattr(reporting.os,'fsync',full)
    with pytest.raises(OSError):analyze_to_report(path,target,overwrite=True)
    assert target.read_text()=='old'
    assert not list(tmp_path.glob('.report.json.*.tmp'))


def test_streaming_unsafe_overlap_and_reused_tuple_are_not_false_evidence(tmp_path):
    import struct
    from generate_demo import tcp_frame
    from packet_pii.engine import analyze_to_report
    req=b'GET /?email=fake%40example.test HTTP/1.1\r\nHost: example.test\r\n\r\n'
    def frame(seq,data=b'',flags=0x18):return tcp_frame('192.0.2.1',1234,'198.51.100.1',80,seq,data,flags=flags)
    frames=[frame(100,flags=2),frame(101,req),frame(105,b'conflict'),
            frame(1000,flags=2),frame(1001,req)]
    path=tmp_path/'sessions.pcap'
    with path.open('wb') as out:
        out.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for f in frames:out.write(struct.pack('<IIII',1,0,len(f),len(f))+f)
    target=tmp_path/'report.json';analyze_to_report(path,target,profile='large')
    report=json.loads(target.read_text())
    assert report['summary']['endpoint_pairs']==1 and report['summary']['flows_processed']==2
    assert report['summary']['http_messages']==1 and report['summary']['analysis_incomplete']
    assert report['findings'][0]['flow_id'].endswith('session_0002')


def test_high_profile_preserves_record_and_decompression_limits(tmp_path):
    import struct,gzip
    from generate_demo import tcp_frame
    from packet_pii.http_extract import MAX_HTTP_BODY
    path=tmp_path/'bad.pcap';header=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
    path.write_bytes(header+struct.pack('<IIII',1,0,0xffffffff,0xffffffff))
    assert analyze(path,profile='stress')['summary']['capture_malformed_records']==1
    body=gzip.compress(b'x'*(MAX_HTTP_BODY+1),mtime=0)
    request=b'POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
    f=tcp_frame('192.0.2.1',1234,'198.51.100.1',80,100,request)
    path.write_bytes(header+struct.pack('<IIII',1,0,len(f),len(f))+f)
    assert analyze(path,profile='large')['summary']['potential_leaks']==0


def test_materialized_budget_includes_metadata_and_empty_collections(tmp_path):
    import struct
    path=tmp_path/'empty.pcap';path.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    with pytest.raises(AnalysisLimitError,match='report'):
        analyze(path,limits=AnalysisLimits(max_report_bytes=1))


def test_completion_notification_cannot_turn_published_success_into_failure(tmp_path):
    from packet_pii.engine import analyze_to_report
    path=capture(tmp_path);target=tmp_path/'report.json';target.write_text('old')
    def notify(event):
        if event['stage']=='complete':raise RuntimeError('observer failed')
    receipt=analyze_to_report(path,target,overwrite=True,progress=notify)
    assert receipt['progress_notification_failed'] is True
    assert json.loads(target.read_text())['summary']['potential_leaks']==7
