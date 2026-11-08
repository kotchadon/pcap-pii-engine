"""Real HTTP job lifecycle: bounded results, idempotency, security and cleanup."""
from contextlib import contextmanager
from http.client import HTTPConnection
import json
from pathlib import Path
import threading
import time
import pytest

from packet_pii.dashboard import DashboardServer


@contextmanager
def server(detector=None):
    s=DashboardServer(('127.0.0.1',0),ml_detector=detector)
    t=threading.Thread(target=s.serve_forever,daemon=True);t.start()
    try:yield s
    finally:s.shutdown();s.server_close();t.join(3)


def request(s,method,path,body=None,headers=None):
    c=HTTPConnection('127.0.0.1',s.server_port,timeout=20)
    c.request(method,path,body=body,headers=headers or {})
    r=c.getresponse();data=r.read();out=r.status,data,dict(r.getheaders());c.close();return out


def begin(s,request_id='test-request-0001',mode='rules',profile='standard'):
    return request(s,'POST','/api/jobs/showcase',headers={
        'X-Dashboard-Token':s.token,'X-Request-ID':request_id,
        'X-Detection-Mode':mode,'X-Analysis-Profile':profile})


def finish(s,job_id):
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        code,body,_=request(s,'GET','/api/jobs/'+job_id,headers={'X-Dashboard-Token':s.token})
        assert code==200
        data=json.loads(body)
        if data['status'] in ('completed','failed','cancelled'):return data
        time.sleep(.02)
    pytest.fail('Job did not reach terminal state')


def test_job_showcase_pages_download_and_repeat_requests():
    with server() as s:
        _,session,cookie=request(s,'GET','/api/session')
        assert json.loads(session)['jobs_supported'] is True
        code,body,_=begin(s);assert code==202
        job_id=json.loads(body)['job_id'];result=finish(s,job_id)
        assert result['status']=='completed'
        assert 'report_write' in result['report']['stage_timings_seconds']
        assert result['report']['stage_timings_seconds']['report_write'] >= 0
        assert result['report']['summary']['http_messages']==24
        assert result['report']['summary']['ml_invoked'] is False
        assert len(result['report']['findings'])<=100
        replay=json.loads(begin(s)[1]);assert replay['job_id']==job_id
        assert begin(s,profile='large')[0]==409
        auth={'X-Dashboard-Token':s.token}
        code,page,_=request(s,'GET',f'/api/jobs/{job_id}/findings?offset=1&limit=2',headers=auth)
        page=json.loads(page);assert code==200 and len(page['items'])==2 and page['offset']==1
        assert page['total']==result['pagination']['findings_total']
        code,raw,h=request(s,'GET',f'/api/jobs/{job_id}/report',headers={'Cookie':cookie['Set-Cookie'].split(';')[0]})
        report=json.loads(raw);assert code==200 and 'attachment' in h['Content-Disposition']
        assert len(report['findings'])==report['summary']['potential_leaks']
        assert 'fictional-demo-password' not in raw.decode()
        assert not s.jobs.get(job_id).capture.exists()
        assert s.jobs.get(job_id).report.stat().st_mode&0o777==0o600
        assert s.jobs.get(job_id).index.stat().st_mode&0o777==0o600
        for suffix in ('','/findings','/report'):
            assert request(s,'GET',f'/api/jobs/{job_id}{suffix}')[0]==403
        assert request(s,'GET',f'/api/jobs/{job_id}/report',headers={**auth,'Origin':'https://evil.test'})[0]==403
        assert request(s,'GET',f'/api/jobs/{job_id}/findings?limit=101',headers=auth)[0]==400
        assert request(s,'GET','/api/jobs/not-a-job',headers=auth)[0]==404



@pytest.mark.parametrize('reason,expect', [
    ('Analysis exceeded configured report byte budget','evidence/report limit'),
    ('Capture exceeds configured packet limit','packet limit'),
    ('Capture exceeds configured buffered TCP payload limit','Network payload exceeded'),
    ('Analysis exceeded configured process memory budget: x','process-memory limit'),
])
def test_failed_scan_explains_which_budget_was_reached_without_leaking_content(monkeypatch, reason, expect):
    from packet_pii.engine import AnalysisLimitError
    import packet_pii.jobs as jobs
    def reject(*args, **kwargs):
        raise AnalysisLimitError(reason + ' /private/client/password-SECRET')
    monkeypatch.setattr(jobs, 'analyze_to_report', reject)
    with server() as s:
        code, body, _ = begin(s, request_id='limit-repro-abcdef1234')
        assert code == 202
        done=finish(s,json.loads(body)['job_id'])
        assert done['status']=='failed'
        assert expect in done['error']
        assert done['reason_type']=='AnalysisLimitError'
        assert '/private/client' not in json.dumps(done)
        assert 'password-SECRET' not in json.dumps(done)
        assert not list(s.jobs.get(done['job_id']).directory.iterdir())



def test_missing_model_and_bad_request_are_not_success():
    with server() as s:
        assert begin(s,mode='hybrid')[0]==422
        assert begin(s,profile='unlimited')[0]==400
        assert request(s,'POST','/api/jobs/showcase',headers={'X-Dashboard-Token':s.token})[0]==400
        s.jobs.disk_quota=32*2**20
        assert begin(s)[0]==507


def test_single_active_scan_cancellation_and_failure_cleanup(monkeypatch):
    import packet_pii.jobs as jobs
    entered=threading.Event();release=threading.Event()
    original=jobs.analyze_to_report
    def blocked(*a,**kw):
        entered.set();assert release.wait(5)
        return original(*a,**kw)
    monkeypatch.setattr(jobs,'analyze_to_report',blocked)
    with server() as s:
        code,body,_=begin(s);assert code==202
        job_id=json.loads(body)['job_id'];assert entered.wait(2)
        assert begin(s,'second-request-0002')[0]==409
        assert request(s,'POST','/api/demo',headers={'X-Dashboard-Token':s.token})[0]==409
        assert request(s,'POST',f'/api/jobs/{job_id}/cancel',headers={'X-Dashboard-Token':s.token})[0]==200
        release.set();done=finish(s,job_id)
        assert done['status']=='cancelled' and 'report' not in done
        assert not list(s.jobs.get(job_id).directory.iterdir())


def test_failed_inference_is_not_zero_finding_success():
    class Broken:
        model_version='broken-test'
        def predict_fields(self,fields):raise RuntimeError('secret raw contents /private/path')
    with server(Broken()) as s:
        code,body,_=begin(s,mode='hybrid');assert code==202
        job_id=json.loads(body)['job_id'];done=finish(s,job_id)
        assert done['status']=='failed' and done['ml_inference_failed']
        assert 'secret raw' not in json.dumps(done) and '/private' not in json.dumps(done)
        assert 'report' not in done and not list(s.jobs.get(job_id).directory.iterdir())


def test_benchmark_is_versioned_offline_evaluation():
    with server() as s:
        code,body,_=request(s,'GET','/api/benchmark');d=json.loads(body)
        assert code==200 and d['available'] and d['dataset']['fields']==1058
        assert d['model_version']=='bilstm-v2-d1f9e9fb9a2b'
        assert .817<d['f1']<.819 and d['bootstrap_ci'][0]<d['f1']<d['bootstrap_ci'][1]


def test_response_loss_after_start_keeps_job_and_lock(monkeypatch):
    import socket
    from http.client import RemoteDisconnected
    import packet_pii.jobs as jobs
    from packet_pii.dashboard import DashboardHandler
    entered=threading.Event();release=threading.Event()
    original=jobs.analyze_to_report;reply=DashboardHandler._reply
    def blocked(*a,**kw):
        entered.set();assert release.wait(5)
        return original(*a,**kw)
    def disconnected(self,payload,status=200):
        if status==202 and 'job_id' in payload:raise socket.timeout('client left')
        return reply(self,payload,status)
    monkeypatch.setattr(jobs,'analyze_to_report',blocked)
    monkeypatch.setattr(DashboardHandler,'_reply',disconnected)
    with server() as s:
        try:
            with pytest.raises(RemoteDisconnected):begin(s)
            assert entered.wait(2)
            job_id=s.jobs.latest_id
            assert s.jobs.get(job_id).status=='running' and s.analysis_lock.locked()
            assert begin(s,'other-request-id')[0]==409
        finally:release.set()
        assert finish(s,job_id)['status']=='completed'


def test_cancel_interrupts_unfinished_upload():
    import socket
    with server() as s:
        conn=socket.create_connection(('127.0.0.1',s.server_port),timeout=2)
        headers=(f'POST /api/jobs HTTP/1.1\r\nHost: 127.0.0.1:{s.server_port}\r\n'
                 f'X-Dashboard-Token: {s.token}\r\nX-Request-ID: slow-upload-test\r\n'
                 'X-Capture-Name: test.pcap\r\nContent-Type: application/octet-stream\r\n'
                 'Content-Length: 100000\r\n\r\nx')
        conn.sendall(headers.encode())
        deadline=time.monotonic()+2
        while s.jobs.latest_id is None and time.monotonic()<deadline:time.sleep(.01)
        job_id=s.jobs.latest_id;assert job_id
        code,_,_=request(s,'POST',f'/api/jobs/{job_id}/cancel',headers={'X-Dashboard-Token':s.token})
        assert code==200
        result=finish(s,job_id);conn.close()
        assert result['status']=='cancelled' and not s.analysis_lock.locked()
        assert not list(s.jobs.get(job_id).directory.iterdir())


def test_expired_index_returns_clean_unavailable_and_non_ml_error_stays_distinct():
    with server() as s:
        job_id=json.loads(begin(s)[1])['job_id'];assert finish(s,job_id)['status']=='completed'
        s.jobs.get(job_id).index.unlink()
        status,body,_=request(s,'GET',f'/api/jobs/{job_id}/findings',headers={'X-Dashboard-Token':s.token})
        assert status==404 and str(s.jobs.root) not in body.decode()
    class NeverCalled:
        model_version='test-not-invoked'
        def predict_fields(self,fields):pytest.fail('Invalid capture must not invoke model')
    with server(NeverCalled()) as s:
        status,body,_=request(s,'POST','/api/jobs',body=b'x'*24,headers={
            'X-Dashboard-Token':s.token,'X-Request-ID':'malformed-capture',
            'X-Detection-Mode':'hybrid','X-Capture-Name':'bad.pcap','Content-Type':'application/octet-stream'})
        assert status==202
        result=finish(s,json.loads(body)['job_id'])
        assert result['status']=='failed' and result['ml_inference_failed'] is False


@pytest.mark.parametrize('bad_output',['version','score'])
def test_invalid_model_output_marks_inference_failure(bad_output):
    from packet_pii.ml import EntitySpan,EntityLabel,ScoreType
    class Invalid:
        model_version='invalid-test'
        def predict_fields(self,fields):
            return [EntitySpan(fields[0].field_index,EntityLabel.PERSON_NAME,0,1,
                'other-version' if bad_output=='version' else self.model_version,
                .9 if bad_output=='version' else None,
                ScoreType.UNCALIBRATED_MODEL_SCORE if bad_output=='version' else ScoreType.NONE)]
    with server(Invalid()) as s:
        job_id=json.loads(begin(s,mode='hybrid')[1])['job_id']
        result=finish(s,job_id)
        assert result['status']=='failed' and result['ml_inference_failed']


def test_worker_start_failure_releases_lock_and_cleans_files(monkeypatch):
    from packet_pii.jobs import JobManager
    manager=JobManager(threading.Lock())
    job,_=manager.reserve('worker-start-test',filename='test.pcap',source='jobs',size=24,mode='rules',profile='standard')
    job.capture.write_bytes(b'x'*24)
    def fail_start(self):raise RuntimeError('thread creation failed')
    monkeypatch.setattr(threading.Thread,'start',fail_start)
    try:
        with pytest.raises(RuntimeError,match='thread creation'):
            manager.start(job)
        manager.fail_upload(job)
        assert job.status=='failed' and not manager.analysis_lock.locked()
        assert not list(job.directory.iterdir())
    finally:manager.close()



def test_dense_report_streams_from_index_without_losing_ordinary_contract(monkeypatch):
    """Opt-in dense format stays complete and keeps the authenticated download."""
    import gzip
    import packet_pii.jobs as jobs
    from packet_pii.engine import AnalysisLimits, GIB
    ordinary = AnalysisLimits.for_profile('stress')
    dense = AnalysisLimits.for_profile('dense')
    assert ordinary.max_report_bytes == 2*GIB
    assert dense.max_report_bytes == 6*GIB
    assert dense.max_memory_bytes == ordinary.max_memory_bytes
    assert dense.max_capture_bytes == ordinary.max_capture_bytes
    # Simulate sufficient free disk for a small fixture; large Mac acceptance
    # must still establish real disk availability and peak RSS separately.
    free_disk = 40*GIB
    real_disk_usage = jobs.shutil.disk_usage
    def available(directory):
        original = real_disk_usage(directory)
        return type(original)(original.total, original.used, free_disk)
    monkeypatch.setattr(jobs.shutil, 'disk_usage', available)
    with server() as s:
        code, session, cookie = request(s, 'GET', '/api/session')
        assert code == 200
        assert json.loads(session)['profiles']['dense']['max_report_bytes'] == 6*GIB
        normal_id = json.loads(begin(s,request_id='normal-report-1234',profile='standard')[1])['job_id']
        normal_result = finish(s,normal_id)
        assert normal_result['status'] == 'completed'
        normal = s.jobs.get(normal_id)
        assert normal.report.name == 'report.json'
        with normal.report.open('rb') as stream:
            ordinary_report = json.load(stream)
        code, body, _ = begin(s,request_id='dense-report-123456',profile='dense')
        assert code == 202
        dense_id = json.loads(body)['job_id']
        dense_result = finish(s,dense_id)
        assert dense_result['status'] == 'completed', dense_result.get('error')
        dense_job = s.jobs.get(dense_id)
        assert dense_job.report.name == 'report.json.gz'
        assert dense_job.report.is_file()
        with gzip.open(dense_job.report,'rt',encoding='utf-8') as stream:
            dense_report = json.load(stream)
        assert dense_report['summary']['potential_leaks'] == ordinary_report['summary']['potential_leaks']
        assert dense_report['field_evidence'] == ordinary_report['field_evidence']
        assert dense_report['http_evidence'] == ordinary_report['http_evidence']
        assert dense_report['findings'] == ordinary_report['findings']
        cookie_header = {'Cookie': cookie['Set-Cookie'].split(';')[0]}
        code, raw, headers = request(s,'GET',f'/api/jobs/{dense_id}/report',headers=cookie_header)
        assert code == 200
        assert headers['Content-Type'] == 'application/gzip'
        assert 'trace-report-' + dense_id + '.json.gz' in headers['Content-Disposition']
        assert json.loads(gzip.decompress(raw)) == dense_report
        assert request(s,'GET',f'/api/jobs/{dense_id}/report')[0] == 403



def test_failed_dense_scan_keeps_only_safe_numeric_progress(monkeypatch):
    from packet_pii.engine import AnalysisLimitError
    import packet_pii.jobs as jobs
    def fail_after_checkpoint(*args, **kwargs):
        kwargs['progress']({'stage': 'ml_inference',
                            'elapsed_seconds': 520.0, 'packets': 495797,
                            'ml_fields_evaluated': 2100000,
                            'ml_inference_batches': 8100,
                            'value': 'SECRET-should-not-be-in-status'})
        raise AnalysisLimitError('Analysis exceeded configured report byte budget')
    monkeypatch.setattr(jobs, 'analyze_to_report', fail_after_checkpoint)
    with server() as s:
        code, body, _ = begin(s, request_id='progress-on-failed-scan', profile='stress')
        assert code == 202
        result = finish(s, json.loads(body)['job_id'])
        assert result['status'] == 'failed'
        assert result['progress']['stage'] == 'failed'
        assert result['progress']['last_stage'] == 'ml_inference'
        assert result['progress']['ml_fields_evaluated'] == 2100000
        assert result['progress']['elapsed_seconds'] == 520.0
        assert 'SECRET-should-not-be-in-status' not in json.dumps(result)
        assert 'report' not in result



def test_deep_field_pages_use_index_seek_and_do_not_stop_at_four_million():
    import sqlite3
    with server() as s:
        code, body, _ = begin(s, request_id='deep-evidence-pages-test')
        assert code == 202
        job_id = json.loads(body)['job_id']
        assert finish(s, job_id)['status'] == 'completed'
        job = s.jobs.get(job_id)
        first = s.jobs.page(job,'field_evidence',offset=0,limit=2)
        second = s.jobs.page(job,'field_evidence',offset=1,limit=2)
        assert first['items'][1] == second['items'][0]
        # This was previously rejected before it could query the index.
        end = s.jobs.page(job,'field_evidence',offset=4_000_001,limit=2)
        assert end['items'] == [] and end['offset'] == 4_000_001
        with sqlite3.connect(job.index) as conn:
            plan = ' '.join(str(row) for row in conn.execute(
                'EXPLAIN QUERY PLAN SELECT data FROM rows '
                'WHERE kind=? AND n>=? ORDER BY n LIMIT ?',
                ('field_evidence', 4_000_001, 100)))
        assert 'USING INDEX' in plan
        assert 'SCAN rows' not in plan
