#!/usr/bin/env python3
"""Fresh-process local HTTP upload/job/page/download benchmark; no capture logs.

The parent verifies downloaded JSON separately from server peak RSS. Run one
workload per invocation. Optional real checkpoint must exist; never falls back.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
from http.client import HTTPConnection
import json
import multiprocessing as mp
from pathlib import Path
import platform
import sys
import threading
import time
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))


def serve(pipe,checkpoint):
    from packet_pii.dashboard import DashboardServer
    from packet_pii.engine import _peak_rss_bytes
    from packet_pii.hybrid import load_experimental_bilstm
    try:
        detector=load_experimental_bilstm(checkpoint) if checkpoint else None
        server=DashboardServer(('127.0.0.1',0),ml_detector=detector)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        pipe.send({'port':server.server_port})
        job_id=pipe.recv()
        job=server.jobs.get(job_id)
        digest=hashlib.sha256()
        with job.report.open('rb') as f:
            while block:=f.read(256*1024):digest.update(block)
        pipe.send({'peak_rss_mib':_peak_rss_bytes()/2**20,
                   'report_sha256':digest.hexdigest(),'index_bytes':job.index.stat().st_size})
        pipe.recv()
        server.shutdown();server.server_close();thread.join(3)
    except Exception as exc:
        pipe.send({'error':type(exc).__name__})
    finally:pipe.close()


def request(port,method,path,*,headers=None,body=None):
    c=HTTPConnection('127.0.0.1',port,timeout=130)
    c.request(method,path,body=body,headers=headers or {})
    response=c.getresponse();raw=response.read();status=response.status;c.close()
    if status>=400:raise ValueError('HTTP request failed: '+str(status))
    return json.loads(raw),len(raw)


def verify_download(path):
    with path.open(encoding='utf-8') as f:report=json.load(f)
    s=report['summary'];findings=report['findings'];flows=report['flows']
    assert len(findings)==s['potential_leaks'] and len(flows)==s['flows_processed']
    assert sum(f['http_messages'] for f in flows)==s['http_messages']
    assert sum(f['packets'] for f in flows)+s['non_tcp_or_unsupported_packets']==s['packets_captured']
    assert Counter(f['detector'] for f in findings)==Counter({k:v for k,v in {'rule':s['rules_findings'],'bilstm':s['ml_findings']}.items() if v})
    assert all('fingerprint' not in f and '***' in f['value'] for f in findings)
    digest=hashlib.sha256()
    for rows in (flows,findings):
        for row in rows:
            digest.update(json.dumps(row,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode());digest.update(b'\n')
    return digest.hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture',type=Path);p.add_argument('download',type=Path)
    p.add_argument('--profile',choices=('standard','large','stress'),default='standard')
    p.add_argument('--ml-checkpoint');a=p.parse_args()
    ctx=mp.get_context('spawn');parent,child=ctx.Pipe()
    process=ctx.Process(target=serve,args=(child,a.ml_checkpoint));process.start();child.close()
    result={'platform':platform.platform(),'machine':platform.machine(),'python':platform.python_version(),
            'capture_name':a.capture.name,'capture_bytes':a.capture.stat().st_size,'profile':a.profile,
            'inference_requested':bool(a.ml_checkpoint),'transport':'real loopback HTTP upload, job, SQLite page, streamed download'}
    try:
        if not parent.poll(90):raise TimeoutError('Server startup deadline')
        ready=parent.recv()
        if 'error' in ready:raise RuntimeError('Checkpoint/server unavailable: '+ready['error'])
        port=ready['port'];session,_=request(port,'GET','/api/session');token=session['token']
        headers={'X-Dashboard-Token':token,'X-Request-ID':str(uuid.uuid4()),'X-Capture-Name':a.capture.name,
            'Content-Type':'application/octet-stream','Content-Length':str(a.capture.stat().st_size),
            'X-Detection-Mode':'hybrid' if a.ml_checkpoint else 'rules','X-Analysis-Profile':a.profile}
        started=time.perf_counter()
        with a.capture.open('rb') as body:accepted,_=request(port,'POST','/api/jobs',headers=headers,body=body)
        accepted_time=time.perf_counter()-started;job_id=accepted['job_id'];auth={'X-Dashboard-Token':token}
        status={};stages=set()
        while time.perf_counter()-started<240:
            status,preview_bytes=request(port,'GET','/api/jobs/'+job_id,headers=auth)
            stages.add(status['progress']['stage'])
            if status['status'] in ('completed','failed','cancelled'):break
            time.sleep(.25)
        if status.get('status')!='completed':raise RuntimeError('Job did not complete: '+str(status.get('reason_type')))
        analysis_wall=time.perf_counter()-started
        summary=status['report']['summary'];total=summary['potential_leaks']
        page,_=request(port,'GET',f'/api/jobs/{job_id}/findings?offset={max(0,total-100)}&limit=100',headers=auth)
        assert page['total']==total and len(page['items'])==min(100,total)
        c=HTTPConnection('127.0.0.1',port,timeout=30);c.request('GET',f'/api/jobs/{job_id}/report',headers=auth)
        response=c.getresponse();assert response.status==200
        checksum=hashlib.sha256();written=0
        with a.download.open('xb') as out:
            a.download.chmod(0o600)
            while block:=response.read(256*1024):out.write(block);checksum.update(block);written+=len(block)
        assert written==int(response.getheader('Content-Length'));c.close()
        total_wall=time.perf_counter()-started
        parent.send(job_id)
        if not parent.poll(30):raise TimeoutError('Measurement deadline')
        metrics=parent.recv();assert checksum.hexdigest()==metrics['report_sha256']
        result.update(success=True,summary=summary,job_accept_seconds=accepted_time,
            analysis_wall_seconds=analysis_wall,upload_analysis_download_seconds=total_wall,
            preview_json_bytes=preview_bytes,preview_findings=len(status['report']['findings']),
            preview_flows=len(status['report']['flows']),report_bytes=written,stages_observed=sorted(stages),
            inference_used=summary['ml_invoked'],**metrics)
        result['semantic_sha256']=verify_download(a.download)
        result['full_output_verified']=True
        parent.send('stop')
    except Exception as exc:
        result.update(success=False,error=type(exc).__name__,failure=str(exc) if isinstance(exc,(TimeoutError,RuntimeError)) else 'Benchmark verification failed')
    finally:
        parent.close();process.join(8)
        if process.is_alive():process.terminate();process.join(3)
    print(json.dumps(result,indent=2));return 0 if result['success'] else 1

if __name__=='__main__':raise SystemExit(main())
