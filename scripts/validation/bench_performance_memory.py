#!/usr/bin/env python3
"""One isolated scan worker; launch separately for each source/configuration.

Fictional fixture only. CPU/heap instrumentation is explicitly separate from
controlled timing runs. Full report digest excludes only documented clocks.
"""
import argparse
import cProfile
import gc
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
import platform
import pstats
import resource
import shutil
import sys
import subprocess
import threading
import time
import tracemalloc


def rss():
    if sys.platform.startswith('linux'):
        return int(Path('/proc/self/statm').read_text().split()[1])*resource.getpagesize()
    import psutil  # independent native reader also works against main, which lacks memory.py
    return psutil.Process().memory_info().rss


def peak():
    value=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform=='darwin' else value*1024)


def canonical(report):
    report['metadata'].pop('generated_at',None)
    for key in ('processing_time_seconds','ml_processing_time_seconds'):
        report['summary'].pop(key,None)
    return hashlib.sha256(json.dumps(report,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--digest-report':
        print(canonical(json.loads(Path(sys.argv[2]).read_text())))
        return
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--mib',type=float,default=2)
    p.add_argument('--profile',choices=['standard','large'],default='standard')
    p.add_argument('--repeat',type=int,default=1)
    p.add_argument('--instrument',action='store_true')
    p.add_argument('--checkpoint',type=Path,help='Genuine checkpoint; omission explicitly selects Rules')
    p.add_argument('--no-cache',action='store_true')
    p.add_argument('--threads',type=int,default=2)
    p.add_argument('--indexed',action='store_true',help='Use actual JobManager, including SQLite index and cleanup')
    p.add_argument('--historical-peak',action='store_true')
    args=p.parse_args();root=args.source_root.resolve()
    if not 1<=args.repeat<=3:p.error('repeat must be1..3')
    if args.output.exists():p.error('output exists')
    sys.path.insert(0,str(root/'src'))
    from packet_pii.engine import analyze_to_report, AnalysisLimits
    if not args.capture.exists():
        spec=importlib.util.spec_from_file_location('fixture',root/'scripts/ml/bench_v2_inference.py')
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        fixture.generate_capture(args.capture,args.mib)
    digest=hashlib.sha256()
    with args.capture.open('rb') as capture_file:
        for block in iter(lambda: capture_file.read(1024*1024), b''):digest.update(block)
    capture_sha=digest.hexdigest()
    bounds=AnalysisLimits.for_profile(args.profile)
    before=rss();historical=None
    detector=None;load_seconds=0.0
    if args.checkpoint:
        import torch
        torch.set_num_threads(args.threads)
        from packet_pii.ml.infer import BiLSTMDetector
        from packet_pii import ml_runner
        ml_runner.PREDICTION_CACHE_ENABLED=not args.no_cache
        tick=time.perf_counter();detector=BiLSTMDetector(str(args.checkpoint.resolve()))
        load_seconds=time.perf_counter()-tick
    loaded_rss=rss()
    if args.historical_peak:
        from dataclasses import replace
        bounds=replace(bounds,max_memory_bytes=96*2**20)
        with mmap.mmap(-1,128*2**20) as region:
            for at in range(0,len(region),4096):region[at]=1
            historical={'allocated_rss':rss(),'peak':peak()}
        historical['released_rss']=rss()
    profiler=cProfile.Profile() if args.instrument else None
    if args.instrument:tracemalloc.start()
    runs=[]
    for n in range(args.repeat):
        target=args.output.with_suffix(f'.scan{n}.json'); stages={};memory={}
        def progress(event):
            key=event['stage'];current=rss()
            memory[key]={'last_current_rss':current,'observed_peak_rss':peak(),
                         'max_sampled_rss':max(current or 0,memory.get(key,{}).get('max_sampled_rss',0))}
        start=time.perf_counter()
        if profiler:profiler.enable()
        manager=None
        try:
            if args.indexed:
                from packet_pii import jobs
                manager=jobs.JobManager(threading.Lock(),detector,assessment_budget=None)
                original=jobs.analyze_to_report
                def indexed_analysis(*a,**kw):
                    observer_key='encoded_row_observer' if 'encoded_row_observer' in kw else 'row_observer'
                    observer=kw[observer_key];index_seconds=0.0
                    def observe(*row_args):
                        nonlocal index_seconds
                        tick=time.perf_counter();observer(*row_args);index_seconds+=time.perf_counter()-tick
                    kw[observer_key]=observe;kw['timings']=stages
                    result=original(*a,**kw)
                    stages['index_observer_included_in_other_stages']=index_seconds
                    return result
                jobs.analyze_to_report=indexed_analysis
                job,_=manager.reserve(str(n),filename='fictional.pcap',source='synthetic',
                    size=args.capture.stat().st_size,mode='hybrid' if detector else 'rules',profile=args.profile)
                job.limits=bounds
                shutil.copyfile(args.capture,job.capture)
                start=time.perf_counter()
                manager.start(job);job.thread.join(timeout=300)
                if job.thread.is_alive():
                    job.cancel.set();raise RuntimeError('indexed scan timed out')
                if job.status!='completed':raise RuntimeError('indexed scan '+job.status+': '+str(job.error))
                target=job.report;receipt=job.receipt
                stages['index_bytes']=job.index.stat().st_size
                jobs.analyze_to_report=original
            else:
                receipt=analyze_to_report(args.capture,target,limits=bounds,profile=args.profile,timings=stages,progress=progress,ml_detector=detector)
        except Exception as exc:
            if profiler:profiler.disable()
            runs.append({'status':'failed','error_type':type(exc).__name__,'error':str(exc),
                         'seconds':time.perf_counter()-start,'stages':stages,'memory':memory,'report_exists':target.exists()})
            if manager:manager.close()
            break
        if profiler:profiler.disable()
        elapsed=time.perf_counter()-start;current=rss();maximum=peak()
        # Decode/hash outside the scan worker: a full JSON load would contaminate later RSS samples.
        full_digest=subprocess.check_output([sys.executable, __file__, '--digest-report', str(target)], text=True).strip()
        runs.append({'status':'completed','seconds':elapsed,'model_seconds':stages.get('ml_inference',0),
                     'current_rss_after_analysis':current,'lifetime_peak_rss':maximum,'stages':stages,
                     'memory':memory,'output_bytes':target.stat().st_size,'canonical_report_sha256':full_digest,
                     'summary':receipt['summary']})
        del receipt;gc.collect()
        if manager:manager.close()
        runs[-1]['current_rss_after_report_release']=rss()
    result={'platform':platform.platform(),'architecture':platform.machine(),'python':platform.python_version(),
            'source_root':str(root),'capture_sha256':capture_sha,'capture_bytes':args.capture.stat().st_size,
            'profile':args.profile,'memory_budget_bytes':bounds.max_memory_bytes,'rss_before':before,
            'scope':'JobManager + SQLite index + atomic report' if args.indexed else 'engine + atomic report; excludes dashboard SQLite indexing',
            'mode':'hybrid' if detector else 'rules','model_load_seconds':load_seconds,'rss_after_model_load':loaded_rss,
            'cache_enabled':bool(detector) and not args.no_cache,'threads':args.threads if detector else None,
            'instrumented':args.instrument,'historical_peak_reproduction':historical,'runs':runs}
    if args.instrument:
        current,maximum=tracemalloc.get_traced_memory();tracemalloc.stop()
        result['python_heap']={'current':current,'peak':maximum,'excludes':'native allocations; run timing instrumented'}
        stats=pstats.Stats(profiler)
        result['profile_top']=[{'file':str(k[0]),'line':k[1],'function':k[2],'calls':v[1],
                                'self_seconds':v[2],'cumulative_seconds':v[3]}
                               for k,v in sorted(stats.stats.items(),key=lambda kv:kv[1][3],reverse=True)[:35]]
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'output':str(args.output),'runs':[{k:r.get(k) for k in ('status','seconds','output_bytes','current_rss_after_analysis','lifetime_peak_rss')} for r in runs]}))


if __name__=='__main__':main()
