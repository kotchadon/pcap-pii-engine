#!/usr/bin/env python3
"""One isolated scan worker; launch separately for each source/configuration.

Fictional fixture only. CPU/heap instrumentation is explicitly separate from
controlled timing runs. Full report digest excludes only documented clocks.
"""
import argparse
import cProfile
from dataclasses import asdict
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


def stream_signature(path):
    """Hash every ordered JSON event using bounded memory; ignore only three clocks."""
    import ijson
    excluded = {'metadata.generated_at', 'summary.processing_time_seconds', 'summary.ml_processing_time_seconds'}
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for prefix, event, value in ijson.parse(source, use_float=True):
            if prefix in excluded or (event == 'map_key' and prefix + '.' + value in excluded):
                continue
            digest.update(json.dumps([prefix, event, value], ensure_ascii=False, separators=(',', ':'),
                                     allow_nan=False).encode() + b'\n')
    return digest.hexdigest()


def main():
    if len(sys.argv) == 3 and sys.argv[1] in ('--digest-report', '--stream-digest-report'):
        path = Path(sys.argv[2])
        print(stream_signature(path) if sys.argv[1] == '--stream-digest-report' else canonical(json.loads(path.read_text())))
        return
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--mib',type=float,default=2)
    p.add_argument('--profile',choices=['standard','large','stress'],default='standard')
    p.add_argument('--worker-timeout',type=int,default=300,help='Indexed worker deadline, 1..7200 seconds; default unchanged')
    p.add_argument('--expected-capture-sha256',help='Require an existing capture with this SHA-256 before loading the model')
    p.add_argument('--stream-digest',action='store_true',help='Bounded-memory full ordered report digest; requires ijson')
    p.add_argument('--require-complete',action='store_true',help='Fail the acceptance run if analysis or eligible ML coverage is incomplete')
    p.add_argument('--repeat',type=int,default=1)
    p.add_argument('--instrument',action='store_true')
    p.add_argument('--checkpoint',type=Path,help='Genuine checkpoint; omission explicitly selects Rules')
    p.add_argument('--ml-profile',choices=('standard','extended','complete','high_capacity',
                                          'capacity_5m','capacity_8m','capacity_10m','capacity_15m'),default='standard',
                   help='Explicit bounded ML work profile for Hybrid; default Standard is unchanged')
    p.add_argument('--no-cache',action='store_true')
    p.add_argument('--threads',type=int,default=2)
    p.add_argument('--indexed',action='store_true',help='Use actual JobManager, including SQLite index and cleanup')
    p.add_argument('--historical-peak',action='store_true')
    args=p.parse_args();root=args.source_root.resolve()
    if not 1 <= args.worker_timeout <= 7200:p.error('worker timeout must be 1..7200 seconds')
    if not 1 <= args.threads <= 8:p.error('threads must be 1..8')
    if args.expected_capture_sha256:
        if len(args.expected_capture_sha256)!=64 or any(c not in '0123456789abcdef' for c in args.expected_capture_sha256):
            p.error('expected capture SHA-256 must be 64 lowercase hexadecimal digits')
        if not args.capture.is_file():p.error('expected capture must already exist; automatic generation disabled')
    if args.stream_digest:
        try:import ijson
        except ImportError:p.error('--stream-digest requires ijson')
    if args.ml_profile != 'standard' and args.checkpoint is None:
        p.error('--ml-profile extended/complete requires a genuine --checkpoint')
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
    if args.expected_capture_sha256 and capture_sha != args.expected_capture_sha256:
        p.error('capture SHA-256 mismatch')
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
    # Benchmark-only accounting; do not retain runners, cached values or field strings.
    from packet_pii import engine
    original_runner = engine.MLBatchRunner
    cache_samples = []
    class MeasuredRunner(original_runner):
        def _run(self, batch):
            tick, model_before = time.perf_counter(), self.seconds
            try:
                return super()._run(batch)
            finally:
                # Includes cache lookup/insertion AND finding reconstruction;
                # do not mislabel this residual as pure cache time.
                self._bench_bookkeeping = getattr(self, '_bench_bookkeeping', 0.) + max(
                    0., time.perf_counter() - tick - (self.seconds - model_before))

        def flush(self, *, final=True):
            result = super().flush(final=final)
            sample = {'model_evaluations':self.model_evaluations,'cache_hits':self.cache_hits,
                      'cache_evictions':self.cache_evictions,'accounted_cache_bytes':self.cache_bytes,
                      'bookkeeping_including_cache_and_findings_seconds':getattr(self, '_bench_bookkeeping', 0.)}
            if cache_samples:cache_samples[0] = sample
            else:cache_samples.append(sample)
            return result
    for n in range(args.repeat):
        target=args.output.with_suffix(f'.scan{n}.json'); stages={};memory={}
        def progress(event):
            key=event['stage'];current=rss()
            memory[key]={'last_current_rss':current,'observed_peak_rss':peak(),
                         'max_sampled_rss':max(current or 0,memory.get(key,{}).get('max_sampled_rss',0))}
        start=time.perf_counter()
        cpu_start=time.process_time()
        if profiler and not args.indexed:profiler.enable()
        manager=None
        original=None
        cache_samples.clear()
        engine.MLBatchRunner = MeasuredRunner
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
                    original_progress=kw.get('progress')
                    def indexed_progress(event):
                        progress(event)
                        if original_progress:original_progress(event)
                    kw['progress']=indexed_progress
                    if profiler:profiler.enable()
                    try:result=original(*a,**kw)
                    finally:
                        if profiler:profiler.disable()
                    stages['index_observer_included_in_other_stages']=index_seconds
                    return result
                jobs.analyze_to_report=indexed_analysis
                job,_=manager.reserve(str(n),filename='fictional.pcap',source='synthetic',
                    size=args.capture.stat().st_size,mode='hybrid' if detector else 'rules',profile=args.profile,
                    ml_profile=args.ml_profile)
                job.limits=bounds
                shutil.copyfile(args.capture,job.capture)
                start=time.perf_counter()
                cpu_start=time.process_time()
                manager.start(job);job.thread.join(timeout=args.worker_timeout)
                if job.thread.is_alive():
                    job.cancel.set();raise RuntimeError('indexed scan timed out')
                if job.status!='completed':raise RuntimeError('indexed scan '+job.status+': '+str(job.error))
                target=job.report;receipt=job.receipt
                stages['index_bytes']=job.index.stat().st_size
            else:
                receipt=analyze_to_report(args.capture,target,limits=bounds,profile=args.profile,timings=stages,
                                          progress=progress,ml_detector=detector,
                                          ml_budget=args.ml_profile if detector else None)
            identity=receipt.get('capture_evidence', {})
            if identity.get('identity_status')!='verified_read' or identity.get('capture_sha256')!=capture_sha:
                raise RuntimeError('capture identity differs from the verified preflight SHA-256')
            if args.require_complete:
                summary=receipt['summary']
                if summary.get('analysis_incomplete') or (detector is not None and (
                    not summary.get('ml_inference_complete') or summary.get('ml_fields_skipped') != 0 or
                    summary.get('ml_fields_evaluated') != summary.get('ml_fields_eligible'))):
                    raise RuntimeError('acceptance requires complete analysis and eligible-field coverage')
        except Exception as exc:
            if profiler:profiler.disable()
            runs.append({'status':'failed','error_type':type(exc).__name__,'error':str(exc),
                         'seconds':time.perf_counter()-start,'stages':stages,'memory':memory,'report_exists':target.exists()})
            if manager:manager.close()
            break
        finally:
            if original is not None:jobs.analyze_to_report=original
            engine.MLBatchRunner=original_runner
        if profiler:profiler.disable()
        elapsed=time.perf_counter()-start;cpu_elapsed=time.process_time()-cpu_start;current=rss();maximum=peak()
        # Decode/hash outside the scan worker: a full JSON load would contaminate later RSS samples.
        digest_mode='--stream-digest-report' if args.stream_digest else '--digest-report'
        try:
            full_digest=subprocess.check_output([sys.executable, __file__, digest_mode, str(target)],
                                                text=True, timeout=args.worker_timeout).strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            runs.append({'status':'failed','error_type':type(exc).__name__,'error':'report integrity verification failed',
                         'seconds':elapsed,'stages':stages,'memory':memory})
            if manager:manager.close()
            break
        runs.append({'status':'completed','seconds':elapsed,'model_seconds':stages.get('ml_inference',0),
                     'process_cpu_seconds':cpu_elapsed,'average_cpu_cores':cpu_elapsed/elapsed,
                     'current_rss_after_analysis':current,'lifetime_peak_rss':maximum,'stages':stages,
                     'memory':memory,'output_bytes':target.stat().st_size,'canonical_report_sha256':full_digest,
                     'report_digest_method':'ordered-json-events-v1' if args.stream_digest else 'sorted-json-v1',
                     'cache':dict(cache_samples[0]) if cache_samples else None,
                     'verified_capture_evidence':identity,
                     'summary':receipt['summary']})
        del receipt;gc.collect()
        if manager:manager.close()
        runs[-1]['current_rss_after_report_release']=rss()
    result={'platform':platform.platform(),'architecture':platform.machine(),'python':platform.python_version(),
            'source_root':str(root),'capture_sha256':capture_sha,'capture_bytes':args.capture.stat().st_size,
            'profile':args.profile,'memory_budget_bytes':bounds.max_memory_bytes,'rss_before':before,
            'analysis_limits':asdict(bounds),
            'ml_work_budget':ml_runner.MLWorkBudget.for_profile(args.ml_profile).public() if detector else None,
            'checkpoint_sha256':{str(f.relative_to(args.checkpoint)):hashlib.sha256(f.read_bytes()).hexdigest()
                                 for f in sorted(args.checkpoint.rglob('*')) if f.is_file() and f.suffix in ('.pt','.json')}
                                if detector else None,
            'worker_timeout_seconds':args.worker_timeout,'expected_capture_sha256':args.expected_capture_sha256,
            'scope':'JobManager + SQLite index + atomic report' if args.indexed else 'engine + atomic report; excludes dashboard SQLite indexing',
            'mode':'hybrid' if detector else 'rules','ml_profile':args.ml_profile if detector else None,
            'model_load_seconds':load_seconds,'rss_after_model_load':loaded_rss,
            'model_version':detector.model_version if detector else None,
            'min_score':detector.min_score if detector else None,'torch':torch.__version__ if detector else None,
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
    return 0 if len(runs)==args.repeat and all(r['status']=='completed' for r in runs) else 1


if __name__=='__main__':raise SystemExit(main())
