#!/usr/bin/env python3
"""Full rules-engine + atomic report benchmark. Run each workload in a fresh process.

No raw captured values are printed. Report verification is a separate process so
its JSON loading does not contaminate the engine's peak RSS measurement.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import platform
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from packet_pii.engine import AnalysisLimits, AnalysisLimitError, analyze_to_report, _peak_rss_bytes


def benchmark(capture,output,profile='standard',**overrides):
    limits=AnalysisLimits.for_profile(profile,**overrides)
    capture=Path(capture)
    info={'capture_path':str(capture),'capture_bytes':capture.stat().st_size,
          'platform':platform.platform(),'machine':platform.machine(),'python':platform.python_version(),
          'profile':profile,'limits':vars(limits),'rules_included':True,'ml_included':False,
          'report_writing_included':True,'network_only':False}
    with capture.open('rb') as f:magic=f.read(4)
    info['capture_format']='pcapng' if magic==b'\x0a\x0d\x0d\x0a' else 'pcap'
    started=time.perf_counter();timings={}
    try:
        receipt=analyze_to_report(capture,output,profile=profile,limits=limits,timings=timings)
        summary=receipt['summary']
        info.update(success=True,summary=summary,report_bytes=receipt['output_bytes'],
                    rules_findings=summary['potential_leaks'],ml_findings=0,
                    report_status='incomplete_evidence' if summary['analysis_incomplete'] else 'complete',
                    failure_cause=None)
    except (OSError,ValueError,TypeError,MemoryError) as exc:
        # Exception strings may contain OS paths. Emit class only; no capture text.
        info.update(success=False,failure_cause=type(exc).__name__,
                    failure_reason=str(exc) if isinstance(exc,AnalysisLimitError) else 'See error class; no report published')
    duration=time.perf_counter()-started
    info.update(wall_seconds=duration,peak_rss_mib=_peak_rss_bytes()/2**20,stage_seconds=timings)
    info['throughput_mib_s']=info['capture_bytes']/2**20/duration if info['success'] else None
    info['packets_per_second']=info['summary']['packets_captured']/duration if info['success'] else None
    return info


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--profile',choices=('standard','large','stress'),default='standard')
    for name in ('capture-mib','packets','flows','tcp-mib','report-mib','memory-mib','findings'):
        p.add_argument('--max-'+name,type=int,default=None)
    a=p.parse_args();overrides={}
    for name,field,mult in [('capture_mib','capture_bytes',2**20),('packets','packets',1),
         ('flows','flows',1),('tcp_mib','tcp_payload_bytes',2**20),('report_mib','report_bytes',2**20),
         ('memory_mib','memory_bytes',2**20),('findings','findings',1)]:
        v=getattr(a,'max_'+name)
        if v is not None:overrides['max_'+field]=v*mult
    info=benchmark(a.capture,a.output,a.profile,**overrides)
    print(json.dumps(info,indent=2))
    return 0 if info['success'] else 1

if __name__=='__main__':raise SystemExit(main())
