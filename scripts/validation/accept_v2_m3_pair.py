#!/usr/bin/env python3
"""Repeated, isolated native M3 comparisons. No uploads or modified resource caps.

Each scan uses a fresh process and model. Load time is reported separately; scan
timing includes the first inference call, indexing and atomic report publication.
Use profile_frozen_v2.py separately for cold/warm model-call measurements.
"""
import argparse
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys

OWNER_CAPTURE_SHA256='42e52f7ebb470d45e3d883ba6c800a11fce17357cf0edad417fefb8ca059c9ce'
OWNER_COUNTS={'packets_captured':361389,'http_messages':120462,'fields_extracted':2349009,
              'ml_fields_excluded_by_policy':421617,'ml_fields_eligible':1927392,
              'ml_fields_evaluated':1927392,'ml_fields_skipped':0,
              'rules_findings':244046,'ml_findings':180694,'potential_leaks':424740}


def validate_pair(before, after):
    errors=[]
    keys=('capture_sha256','capture_bytes','profile','analysis_limits','ml_work_budget',
          'ml_profile','threads','torch','checkpoint_sha256','model_version','min_score','cache_enabled')
    for key in keys:
        if before.get(key) is None or before.get(key)!=after.get(key):errors.append('mismatch: '+key)
    for name,data in (('baseline',before),('candidate',after)):
        if data.get('model_version')!='bilstm-v2-d1f9e9fb9a2b' or data.get('min_score')!=.35:
            errors.append(name+': not frozen V2 operating point')
        if not data.get('checkpoint_sha256') or not data.get('analysis_limits') or not data.get('ml_work_budget'):
            errors.append(name+': missing identity/resource metadata')
        runs=data.get('runs',[])
        if len(runs)!=1:errors.append(name+': expected one isolated scan');continue
        run=runs[0];summary=run.get('summary',{});identity=run.get('verified_capture_evidence',{})
        if data.get('capture_sha256')==OWNER_CAPTURE_SHA256:
            for key,expected in OWNER_COUNTS.items():
                if summary.get(key)!=expected:errors.append(name+': historical capture count mismatch: '+key)
        if run.get('status')!='completed' or summary.get('analysis_incomplete') is not False:
            errors.append(name+': incomplete scan')
        if (summary.get('ml_inference_complete') is not True or summary.get('ml_fields_skipped')!=0
                or not summary.get('ml_fields_eligible',0)
                or summary.get('ml_fields_eligible')!=summary.get('ml_fields_evaluated')):
            errors.append(name+': incomplete or empty eligible coverage')
        if identity.get('identity_status')!='verified_read' or identity.get('capture_sha256')!=data.get('capture_sha256'):
            errors.append(name+': unverified capture identity')
        if run.get('report_digest_method')!='ordered-json-events-v1' or not run.get('canonical_report_sha256'):
            errors.append(name+': missing full report signature')
        if not 0 < run.get('lifetime_peak_rss',0) <= data.get('analysis_limits',{}).get('max_memory_bytes',0):
            errors.append(name+': missing or excessive peak RSS')
    if len(before.get('runs',[]))==len(after.get('runs',[]))==1:
        if before['runs'][0].get('canonical_report_sha256')!=after['runs'][0].get('canonical_report_sha256'):
            errors.append('full report content changed (excluding only three clocks)')
    return errors


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline-root',type=Path,required=True)
    p.add_argument('--candidate-root',type=Path,default=Path(__file__).resolve().parents[2])
    p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--expected-capture-sha256',required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--threads',type=int,default=2)
    p.add_argument('--repetitions',type=int,choices=(2,3),default=2)
    p.add_argument('--ml-profile',default='high_capacity')
    args=p.parse_args()
    if sys.platform!='darwin' or platform.machine()!='arm64':p.error('BLOCKED: native arm64 macOS M3 required')
    chip=subprocess.check_output(['sysctl','-n','machdep.cpu.brand_string'],text=True).strip()
    if chip!='Apple M3':p.error('BLOCKED: exact Apple M3 CPU required; found '+chip)
    machine_model=subprocess.check_output(['sysctl','-n','hw.model'],text=True).strip()
    memory=int(subprocess.check_output(['sysctl','-n','hw.memsize'],text=True))
    if memory!=16*2**30:p.error('BLOCKED: specified 16 GiB target required')
    if not 1<=args.threads<=8:p.error('threads must be 1..8')
    if not args.capture.is_file():p.error('existing capture required')
    if args.output_dir.exists():p.error('output directory exists')
    args.output_dir.mkdir(parents=True,mode=0o700)
    roots={'baseline':args.baseline_root.resolve(),'candidate':args.candidate_root.resolve()}
    bench=Path(__file__).with_name('bench_performance_memory.py')
    collected={'baseline':[],'candidate':[]};errors=[]
    for iteration in range(args.repetitions):
        order=('baseline','candidate') if iteration%2==0 else ('candidate','baseline')
        for name in order:
            root=roots[name];destination=args.output_dir/f'{name}-{iteration}.json'
            cmd=[sys.executable,str(bench),'--source-root',str(root),'--capture',str(args.capture.resolve()),
                 '--expected-capture-sha256',args.expected_capture_sha256,'--output',str(destination),
                 '--checkpoint',str(root/'src/packet_pii/ml/artifacts/bilstm_v2'),
                 '--profile','stress','--ml-profile',args.ml_profile,'--threads',str(args.threads),
                 '--indexed','--require-complete','--stream-digest','--worker-timeout','7200']
            subprocess.run(cmd,check=True,timeout=7500)
            collected[name].append(json.loads(destination.read_text()))
        errors.extend(validate_pair(collected['baseline'][-1],collected['candidate'][-1]))
        if errors:break  # refuse further expensive repetitions after a failed correctness gate
    medians={name:statistics.median(d['runs'][0]['seconds'] for d in results) for name,results in collected.items()}
    # Require repeatable report identity, not merely equal totals in each pair.
    digests={d['runs'][0]['canonical_report_sha256'] for results in collected.values() for d in results}
    if len(digests)!=1:errors.append('nonrepeatable report identity across repetitions')
    owner_capture=args.expected_capture_sha256==OWNER_CAPTURE_SHA256
    report={'chip':chip,'machine_model':machine_model,'memory_bytes':memory,'platform':platform.platform(),
            'repetitions':args.repetitions,'errors':errors,'median_scan_seconds':medians,
            'reduction_percent':100*(1-medians['candidate']/medians['baseline']),
            'comparative_30_percent_target_met':not errors and medians['candidate']<=.7*medians['baseline'],
            'historical_110mib_30_percent_target_met':(not errors and medians['candidate']<=.7*683.834) if owner_capture else None,
            'historical_110mib_five_minute_target_met':(not errors and medians['candidate']<=300) if owner_capture else None,
            'scope':'Fresh process/model per scan. Load excluded, first inference included. No size extrapolation.',
            'results':collected}
    (args.output_dir/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'output':str(args.output_dir/'comparison.json'),'errors':errors,'medians':medians}))
    return 1 if errors else 0


if __name__=='__main__':raise SystemExit(main())
