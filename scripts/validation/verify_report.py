#!/usr/bin/env python3
"""Separate-process complete JSON, accounting, masking and semantic digest check.

This validator loads the report. Its RAM is NOT included in the engine benchmark.
Digest excludes timing and metadata; preserves finding/flow order and provenance.
No individual finding or captured text is printed.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def verify(path):
    with Path(path).open(encoding='utf-8') as f:report=json.load(f)
    summary=report['summary'];findings=report['findings'];flows=report['flows']
    assert len(findings)==summary['potential_leaks']
    assert len(flows)==summary['flows_processed']
    assert sum(x['packets'] for x in flows)+summary['non_tcp_or_unsupported_packets']==summary['packets_captured']
    assert sum(x['http_messages'] for x in flows)==summary['http_messages']
    assert sum(x['http_transactions'] for x in flows)==summary['http_transactions']
    assert report['metadata']['raw_values_included'] is False
    assert all('fingerprint' not in x and '***' in x['value'] and x['detector']=='rule' for x in findings)
    digest=hashlib.sha256()
    for collection in (flows,findings):
        for row in collection:
            digest.update(json.dumps(row,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode())
            digest.update(b'\n')
    return {'valid_json':True,'accounting_matches':True,'all_findings_masked':True,
            'semantic_sha256':digest.hexdigest(),'findings_by_type':dict(Counter(x['pii_type'] for x in findings)),
            'summary':summary}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path)
    a=p.parse_args();print(json.dumps(verify(a.report),indent=2))

if __name__=='__main__':main()
