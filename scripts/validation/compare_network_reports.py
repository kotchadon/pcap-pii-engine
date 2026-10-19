#!/usr/bin/env python3
"""Compare legacy finding/flow semantics without materializing large reports.

Validation-only dependency: ijson>=3.3,<4. No payload values are printed.
"""
import argparse
import hashlib
import json
from pathlib import Path


def fingerprint(path):
    import ijson
    with Path(path).open('rb') as stream:
        summary = next(ijson.items(stream, 'summary', use_float=True))
    result = {}
    for name, expected in [('flows', summary['flows_processed']), ('findings', summary['potential_leaks'])]:
        digest = hashlib.sha256()
        count = 0
        if expected:
            with Path(path).open('rb') as stream:
                for row in ijson.items(stream, name+'.item', use_float=True):
                    if name == 'findings':
                        row.pop('evidence', None)
                    digest.update(json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode())
                    digest.update(b'\n')
                    count += 1
                    if count == expected:
                        break
        if count != expected:
            raise ValueError('Report row count differs from summary')
        result[name] = {'count': count, 'sha256': digest.hexdigest()}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    baseline, candidate = fingerprint(args.baseline), fingerprint(args.candidate)
    result = {'baseline': baseline, 'candidate': candidate, 'legacy_semantics_equal': baseline == candidate,
              'comparison': 'All flow and finding fields; only additive finding.evidence excluded'}
    print(json.dumps(result, indent=2))
    return 0 if result['legacy_semantics_equal'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
