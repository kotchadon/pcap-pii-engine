#!/usr/bin/env python3
"""Bounded-memory equivalence check for plain/gzip reports (requires ijson).

Hashes the complete ordered JSON event stream, excluding only the existing
summary.processing_time_seconds runtime measurement. No field values printed.
This is storage equivalence, not an independent accuracy assessment.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

import ijson


def signature(path):
    digest = hashlib.sha256()
    counts = Counter()
    opener = gzip.open if path.name.endswith('.json.gz') else open
    with opener(path, 'rb') as stream:
        for prefix, event, value in ijson.parse(stream, use_float=True):
            if prefix == 'summary.processing_time_seconds' or (
                    prefix == 'summary' and event == 'map_key' and value == 'processing_time_seconds'):
                continue
            if event == 'start_map' and prefix.endswith('.item') and prefix.count('.') == 1:
                counts[prefix[:-5]] += 1
            digest.update(json.dumps([prefix, event, value], ensure_ascii=False,
                                     separators=(',', ':'), allow_nan=False).encode('utf-8') + b'\n')
    return {'ordered_event_sha256': digest.hexdigest(), 'row_counts': dict(counts)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plain', type=Path)
    parser.add_argument('compressed', type=Path)
    args = parser.parse_args()
    first, second = signature(args.plain), signature(args.compressed)
    result = {'equal_except_processing_time': first == second, 'plain': first, 'compressed': second,
              'excluded': ['summary.processing_time_seconds']}
    print(json.dumps(result, indent=2))
    return 0 if result['equal_except_processing_time'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
