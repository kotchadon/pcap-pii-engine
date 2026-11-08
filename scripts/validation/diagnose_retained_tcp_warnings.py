#!/usr/bin/env python3
"""Read-only, privacy-safe summary of retained TRACE TCP reconstruction warnings.

This does not open raw PCAPs, rerun inference, print field values, or modify
SQLite. Run while the dashboard that produced the job is still running.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile


def inspect_index(path: Path) -> dict:
    """Count results and TCP diagnoses using the existing private index."""
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as db:
        findings = db.execute("SELECT count(*) FROM rows WHERE kind='findings'").fetchone()[0]
        http_messages = db.execute("SELECT count(*) FROM rows WHERE kind='http_evidence'").fetchone()[0]
        directions = unsafe = 0
        reasons: Counter[str] = Counter()
        for (encoded,) in db.execute("SELECT data FROM rows WHERE kind='stream_evidence' ORDER BY n"):
            row = json.loads(encoded)
            if row.get('row_type') != 'stream':
                continue
            directions += 1
            if row.get('unsafe') is True:
                unsafe += 1
                reasons.update(set(row.get('diagnostics') or []))
        return {
            'findings': findings,
            'http_messages': http_messages,
            'tcp_directions': directions,
            'unsafe_tcp_directions': unsafe,
            'tcp_diagnostics_for_unsafe_directions': dict(sorted(reasons.items())),
            'interpretation': (
                'Unsafe includes proven sequence gaps but also resets, '
                'ambiguous overlaps and uncertain TCP boundaries. It does NOT '
                'establish that every marked direction lost packet bytes.'
            ),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--findings', type=int, required=True,
                        help='Exact finding count from the finished TRACE Summary; prevents analysing another job')
    options = parser.parse_args()
    if options.findings < 0:
        parser.error('findings must not be negative')
    root = Path(tempfile.gettempdir())
    indices = sorted(root.glob('trace_jobs_*/*/index.sqlite'),
                     key=lambda p: p.stat().st_mtime, reverse=True)
    for path in indices:
        try:
            result = inspect_index(path)
        except (OSError, sqlite3.Error, ValueError, json.JSONDecodeError):
            continue
        if result['findings'] != options.findings:
            continue
        print(json.dumps(result, indent=2))
        return
    parser.error('No retained completed index with this finding count. '
                 'Keep the original server running; expired/cleaned jobs cannot be recovered.')


if __name__ == '__main__':
    main()
