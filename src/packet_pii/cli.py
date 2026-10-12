"""CLI entrypoint: local analysis with private, atomic JSON output."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import analyze
from .reporting import write_private_report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description='Analyse a local PCAP/PCAPNG for potential PII in plaintext HTTP/1.x'
    )
    parser.add_argument('capture', help='Path to PCAP/PCAPNG file')
    parser.add_argument('--threshold', type=float, default=0.8,
                        help='Minimum heuristic confidence (0..1)')
    parser.add_argument('--output', '-o', default='report.json',
                        help='Private JSON report path (refuses overwrite by default)')
    parser.add_argument('--overwrite', action='store_true',
                        help='Explicitly replace an existing output report')
    parser.add_argument('--include-values', action='store_true',
                        help='Include raw detected data (SENSITIVE; local only)')
    args = parser.parse_args(argv)
    try:
        # Prevent self-destruction if --output points at the capture file,
        # including links and paths with equivalent canonical representation.
        input_path = Path(args.capture)
        output_path = Path(args.output)
        if input_path.resolve() == output_path.resolve():
            raise ValueError('Output report must not be the input capture file')
        # Early refusal avoids potentially expensive capture processing. The
        # writer also enforces this atomically against races and symlinks.
        if not args.overwrite and output_path.is_symlink():
            raise FileExistsError('Output already exists (use --overwrite explicitly)')
        if not args.overwrite and output_path.exists():
            raise FileExistsError('Output already exists (use --overwrite explicitly)')
        report = analyze(input_path, args.threshold, args.include_values)
        write_private_report(report, output_path, overwrite=args.overwrite)
        if args.include_values:
            print('WARNING: report contains unmasked PII/credentials; restrict its distribution.',
                  file=sys.stderr)
        print(f"Analysed {report['summary']['packets_captured']} packets, "
              f"{report['summary']['flows_processed']} TCP flows, "
              f"{report['summary']['http_messages']} HTTP messages, "
              f"{report['summary']['potential_leaks']} potential PII findings. "
              f"Report: {args.output}")
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
