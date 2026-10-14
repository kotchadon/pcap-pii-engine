"""CLI entrypoint: local analysis with private, atomic JSON output."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import AnalysisLimits, analyze
from .reporting import write_private_report
from .hybrid import load_experimental_bilstm


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
    parser.add_argument('--ml-checkpoint', default=None,
                        help='Opt in to experimental BiLSTM inference using this local checkpoint directory')
    parser.add_argument('--include-values', action='store_true',
                        help='Include raw detected data (SENSITIVE; local only)')
    parser.add_argument('--max-capture-mib', type=int, default=128,
                        help='Maximum input capture size in MiB (default 128)')
    parser.add_argument('--max-packets', type=int, default=100000,
                        help='Maximum packets to process (default 100000)')
    parser.add_argument('--max-flows', type=int, default=20000,
                        help='Maximum distinct TCP endpoint pairs (default 20000)')
    parser.add_argument('--max-tcp-mib', type=int, default=64,
                        help='Maximum buffered TCP payload MiB (default 64)')
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
        limits = AnalysisLimits(
            max_capture_bytes=args.max_capture_mib * 1024 * 1024,
            max_packets=args.max_packets,
            max_flows=args.max_flows,
            max_tcp_payload_bytes=args.max_tcp_mib * 1024 * 1024,
        )
        model = load_experimental_bilstm(args.ml_checkpoint) if args.ml_checkpoint else None
        report = analyze(input_path, args.threshold, args.include_values, limits=limits, ml_detector=model)
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
    except (OSError, ValueError, TypeError, ImportError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
