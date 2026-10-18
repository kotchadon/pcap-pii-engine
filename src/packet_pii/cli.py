"""CLI entrypoint: local analysis with private, atomic JSON output."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import AnalysisLimits, analyze_to_report
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
                        help='Opt in to experimental BiLSTM using a local checkpoint directory')
    parser.add_argument('--include-values', action='store_true',
                        help='Include raw detected data (SENSITIVE; local only)')
    parser.add_argument('--profile', choices=('standard','large','stress'), default='standard',
                        help='Explicit resource profile; Standard remains the default')
    parser.add_argument('--max-report-mib', type=int, default=None)
    parser.add_argument('--max-memory-mib', type=int, default=None)
    parser.add_argument('--max-findings', type=int, default=None)
    parser.add_argument('--max-capture-mib', type=int, default=None,
                        help='Override profile input limit in MiB (Standard: 128)')
    parser.add_argument('--max-packets', type=int, default=None,
                        help='Override profile packet limit (Standard: 100000)')
    parser.add_argument('--max-flows', type=int, default=None,
                        help='Override endpoint-pair and session limit (Standard: 20000)')
    parser.add_argument('--max-tcp-mib', type=int, default=None,
                        help='Override profile TCP payload MiB (Standard: 64)')
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
        overrides = {}
        for arg,field,multiplier in (
            ('max_capture_mib','max_capture_bytes',1024*1024),
            ('max_packets','max_packets',1), ('max_flows','max_flows',1),
            ('max_tcp_mib','max_tcp_payload_bytes',1024*1024),
            ('max_report_mib','max_report_bytes',1024*1024),
            ('max_memory_mib','max_memory_bytes',1024*1024),
            ('max_findings','max_findings',1)):
            value=getattr(args,arg)
            if value is not None:
                overrides[field]=value*multiplier
        limits = AnalysisLimits.for_profile(args.profile,**overrides)
        model = load_experimental_bilstm(args.ml_checkpoint) if args.ml_checkpoint else None
        report = analyze_to_report(input_path,output_path,args.threshold,args.include_values,
                                   profile=args.profile,limits=limits,overwrite=args.overwrite,
                                   ml_detector=model)
        if args.include_values:
            print('WARNING: report contains unmasked PII/credentials; restrict its distribution.',
                  file=sys.stderr)
        print(f"Analysed {report['summary']['packets_captured']} packets, "
              f"{report['summary']['flows_processed']} TCP flows, "
              f"{report['summary']['http_messages']} HTTP messages, "
              f"{report['summary']['potential_leaks']} potential PII findings. "
              f"Report: {args.output}")
        return 0
    except (OSError, ValueError, TypeError, ImportError, RuntimeError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
