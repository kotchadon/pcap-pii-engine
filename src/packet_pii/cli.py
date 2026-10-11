"""Local command line entry point."""
import argparse
import json
import sys
from .engine import analyze


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description='Analyse a local PCAP/PCAPNG for potential PII in plaintext HTTP/1.x')
    parser.add_argument('capture',help='Path to PCAP/PCAPNG file')
    parser.add_argument('--threshold',type=float,default=0.8,help='Minimum heuristic confidence (0..1)')
    parser.add_argument('--output','-o',default='report.json',help='Where to write JSON report')
    parser.add_argument('--include-values',action='store_true',help='Include raw detected data (SENSITIVE; local only)')
    args=parser.parse_args(argv)
    try:
        report=analyze(args.capture,args.threshold,args.include_values)
        with open(args.output,'w',encoding='utf-8') as file:
            json.dump(report,file,indent=2)
        print(f"Analysed {report['summary']['packets_captured']} packets, "
              f"{report['summary']['flows_processed']} TCP flows, "
              f"{report['summary']['http_messages']} HTTP messages, "
              f"{report['summary']['potential_leaks']} potential PII findings. Report: {args.output}")
        return 0
    except (OSError,ValueError) as exc:
        print(f'Error: {exc}',file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
