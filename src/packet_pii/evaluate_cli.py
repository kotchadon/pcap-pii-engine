"""CLI: score one capture against an independent ground-truth manifest (file-specific precision / recall / F1)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .groundtruth import EvaluationRejected, ManifestError, evaluate_capture, export_result, load_manifest
from .ml_runner import ML_PROFILES


def _fmt(value) -> str:
    return 'n/a' if value is None else f'{value:.3f}'


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Evaluate TRACE against a verified ground-truth manifest for one capture')
    parser.add_argument('capture', help='Path to the PCAP/PCAPNG the manifest describes')
    parser.add_argument('manifest', help='Ground-truth manifest (schemas/ground-truth-v1.schema.json)')
    parser.add_argument('--output', '-o', default=None, help='Private JSON result path (refuses overwrite unless --overwrite)')
    parser.add_argument('--overwrite', action='store_true')
    parser.add_argument('--ml-checkpoint', default=None, help='Also evaluate the contextual model from this checkpoint directory')
    parser.add_argument('--ml-coverage', choices=ML_PROFILES, default='standard', help='Model work budget profile')
    parser.add_argument('--allow-partial', action='store_true',
                        help='Exit 0 even if some annotated fields could not be scored (the result is still marked partial)')
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        detector = None
        if args.ml_checkpoint:
            from .hybrid import load_experimental_bilstm
            detector = load_experimental_bilstm(args.ml_checkpoint)
        result = evaluate_capture(Path(args.capture), manifest, detector=detector, ml_budget=args.ml_coverage)
        if args.output:
            export_result(result, args.output, overwrite=args.overwrite)
        print(f"{result['manifest']['name']}: status={result['status']} "
              f"aligned={result['alignment']['aligned']}/{result['alignment']['manifest_fields']} "
              f"model={result['model_version'] or 'none'}")
        for name, system in result['systems'].items():
            micro = system['micro']
            print(f"  {name:17s} scored_fields={system['scored_fields']} TP={micro['tp']} FP={micro['fp']} FN={micro['fn']} "
                  f"P={_fmt(micro['precision'])} R={_fmt(micro['recall'])} F1={_fmt(micro['f1'])}")
        if result['status'] != 'complete':
            print('PARTIAL: some annotated fields were not scored; these are NOT full-file metrics.', file=sys.stderr)
            return 0 if args.allow_partial else 3
        return 0
    except (ManifestError, EvaluationRejected) as exc:
        print(f'Rejected: {exc}', file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, ImportError, RuntimeError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
