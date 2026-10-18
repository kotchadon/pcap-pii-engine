# Unified TRACE demonstration

Integration starts at main `c6098d879466636678fb0a40e7f21b5d0d68f0aa` and selectively
ports showcase branch `86ad30335e9516b9deb7d10ec5849f3304c1bb55`.
PRs 12 and 13 are unchanged. This branch deliberately reconciles orchestration;
it does not replace the PR11 large-file engine with the older hybrid pipeline.

## First runnable checkpoint (A/B)

One shared engine supports rules-only and optional BiLSTM through `analyze()`
and atomic `analyze_to_report()`. Standard/Large/Stress, compact packet retention,
M3C session/safe-prefix reconstruction and private bounded reporting remain.
ML errors fail the scan; no requested hybrid scan silently falls back to rules.

The dashboard includes the actual 12-conversation PCAP generator, masked finding
inspector, client-disconnect handling and live per-scan ML accounting. Research
metrics are read from versioned evaluation JSON and checked against the model
manifest. They are not live-upload accuracy. The How TRACE Works page explains
supported behavior at two levels.

## Mac commands

Use the user's full checkout; preserve any uncommitted work before switching.
From the repository root:

```bash
git fetch origin
git switch --track origin/feature/trace-unified-vp-integration
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[ml]' pytest
python -m pytest -q tests/test_unified_engine.py tests/test_hybrid_integration.py tests/test_dashboard.py tests/test_dashboard_scan_modes.py tests/test_hybrid_dashboard.py tests/test_showcase_live_evidence.py tests/test_dashboard_disconnect.py tests/test_large_capture_performance.py
python -m packet_pii.dashboard --port 8765 --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2
```

Open http://127.0.0.1:8765/. Select AI-assisted hybrid explicitly, run the
12-conversation showcase, inspect actual returned predictions if present, and
compare a rules-only run. Loaded, invoked and prediction-found are distinct
states. Nothing requires network transmission of capture data.

For the exact 110 MiB capture through the full bounded rules CLI:

```bash
pcap-pii /path/to/trace_synthetic_110MiB.pcap --profile large -o trace-110.json
```

The CLI supports optional `--ml-checkpoint`. Hybrid inference is bounded to
10,000 fields / 2,000,000 characters per scan. Counts expose all skipped eligible
fields, and skipped work marks analysis incomplete. A complete large rules scan
is not proof that full 110 MiB hybrid inference ran.

## Validation limits

Cloud tests can execute CPU PyTorch, but authentic committed model.pt files and
v2 train.jsonl.gz could not be materialized here. Their Git entries are unchanged.
Mock-model tests verify integration, not model quality. Real V2 showcase output
must be measured using the complete checkout; no prediction counts are invented.
Linux timings must not be presented as Mac M3 measurements.

The original showcase guide describes its source branch. This document supplies
the integrated launch instructions and supersedes those branch-specific commands.
