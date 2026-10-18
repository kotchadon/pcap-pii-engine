> Historical source-branch notes. Current integrated commands, limits and status
> are in [integration/UNIFIED_VP.md](integration/UNIFIED_VP.md).

# TRACE — Sunday VP demonstration dashboard (first tested slice)

## Purpose
A **real**, loopback-only web interface for the existing PCAP PII Engine's rules-only analysis. Unlike a mock-up, its **Choose capture** and **Use synthetic demo** controls call the existing `packet_pii.engine.analyze()` function. There are no external APIs, CDN assets or analytics calls.

## Start (Mac / Python environment)

```bash
cd ~/Downloads/pcap-pii-engine
source .venv/bin/activate
python -m packet_pii.dashboard --port 8765
```

Open `http://127.0.0.1:8765/` in the same laptop's browser and select **Use synthetic demo**. The demo uses `examples/generate_demo.py`: an 8-packet synthetic PCAP, out-of-order segments, a retransmission, one gzip response, and seven masked rules-based PII findings. Alternatively choose a real locally available, authorised `.pcap` or `.pcapng` capture (up to 128 MiB).

The UI offers: capture metrics, PII-type breakdown, incomplete-analysis disclosure, searchable/type-filtered masked findings, source/destination metadata, flow inventory, JSON export, and a *separately labelled* model-lab screen for previously reported synthetic BiLSTM metrics.

## Exact security and model scope

- Local `127.0.0.1` listener **only**; no authentication appropriate for remote deployment. Do not expose on LAN or internet.
- Host, origin and random session token checks on mutating endpoints. Uploaded bytes are streamed to an ephemeral private temp directory and deleted after processing.
- Engine called with `include_values=False`. Sensitive raw request/response bodies are not returned to browser, except the masked findings in the JSON report. Nothing is uploaded to a third-party service.
- Resource defaults inherited from Milestone 3B: 128 MiB input, 100k packets, 20k flows, 64 MiB buffered TCP. Larger stress tests require a separately reviewed resource configuration; **not ready for a 300 MB upload**.
- Current dashboard and returned reports are **rules-only**. The model laboratory displays **external research benchmark numbers** from Claude's synthetic evaluation, not live capture inference.
- The UI neither promises exfiltration proof nor claims encryption support. HTTPS ciphertext, HTTP/2, IP fragmentation and packet/session edge cases remain out of scope.
- NOT production-ready for sensitive client captures: no authentication, quotas against parallel uploads, hardened reverse proxy, or robust performance measurements.

## Tests included

Run `python -m pytest -q` — four dashboard tests exercise served assets, CSP/headers, synthetic-demo packet analysis, actual binary upload, and refusal of cross-origin/tokenless/oversized requests.

## Next integration step

The user's **current GitHub `main` plus Claude's PR #5 ML code** are not accessible in this workspace. Rebase/apply these new-files-only dashboard additions on the latest combined branch, then implement a validated **optional ML adapter** and rerun the combined tests. Default to rules-only. Do not silently replace rule scores with uncalibrated ML confidences or claim 88% F1 without a new held-out evaluation.
