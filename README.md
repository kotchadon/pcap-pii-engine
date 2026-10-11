# PCAP PII Engine

**Private, local-first cybersecurity prototype** that scans reconstructed **plaintext HTTP/1.x** over TCP in `.pcap` or `.pcapng` and emits a JSON report containing possible PII exposure.

> **Status: v0.1 / engineering baseline, NOT production-ready and NOT yet ML-based.** Rule-based confidence scores are *heuristic*, not calibrated probabilities. A finding indicates that sensitive data may have been transmitted; it is **not by itself proof of a leak/exfiltration**.

## Architecture

```
PCAP/PCAPNG reader → Ethernet/IP/TCP decoding → TCP flow grouping
→ TCP payload reassembly (out-of-order and retransmissions)
→ HTTP/1.x message parsing → headers, URL query, JSON/form/body extraction
→ rule-based PII detector → masked findings → JSON report
                         ↳ planned: ML entity recogniser / BiLSTM evaluation
```

## Run locally on macOS

Requires **Python 3.10+**. Core prototype uses only Python's standard library.

```bash
# Inside the extracted project directory
python3 examples/generate_demo.py demo.pcap
PYTHONPATH=src python3 -m packet_pii.cli demo.pcap --output demo-report.json
```

Now open `demo-report.json` with VS Code or run:

```bash
python3 -m json.tool demo-report.json
```

Also test PCAPNG:

```bash
python3 examples/generate_demo.py demo.pcapng
PYTHONPATH=src python3 -m packet_pii.cli demo.pcapng --output demo-ng-report.json
```

Optional editable install + tests (requires `pip` and `pytest`):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e . pytest
pytest -q
```

After installing, the CLI also works with `pcap-pii demo.pcap -o demo-report.json`.

### CLI options

- `--threshold 0.8`: ignore detections with heuristic score below 0.8
- `--output report.json`: location of report
- `--include-values`: **SENSITIVE**: include complete detected secrets/PII. **Never use on real captures unless expressly approved and handled securely.** By default, values are masked and fingerprinted.

## What works (and what doesn't)

| Feature | Status |
|---|---|
| Classic PCAP + PCAPNG (enhanced packet blocks) | Implemented, basic Ethernet/raw IP/Linux cooked support |
| IPv4, basic IPv6 TCP decoding | Implemented, limited |
| TCP streams, out-of-order packets, retransmissions | Implemented for contiguous payloads and non-wrapping sequence numbers |
| HTTP/1.x requests and responses | Implemented for common Content-Length and chunked cases |
| URL query, JSON, URL-encoded/multipart forms, headers | Implemented for common text payloads |
| gzip/deflate bodies | Implemented with output size cap |
| Email/IP/phone/card/credential/username/structured name candidates | Implemented as rules and validators |
| Confidence threshold + structured JSON report | Implemented; scores are heuristics, not calibrated probabilities |
| Contextual ML, BiLSTM, training and validation | **NOT implemented yet** |
| TLS HTTPS without session keys, HTTP/2, HTTP/3 | **NOT supported** |
| IP fragmentation, TCP seq wrap, repeated connection tuple/session separation | **NOT supported** |
| Production-grade HTTP framing, large-scale streaming, comprehensive evasion handling | **NOT supported** |

The parser **skips malformed and incomplete traffic** rather than treating it as complete. Its output is not a forensic guarantee.

## Security and data-handling

- `.pcap`, `.pcapng`, and `*report.json` are excluded by `.gitignore`.
- Never commit real captures, API keys, credentials, or raw leak reports.
- Use synthetic samples and test-card numbers for development.
- Prefer scanning locally; only upload approved, sanitized test artefacts.
- Masked values still contain metadata that can be sensitive; keep reports private.

## Project structure

```
src/packet_pii/
  capture.py      # PCAP / PCAPNG and TCP parsing & reassembly
  http_extract.py # HTTP messages and fields
  detect.py       # PII rule-based baseline
  engine.py       # pipeline and report generation
  cli.py          # command line
examples/
  generate_demo.py # fake-PII capture generator, does NOT capture live traffic
tests/
  test_pipeline.py
PLAN.md            # milestones and validation tasks
```

## Test and compare in Wireshark

Generate `demo.pcap`, open it in Wireshark, use `tcp.stream eq 0`, and click **Follow → TCP Stream**. Compare reconstructed HTTP text and fields with `demo-report.json`. This helps verify the code, not just trust an AI-generated result.
