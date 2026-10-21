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
- `--include-values`: **SENSITIVE**: include complete detected secrets/PII. **Never use on real captures unless expressly approved and handled securely.** By default, values are masked. Reports do not export unkeyed secret fingerprints.
- `--max-capture-mib`, `--max-packets`, `--max-flows`, `--max-tcp-mib`: cap file size, total records, endpoint-pair flows and buffered TCP payloads. Defaults: 128 MiB, 100000, 20000, and 64 MiB respectively. Exceeding a limit aborts without publishing a partial report.
- `summary.analysis_incomplete`: true if corruption/truncation was observed or reconstructed TCP data has gaps. See `summary.capture_truncated_records` and `summary.capture_malformed_records`. Details: `docs/milestone3b-input-robustness.md`.

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
| Advertising IDs (IDFA/GAID), explicitly transmitted age, gender/sex, device and account IDs | Context-validated deterministic rules; see [`PII_DETECTION_TAXONOMY.md`](docs/integration/PII_DETECTION_TAXONOMY.md) |
| Network Evidence v2 | Verified capture hashing, packet-to-stream provenance, HTTP field source mapping and redacted Inspector; higher report-storage requirements apply |
| Confidence threshold + structured JSON report | Implemented; scores are heuristics, not calibrated probabilities |
| Contextual ML (BiLSTM V2, opt-in via `--ml-checkpoint`) | Implemented, **experimental**; bounded work budgets with explicit coverage accounting (see below) |
| Encrypted TLS HTTP/2 or HTTP/3/QUIC | Not decrypted or decoded; only authorised plaintext/decrypted application data can be inspected |
| TCP sequence wraparound, repeated connection tuples | Handled (reused tuples are split into separate flows) |
| IP fragments / IPv6 extensions / plaintext HTTP/2 | Bounded, conservative support in Network Evidence v2; malformed/unsupported traffic still accounted for |
| Production-grade HTTP framing, large-scale streaming, comprehensive evasion handling | **NOT supported** |

The parser **skips malformed and incomplete traffic** rather than treating it as complete. Its output is not a forensic guarantee.

## Contextual ML coverage and ground-truth evaluation

Hybrid mode runs the experimental BiLSTM V2 over every eligible extracted field (headers and credential fields are excluded by policy) in bounded, batched inference. Work is limited by a validated profile, selected with `X-ML-Coverage` in the dashboard (the *ML coverage* selector) or `ml_budget=` in the API:

| Profile | Eligible fields | Characters | Model time |
|---|---|---|---|
| `standard` (default) | 10,000 | 2,000,000 | 60 s |
| `extended` | 100,000 | 20,000,000 | 300 s |
| `complete` | 1,000,000 | 200,000,000 | 1,800 s |

There is no unlimited mode. Every eligible field is either evaluated or counted as skipped with a reason; `summary.ml_coverage_status` is `not_requested`, `no_eligible_fields`, `complete` or `partial` (a mid-scan model failure publishes nothing). Partial coverage sets `analysis_incomplete`, and the Model laboratory shows e.g. *"ML coverage limit reached. Analysed 10,000 of 88,192 eligible fields (11.3%). Results are incomplete."* Measured on this repository's synthetic 108,012-eligible-field capture: `standard` 4.6 s (partial, 9.3%), `complete` 40 s (complete) on the development machine.

File-specific precision, recall and F1 exist only when an independent, SHA-256-verified ground-truth manifest for that exact capture is supplied (`schemas/ground-truth-v1.schema.json`):

```bash
pcap-pii-evaluate examples/groundtruth/controlled_fixture_v1.pcap \
  examples/groundtruth/controlled_fixture_v1.manifest.json \
  --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2 -o evaluation.json
```

Without a manifest, TRACE reports no accuracy for an uploaded file. The 81.8 % offline F1 is a different, synthetic benchmark. Method, the controlled fixture and measured V2 results: `docs/ml/GROUND_TRUTH_EVALUATION.md`; engineering handover: `docs/integration/HANDOVER_ML_COVERAGE_GROUNDTRUTH.md`.

### Automated model quality assessment (synthetic probes)

After every AI-assisted scan the dashboard automatically runs a small, bounded, local assessment: fictional, labelled probes (names, usernames, hard negatives) built from a privacy-safe structural summary of the capture are scored with the real V2 model. The result is called **Context-matched synthetic probe F1** and is *not* the accuracy of your capture (no values or field names from it are used). It is shown in Model laboratory → Automated Model Quality Assessment, separate from live coverage, from manifest-based ground-truth evaluation, and from the offline benchmark. `--assessment-probes 0` disables it. Details: `docs/ml/AUTOMATED_MODEL_QUALITY_ASSESSMENT.md`.

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
