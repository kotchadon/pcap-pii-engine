# Milestone 3B — Bounded Input, Capture Diagnostics and Safe Failure

## Ownership / compatibility

Non-ML only: changes to `capture.py`, `engine.py`, `cli.py`, and the report schema;
new tests in `test_capture_robustness.py`. No changes to `detect.py`, ML
interfaces/models/training code, HTTP parsing, or existing tests. The normal
`analyze(path, threshold=0.8, include_values=False)` signature still works;
optional `limits=AnalysisLimits(...)` is keyword-only.

## What is implemented

- **Resource limits** (defaults for laptop-scale analysis): maximum 128 MiB
  regular-file capture; 100,000 packet records; 20,000 endpoint-pair flow keys;
  64 MiB aggregate captured TCP payload bytes. Individual PCAP records and
  PCAPNG blocks are limited to 16 MiB. This is bounded **input storage**, not
  constant-memory streaming. Decoded HTTP/report objects can increase memory use.
- Preflight rejects non-regular file paths (FIFO/device), invalid configured
  limits and captures above the configured file-size budget.
- Reported `capture_truncated_records` and `capture_malformed_records` count
  nonfatal invalid/trailing structures in both PCAP and PCAPNG. PCAPNG section
  trailer lengths are checked. Invalid EPB references/lengths and impossible
  timestamps are skipped and marked malformed. Malformed structure processing
  does not attempt risky byte-level resynchronisation.
- `summary.analysis_incomplete` is true on capture corruption/truncation or
  detected TCP reassembly gaps. Recovered findings **may not be exhaustive**;
  users must not treat them as all the data in a capture.
- Limit overflow raises `AnalysisLimitError` / `CaptureFormatError`. The CLI
  exits with code 1, writes an error to stderr without raw packet data, and
  **does not publish a partial report**.
- The applied limits are recorded in `metadata.analysis_limits` so a reviewer
  can distinguish a successfully processed bounded input from unsupported data.

## CLI: inspect the working result

Run from the repository with an activated virtual environment:

```bash
python -m pytest -q
python examples/generate_demo.py demo.pcap
python -m packet_pii.cli demo.pcap -o demo-robustness-report.json
python -m json.tool demo-robustness-report.json
```

In the report look for `analysis_incomplete`, the two capture diagnostic
counters, and `metadata.analysis_limits`. The healthy demo should be complete.

To demonstrate safe budget failure **without creating a report**:

```bash
python -m packet_pii.cli demo.pcap -o should-not-exist-report.json --max-packets 1
# Error: Capture exceeds configured packet limit
# Exit status: 1; no report file created
```

Optional switches: `--max-capture-mib`, `--max-packets`, `--max-flows`,
`--max-tcp-mib`. Increasing budgets consumes more memory; only increase for a
trusted system with available resources. All limits must be positive integers.

To see individual test cases:

```bash
python -m pytest -v tests/test_capture_robustness.py
```

## Tests and evidence

Reproduced 74 tests on the pre-ML Milestone 3A snapshot before changes. After
this patch: **101 passed** (74 existing + 27 new, including parameterized
cases), using Python 3.13 and `python -m pytest -q`. Tests cover input file,
packet, flow and buffered-TCP limits; invalid configuration; truncated PCAP
and PCAPNG; malformed headers/blocks; invalid interfaces; safe CLI failure;
nonblocking rejection of FIFO inputs; and analysis-incomplete provenance.

This snapshot **does not include** the independently developed Claude ML
interface branch. If 25 ML-interface tests are already merged into `main`, the
expected collected test count is **126**, provided no cross-branch regressions.
That 126 figure is an expectation, **not tested or confirmed here**.

## Important remaining limitations

- Still buffers TCP packets and decoded HTTP messages; this is **not** a
  constant-memory engine or a production-scale capture service. Peak memory
  requires benchmarking under realistic traffic.
- Malformed trailing records are treated as nonfatal and identified as
  incomplete, rather than rejecting all valid records collected earlier.
- Strict validation might reject unusual/nonconforming real-world captures.
  The parser only implements supported PCAP/PCAPNG block types/link layers.
- TCP 4-tuple reuse and 32-bit sequence wrap, IP fragmentation, HTTP/2/3,
  encrypted HTTPS payloads without decryption and full TCP session lifecycle
  handling remain separate scope.
- Counters show detected input corruption, not every unobserved packet loss.
  Absence of warnings is **not a forensic guarantee** of capture completeness.
- Do not process confidential PCAPs in third-party cloud tools without
  explicit authorization. Only fake/test data was used for these tests.
