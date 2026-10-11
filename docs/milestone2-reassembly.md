# Milestone 2a — TCP reassembly correctness

## Goal

Before the PII detector sees any HTTP data, TCP payload segments must be ordered by sequence number and reassembled into contiguous bytes. Incorrect reconstruction can yield false findings or miss sensitive data.

## Scenarios tested

| Scenario | Expected result |
| --- | --- |
| Out-of-order segments | Reconstruct original bytes correctly |
| Exact retransmission | Ignore duplicate bytes |
| Partial overlapping retransmission | Deduplicate overlap and append new bytes |
| Missing middle segment | Stop at contiguous prefix and set anomaly flag |
| Observed SYN but missing initial data | Detect missing initial segment; don't assume later bytes start stream |
| Conflicting overlapping retransmission | Set anomaly flag; don't silently select contradictory bytes |
| Handshake without data | Empty application stream |
| Separate TCP flows (different source ports) | Distinct report flow IDs and findings |
| Missing HTTP request body segment | Never fabricate complete HTTP message or PII findings |
| Corrupt Ethernet frame | Ignore safely and continue processing valid packets |

## Implementation notes

`reassemble()` uses the first observed SYN's sequence number plus one as the expected initial application-data sequence when a SYN is present. Without an observed SYN, the capture may begin midstream; absence of a reported gap does **not** prove the complete flow was captured.

A `True` second return value denotes an unreconstructable condition (gap, conflicting bytes, unsupported size/ordering); the current report groups these under `stream_gaps`, which remains a simplifying limitation.

Remaining limitations: TCP 32-bit sequence wraparound, sessions reusing the same endpoint tuple, IP fragmentation, advanced TCP evasion/ambiguities, memory-bounded long-running analysis, and comprehensive HTTP protocol handling. The tests are intentionally **synthetic** and do not demonstrate general correctness against hostile real-world PCAPs.

## Local verification

```bash
python -m pytest -q
# Expect: 19 passed (9 original + 10 new) against the base starter
```

Never commit real PCAPs or full sensitive report values. Use `examples/generate_demo.py` and temporary synthetic captures only.
