# Engineering plan: 14-day project window

## Objective
Produce a reproducible pipeline that identifies **potential PII exposure** in reconstructable HTTP messages and reports provenance. Avoid claims of completeness, actual exfiltration, or calibrated confidence without evaluation.

## Phase 1 — reproducible data/ingestion (days 1–3)
- Confirm sample data permissions, HTTP version, TLS visibility, PII classes, output contract.
- Establish private repository, tests and synthetic PCAP/PCAPNG generator.
- Packet parsing, per-direction TCP reassembly, retransmissions, out-of-order tests.
- Acceptance: synthetic PCAP and PCAPNG give identical logical findings; malformed file does not crash.

## Phase 2 — HTTP decoding (days 4–6)
- Parse HTTP/1.x request and response streams, headers, query, JSON, forms, compression.
- Track flow ID, timestamps, source/destination and original HTTP field locations.
- Test multi-message streams, chunking, compression, retransmissions and incomplete content.
- Acceptance: explicit test examples recover each required field type and the location.

## Phase 3 — baseline and ML validation (days 7–10)
- Rules: validated emails, phone patterns, IPs, Luhn card checks, contextual credential field keys.
- Collect or obtain authorized, **labelled** text/HTTP examples before training ML.
- Add pretrained NER baseline for contextual PERSON/locations, compare precision/recall/F1.
- Only use BiLSTM if there is a suitable dataset and an explicit evaluation reason; no invented accuracy.
- Evaluate threshold behaviour and false positives; calibrate score where feasible.

## Phase 4 — report, resilience, demo (days 11–14)
- JSON schema + risk-sensitive value masking, unique finding IDs, reproducible CLI.
- Expand tests to include corrupted payloads, deliberately missing segments and mixed protocols.
- Benchmark sample capture size and run time; document what cannot be decrypted.
- Deliver local demo, tests, example report, limitations, next-step backlog.

## Immediate blockers to resolve with mentor

1. **Input traffic**: plaintext HTTP/1.x, decrypted HTTPS, or arbitrary TLS-only PCAPs?
2. **ML expectation**: must a BiLSTM be trained, or is a pretrained NER/hybrid ML approach acceptable?
3. **Acceptance**: minimum PII classes, sample/labelled dataset, target precision/recall, and runtime constraints?
4. **Privacy**: may reports contain full PII values, or should they be redacted by default?
5. **Date**: exact delivery deadline and what counts as MVP completion?
