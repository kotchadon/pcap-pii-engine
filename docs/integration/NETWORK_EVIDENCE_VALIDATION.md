# Network evidence validation and reproducibility

This is an integration candidate requiring review. A green count alone is not an
acceptance argument. The checks separately establish source identity/mapping,
privacy, protocol behavior, resource failure semantics, unchanged legacy outputs,
and the limits imposed by missing artifacts. Final measurements are recorded in
`results/network_evidence_validation.json` and the benchmark/comparison JSON files.

## Reproduce

Use Python 3.12, the repository's existing test dependencies and optional HPACK:

```sh
python -m pip install -e '.[http2]'
python -m pip install pytest 'ijson>=3.3,<4'
OMP_NUM_THREADS=1 python -m pytest -q
python scripts/validation/benchmark_engine.py capture.pcap report.json --profile large
python scripts/validation/benchmark_engine.py capture.pcap evidence-report.json --profile large --max-report-mib 2048
python scripts/validation/compare_network_reports.py baseline-report.json evidence-report.json
```

Use fresh output paths; publication is exclusive unless explicitly overwritten.
The 2 GiB override is intentional and must be budgeted: default Large retains its
existing 1 GiB report cap. Full evidence for millions of fields is materially
larger than findings alone. A report-budget failure publishes no partial success.
Run each performance command in a fresh process, without competing benchmark/test
workloads. RSS is process peak, not a claimed instantaneous allocation limit.
Generated fixtures are fictional; no private traffic was uploaded or used.

The controlled fixture is generated with
`python examples/generate_groundtruth_fixture.py NEW_SCRATCH_DIRECTORY`. Verify
its SHA-256 against the committed manifest before using it; do not overwrite the
frozen manifest. The baseline checkout lacked that binary; it was restored locally
only after exact manifest-hash verification. Model checkpoint and V2 training-data
binaries remained unavailable, so real-model test failures are reported rather
than skipped, replaced with test doubles, or represented as successful validation.
Test doubles in integration tests are labelled and establish interface/provenance
behavior only. They do not establish model quality, accuracy or real inference.

## Evidence-based acceptance checks

| Claim | Independent check |
|---|---|
| Actual capture identity | SHA-256 over independently read original bytes, mutation during analysis, complete malformed-tail hashing, no identity on unfinished iteration |
| Exact provenance | Independently constructed PCAP/PCAPNG bytes; reconstruct original file slices using exported joins across reordering, retransmission, overlap, wrap and fragments |
| Honest transformations | Unicode character/byte distinction; compressed, escaped, percent-decoded, multipart, chunked and HPACK cases must never claim raw detection offsets |
| Privacy | Whole serialized reports, evidence, callback/progress payloads and API responses checked for fictional raw sentinels; no value hashes added |
| Resource behavior | Existing report atomicity, cancellation, RSS/payload/frame/flow limits plus IP/HTTP2 caps; excessive evidence fails rather than truncates silently |
| Evaluation provenance | Controlled change between prehash and actual parse must reject manifest evaluation while retaining the correctly identified report |
| Protocol completeness | HEAD/CONNECT/1xx, earlier orphan responses, ambiguous/incomplete tails, fragments, extension chains, H2 continuation/settings/reset/trailer/interim-only cases |
| No finding regressions | Compare every original finding/flow field on fixed fixtures; only additive finding evidence is excluded from the semantic digest |
| ML preservation | Existing batching, disposition, identity and budget tests; model source/weights/thresholds/frozen datasets untouched |

`tshark` is unavailable in this environment. No Wireshark differential validation
is claimed. Manual byte oracles and available independent parser tests are useful
checks, but do not substitute for a future external PCAP conformance corpus.
No real-world precision/recall or encrypted-traffic inspection result is claimed.

## Review gates and remaining limits

Review the evidence contract before frontend work. Compare same-hash captures and
exact source ranges, not timestamp proximity. Budget the additional disk and CPU
cost. Restore authenticated model/data artifacts and rerun the failed real-model
gates before any claim of full regression qualification. The original suite's
artifact failures remain blockers even when all newly executable checks pass.

The branch intentionally does not add raw-byte retrieval, retained TLS keys,
HTTPS decryption, QUIC/H3, h2c upgrade, arbitrary HPACK settings or unsupported
PCAPNG packet-block parsing. Sparse or adversarial captures can remain ambiguous;
handshakes, closed streams and `analysis_incomplete=false` do not prove capture
completeness. IPv6 overlap rejection is conservative; fragment identity quarantine
has a finite horizon. HTTP/1 pairing remains best-effort. Evidence source intervals
select supporting bytes, not every retransmitted copy or a court-certified chain
of custody.

## Measured results

Measurements use exact input hashes and fresh processes. Performance includes report writing; ML is disabled.

| Workload | Baseline seconds | Evidence seconds | Peak RSS MiB | Evidence report MiB | Original findings |
|---|---:|---:|---:|---:|---:|
| small | 0.022 | 0.105 | 16.75 | 0.66 | 18 |
| showcase | 0.015 | 0.038 | 16.38 | 0.16 | 19 |
| medium | 1.470 | 3.430 | 29.75 | 24.34 | 1986 |
| large | 43.994 | 138.979 | 414.11 | 1453.78 | 244046 |

Every original flow and finding field matched the baseline on all four inputs (additive finding evidence excluded).
The large workload requires the explicit 2 GiB report budget; the default 1 GiB cap remains unchanged. This is a material storage/CPU regression relative to findings-only reports, disclosed for integration review.

Full baseline: **552 passed, 24 failed, 77 errors, 3 skipped**. The full candidate run exposed four new schema/diagnostic expectation failures, subsequently corrected. After excluding the 98 already-observed artifact-dependent failures, the broad executable run recorded **652 passed, 1 failed, 4 skipped**; its remaining legacy diagnostics assertion was corrected to verify the new hash/length/status fields. The final two targeted checks (that byte oracle and an actual JSON Schema validation) both passed. No remaining new failure was observed; the complete real-model suite is not qualified.

The small controlled fixture and medium capture can be regenerated from committed scripts; the medium uses `--size-mib 5 --seed 20261014`. Showcase uses `examples/generate_showcase.py`. The large input reuses the existing synthetic 110 MiB fixture with the SHA recorded in the machine results; its original generation provenance was not reconstructed in this turn. Reproduction of that benchmark requires the same-hash fixture.

Runtime/source revision measured: remote commit `355c669f513db7d4701368040843f74e0d68fd0d`, tree `f208339e98a57a7d00d1082159b90e20db8069ae`. The subsequent validation commit changes documentation/results only.
