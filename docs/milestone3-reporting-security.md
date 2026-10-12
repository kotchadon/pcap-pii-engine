# Milestone 3A — Report provenance, privacy & local file safety

## Workstream ownership

**Non-ML only.** Changes are limited to the report boundary (`engine.py`, `cli.py`, new `reporting.py`), its test suite, documentation, and an extensible output schema. The rule detector (`detect.py`), TCP/HTTP implementations, and everything within the ML workstream remain untouched. The `analyze(path, threshold=0.8, include_values=False)` API remains unchanged, so Astra's proposed optional ML adapter can later be integrated by the host developer.

## Why this matters

A functioning PII detector can become another source of sensitive-data leakage if its outputs are unsafe. The prior exported JSON included a truncated, unsalted SHA-256 fingerprint of each raw value, even when masking was enabled. Low-entropy phone numbers, codes and short tokens can be guessed from such fingerprints. The CLI also used ordinary `open(..., 'w')`, which could leave world-readable reports depending on the user's umask and silently replace previous output.

## Implemented changes

1. `engine.analyze` **removes unkeyed `fingerprint` values from exported findings**, regardless of `include_values`. Internal detector fingerprints are unaffected; the ML team's detector implementation remains out of scope. No claim of cryptographic anonymization is made.
2. **Syntactically suspicious HTTP field locations are redacted in default reports.** JSON keys, multipart form names and URL parameter names are supplied by remote parties and can themselves contain PII. Ordinary field paths such as `json_body.customer[0].email` remain intact; suspicious/very long components are replaced with `[redacted-key]`. Keys containing `@` or control characters have their entire untrusted suffix collapsed. With `--include-values`, the raw location is preserved by explicit request. This filtering is a privacy improvement, not a complete sanitizer for every possible secret-like key.
3. `reporting.write_private_report` creates JSON reports with POSIX **0600** permissions. A temporary private file is fully written and fsynced before publication. Without `--overwrite`, exclusive linking prevents a pre-existing path or symlink from being overwritten even during concurrent writes. With `--overwrite`, atomic `os.replace` replaces the old path; it does not follow an existing symlink's target. Failed JSON serialization leaves no partial report behind.
4. The CLI **refuses to overwrite output files by default**; use `--overwrite` intentionally. It also rejects the input capture file as an output destination, even through canonical/symlink resolution. `--include-values` prints a warning without echoing PII to the console.
5. `metadata.report_schema_version` is now `1.0.0`, with a Draft 2020-12 JSON Schema in `schemas/report-v1.schema.json`. It defines stable required fields, confidence range, provenance fields, flow summaries and timestamps, while allowing additional optional ML findings/properties in a future reviewed integration.

## Verified test evidence (against the consolidated pre-ML codebase)

- Before this patch: **59 passed**.
- With this patch: **74 passed**, using `python -m pytest -q`. The added regression cases include no exported fingerprint, default-value masking, suspicious JSON-key masking in an end-to-end synthetic PCAP, private output permissions, deliberate overwrite policy, symlink protection, interrupted/invalid report serialization cleanup, output/capture alias prevention, JSON version contract, and explicit raw-value warnings.
- `jsonschema` 4.x was separately used to validate the example report against the draft schema; this is not a new required runtime dependency.

## Local demonstration

```sh
python -m pytest -q
python examples/generate_demo.py demo.pcap
python -m packet_pii.cli demo.pcap -o local-private-report.json
ls -l local-private-report.json  # POSIX mode -rw-------
python -m json.tool local-private-report.json
# Repeating the CLI command will now fail harmlessly unless --overwrite is added.
```

## Known limitations (NOT fixed by this patch)

- The **rules-only** confidence scores are heuristic, not calibrated probabilities; ML training/evaluation is a separate Work task. The `detection_method` metadata remains `rules_only` until actual integration.
- Masking is not a cryptographic security guarantee. `--include-values` deliberately exports raw PII for explicitly authorized local investigation; any resulting report needs strict handling. Endpoint IP addresses and capture timestamps remain present because the investigative requirement mandates them.
- Arbitrary raw field keys that resemble ordinary identifiers could still be sensitive. The exported location sanitizer reduces obvious leaks but cannot fully identify secrets by syntax alone.
- PCAP size, RAM usage, HTTP edge cases, TCP tuple reuse, sequence wraparound, encrypted HTTPS, and HTTP/2/3 remain separate pending milestones.
- File mode `0600` protects contents from other local user accounts on a standard POSIX filesystem. It does not secure backups, root access, synced directories, or an already compromised host. Parent directory access control remains the caller's responsibility.
- The schema is a **v1 interoperability contract**, not formal proof of traffic-decoding accuracy or ML quality. `additionalProperties` intentionally permits new model metadata.

## Branch and review boundaries

Create `feature/reporting-privacy` from a branch/commit already containing all 59 baseline tests. Apply this patch **without replacing other modules**. Verify 74 tests locally and in CI, push the feature branch, open a PR, and merge only after review. The ML developer should stay on `feature/ml-bilstm-ner`; no parallel edits to `src/packet_pii/ml/`, `training/`, `tests/test_ml_*` or `detect.py` are included here.
