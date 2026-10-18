# Sunday VP demo — Experimental BiLSTM + capture dashboard

## What this patch implements

Connects the **existing**, independently trained model (PR #5) to the hardened
capture processing engine (Milestone 3B) via a new isolated module `hybrid.py`.
The model code, checkpoint and evaluation results are not modified or retrained.
Adds `--ml-checkpoint` opt-in to both the command-line interface and the loopback
TRACE dashboard. No external services. Default remains **rules-only**.

Analysis flow (for supported plaintext HTTP/1.x):

    PCAP/PCAPNG → bounded frame reading → TCP reassembly → HTTP extraction
     ├── rules (formatted PII + field-aware findings, heuristic scores)
     └── experimental BiLSTM (PERSON_NAME / USERNAME, raw uncalibrated scores)
              → separate, masked findings, original offsets, flow/message provenance
              → JSON report and local UI

Scores are never averaged or combined; the **potential_leaks** count is a
count of detection *signals* and can double-count the same value across the
two detectors. It does **not** prove leakage or exfiltration. Each entry
identifies its detector, and ML entries carry `model_version`, `span_start`,
`span_end`, `field_index`, `confidence_type`. The summary separately counts
`rules_findings`, `ml_findings`, `ml_fields_evaluated`,
`ml_fields_excluded_by_policy` and `ml_fields_skipped`.

### False-positive containment policy

The pretrained tagger exhibited unsupported USERNAME predictions from email
addresses and password strings in the synthetic traffic example. To avoid
presenting those as a reliable new capability, the integration sends only
contextual candidate fields to ML. **HTTP headers and obvious structured
credential/contact fields** (e.g. password, token, email, card, phone, IP)
remain covered by rules and are excluded from experimental ML, with counts.
Oversized textual fields are skipped and counted, never silently truncated.
This gating is engineering hygiene, **not a measured precision improvement**.

## Prerequisite branches

1. Merge and verify `feature/input-robustness` into `main`.
2. Review and merge Claude's `feature/ml-bilstm-v1` PR #5 into `main`.
   Its model weights `src/packet_pii/ml/artifacts/bilstm_v1/model.pt`
   must be present.
3. Apply this ZIP to a **clean new branch from the combined `main`**.
   The ZIP contains **only our files** and deliberately never replaces ML
   model code or its checkpoint.

## Mac setup and demonstration

    cd ~/Downloads/pcap-pii-engine
    source .venv/bin/activate
    python -m pip install -e '.[ml]' pytest
    python -m pytest -q

Rules-only:

    python -m packet_pii.dashboard --port 8765

Opt in to real experimental model:

    python -m packet_pii.dashboard --port 8765 \
      --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v1

Open `http://127.0.0.1:8765` in a browser. Click **Use synthetic demo**.
The bundled synthetic example contains 8 frames and 2 HTTP messages. In our
verified environment it yielded 7 rules + 1 BiLSTM finding (Alex Example),
with defaults preserving masks. Results can vary if the underlying model
checkpoint is replaced. Check the **Model Laboratory** tab: the 0.756 F1
shown there is an *offline synthetic held-out benchmark*, **not** the
accuracy of the uploaded capture.

The equivalent CLI is:

    python examples/generate_demo.py demo.pcap
    python -m packet_pii.cli demo.pcap --output demo-hybrid.json \
      --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v1

Do not enable `--include-values` for a demo shared with other people.

## Checks and limitations

- Verified against the Claude ML archive + hardening patch + first dashboard:
  synthetic PCAP → model load/checkpoint → rule and BiLSTM entries → report,
  and HTTP-level dashboard demo endpoint. Full test suite verified separately.
- Rules-only runtime never loads PyTorch.
- A dataset-derived benchmark does not validate real traffic/generalisation.
- No HTTP/2, HTTP/3, encrypted HTTPS payload inspection, IPv4 fragmentation,
  or general TCP reused-session separation.
- Dashboard binds **127.0.0.1 only**, masks by default, requires a session
  token for uploads and does not persist uploaded captures on disk.
- Malformed captures, resource budgets and incomplete records are addressed
  by Milestone 3B; this is not a streaming production analyzer.
- Very large (100–300 MB) stress-test input requires an explicitly enlarged,
  safely configured capture budget and separate resource/performance assessment.
  The default browser upload budget remains 128 MiB.
