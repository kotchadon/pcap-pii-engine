# TRACE VP showcase — reproducible synthetic network investigation

## What the demo button really does
**Run 12-conversation showcase** calls `POST /api/showcase`. The local server invokes
`examples/generate_showcase.py` to create a reproducible, fictional classic-PCAP
file in a temporary directory. It then invokes the SAME
`packet_pii.engine.analyze()` pipeline used for user-uploaded PCAP/PCAPNG files.
No finding, HTTP count, model prediction, rule result, score or flow record is
hardcoded by the showcase handler. The temporary PCAP is deleted afterwards.

The legacy `POST /api/demo` remains available as an 8-packet regression fixture.
The current dashboard button uses `/api/showcase`, not the legacy demo.

## What you can show
- Reconstructed conversations across 12 different endpoint pairs.
- Actual HTTP requests/responses, including one form post, a chunked request and
  a gzip-compressed response.
- Deterministic-rule findings in fictional emails, an Australian-style mobile,
  Luhn-valid test-card data, credentials, explicit `username` and `full_name` fields.
- Contextual-candidate fields `json_body.shipping.recipient` =
  `Priyanka Venkataraman` and `json_body.audit.actor` = `night_owl_77`.
  These are examples from the model's separately shipped V2 demo, NOT promises
  that every scan or future checkpoint will yield positive predictions.
- Hard negatives/uncertain fields `Johnson & Johnson` and `Madison`; if flagged
  as a person, call it a false-positive candidate. Never suppress it to improve
  presentation numbers.

## Model status is not a model result
- **Model ready** = the trained V2 checkpoint loaded.
- **AI invoked** = `analyze(..., ml_detector=...) ` was called for that scan.
- **ML fields evaluated** = real count of eligible extracted fields passed to model.
- **ML findings** = real count of contextual entity spans returned after filtering.
- **ML=0** is possible even when inference ran successfully: zero predictions
  does not prove either a broken model or complete privacy of the capture.

## Why a finding appeared
The **Inspect** action uses provenance already present in the actual report:
PII type, location, original HTTP-message identifier, TCP flow, endpoints,
detector, raw/heuristic score type and model span offsets (when available).
For rules, it explains the class of deterministic field/pattern/validation.
For ML, it identifies the predicted span and contextual field, **without claiming
a causal explanation of internal neuron attention or learned features**.

## Two ways to explain this
**Plain language**: A PCAP is a recording of network messages. TRACE joins
packets, reads supported HTTP content, looks for personal information, and
shows masked examples and where they were found. It does not prove a breach.

**Technical**: Capture ingestion -> IPv4/TCP decoding -> endpoint grouping and
per-direction TCP reassembly -> HTTP/1.x parsing and field extraction ->
structured rules + optional contextual BiLSTM V2 sequence tagging -> redacted,
provenance-bearing findings with explicit processing limitations.

## Accuracy: what is measured and what is not
This live file has **no independently annotated ground truth**, so live
precision, recall, F1 and accuracy are **not measurable** from it.
The fixed numbers displayed further down the Model Laboratory are a separate
research result on a 1,058-field frozen **synthetic challenge**:
V2 precision 0.836, recall 0.801, exact-span micro-F1 0.818 (95% CI
0.794–0.840). Those figures **are not computed from the uploaded PCAP**.
Scores attached to individual ML predictions are uncalibrated, not probabilities
of correctness. See `docs/ml/V2_MODEL_CARD.md`.

## Run on Mac
```bash
cd ~/Downloads/pcap-pii-engine
source .venv/bin/activate
git fetch origin
git switch --track origin/feature/vp-live-evidence-showcase
python -m pytest -q tests/test_showcase_live_evidence.py tests/test_dashboard.py tests/test_dashboard_scan_modes.py tests/test_hybrid_dashboard.py
python -m packet_pii.dashboard --port 8765 --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2
```
Open `http://127.0.0.1:8765/`, leave Terminal running, select
**AI-assisted hybrid** and click **Run 12-conversation showcase**.
Then inspect a contextual finding if present, compare Rules-only mode, and
demonstrate the distinction between live evidence and offline evaluation.

To create the same PCAP manually for an upload (no model or backend required):
```bash
python examples/generate_showcase.py ~/Downloads/trace-vp-showcase.pcap
```

Do not merge PR #11's separate rules-only `engine.py` into this
hybrid-enabled engine without a deliberate integration pass; its
`analyze_to_report` API currently does not support optional ML inference.

## Known limitations
This is a local-first research demonstration of supported plaintext HTTP/1.x.
It is not a production forensic tool; does not decrypt HTTPS; does not claim
HTTP/2/HTTP/3 or comprehensive UDP inspection; and cannot establish genuine
breaches, user consent or live-dataset model accuracy.
