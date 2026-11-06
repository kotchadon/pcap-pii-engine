# TRACE — Network Privacy & Evidence Explorer

**A local-first cybersecurity project for finding personal information in recorded network traffic — and showing exactly where it appeared.**

I started TRACE because a list of detected emails or passwords isn't particularly useful if you can't explain where those values came from. I wanted a tool that could read a packet capture, piece together the conversations inside it, identify information worth investigating, and take that finding all the way back to the original network evidence.

That idea has grown into a working Python-based analysis engine with a browser dashboard, structured reports, packet-level investigation and an experimental machine-learning detector.

## What TRACE does

TRACE examines PCAP and PCAPNG recordings, reconstructs supported TCP and HTTP traffic, and looks for personal information in readable web requests and responses. Rather than treating detections as isolated text matches, it connects them to the conversation, field and supporting packet evidence.

The current implementation includes:

- **Network reconstruction:** packet decoding, TCP conversation grouping and reassembly, with handling for retransmissions, out-of-order segments and incomplete recordings.
- **Personal-information detection:** pattern-based checks for emails, telephone numbers, payment card candidates, IP addresses, credentials, usernames, names and selected device or account identifiers.
- **Contextual AI:** an optional three-model BiLSTM V2 ensemble trained to identify names and usernames that simple field-name rules can miss.
- **An evidence Inspector:** a finding can be followed into its HTTP message, field metadata, source ranges and supporting original packets. Recovered HTML can be inspected as inert content where the recording supports it.
- **A local dashboard:** readable summaries, searchable findings, web conversations, technical evidence, coverage information and controlled report exports.
- **Reproducible testing:** fictional network captures, verification against the original packet bytes, automated regression tests and ground-truth evaluation with independently labelled examples.

A major design decision is to keep the network evidence separate from the detection claim. TRACE should be able to explain both **what it noticed** and **what the recording actually proves**.

## How it's built

The core pipeline is written in **Python**, with bounded packet processing and HTTP reconstruction feeding a rules engine and optional **PyTorch BiLSTM** inference. The browser interface runs locally; **SQLite** provides searchable evidence and result indexing, while JSON reports preserve structured findings and their provenance.

The machine-learning system is deliberately separate from the rule-based checks. That makes it possible to compare their results, track which fields the model examined and distinguish an incomplete analysis from a clean scan.

Key areas of the codebase include the capture/HTTP processing engine, detection rules, model inference and evaluation, report and evidence handling, and the dashboard/Inspector.

## Detection quality and what the numbers mean

The current **V2 BiLSTM ensemble** achieved **81.8% exact-span F1** on a held-out, out-of-generator **synthetic** challenge covering names and usernames. This is an evaluation of that specific model and dataset — **not an 81.8% accuracy claim for arbitrary packet captures**, and not a score for every kind of personal information TRACE reports.

A finding is a lead to investigate, not proof that a breach or exfiltration occurred. Model scores are not calibrated probabilities. File-specific accuracy can only be reported when the capture has matching independently verified ground-truth annotations.

[Read the V2 evaluation](docs/ml/V2_EVALUATION.md) · [Ground-truth evaluation approach](docs/ml/GROUND_TRUTH_EVALUATION.md)

## Where the project stands

TRACE is an **active research and engineering prototype**, not a commercial forensic product.

The reconstruction, detection, dashboard and evidence-inspection workflows are implemented. The work still in progress is mainly about **large-capture reliability, report storage, processing speed and broader detection quality**. The higher AI-field settings are bounded processing allowances, not a promise that every large recording can finish within those limits. A V3 detector is being explored separately; the existing V2 remains the reference until a replacement is properly validated.

TRACE does not magically decrypt HTTPS. Encrypted payloads, missing packet data and unsupported protocol features limit what can be recovered. HTTP support is intentionally bounded, and a completed analysis of readable traffic is not proof that every byte in the recording was interpreted.

For the technical investigation work, see the [packet-to-HTTP mentor demonstration](docs/integration/MENTOR_DEMO_COMPLETION.md) and the [detection taxonomy](docs/integration/PII_DETECTION_TAXONOMY.md).

## Why this project matters to me

TRACE has been an opportunity to work across different parts of security engineering rather than stopping at detection rules: network protocols, Python systems design, machine learning, data provenance, local privacy controls, performance profiling, automated testing and user experience.

The part I care most about is **trustworthy evidence**. A useful security tool should not just produce an impressive-looking result; it should be able to show what it examined, identify its limitations and let someone verify the finding for themselves.

---

*TRACE is intended for authorised analysis and research. Test data in this repository is fictional; real packet captures and exported personal information should be handled privately and with permission.*
