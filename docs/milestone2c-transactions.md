# Milestone 2C — HTTP message provenance and conservative correlation

## Why this change exists

Earlier versions parsed each TCP direction independently. They assigned every
finding in a direction the timestamp of the first packet in that direction,
including the TCP SYN. They also lacked stable HTTP message IDs and did not
link server response findings to the originating client request.

This update keeps a decoded message's **start/end byte offsets** within its
reassembled TCP direction; maps the start byte back to the contributing TCP
segment's capture timestamp; and correlates HTTP/1.x request and response
messages conservatively.

## Added report fields

Every finding now includes:

- `http_message_id`: unique message ID within one reported flow.
- `http_request_id`: request ID for request findings and safely paired
  response findings; `null` if a response cannot be linked.
- `http_message_type`: `request` or `response`.
- `timestamp`: capture time of a packet carrying the first byte of that HTTP
  message, not the earliest packet (for example the SYN) in the conversation.

Summary and flow records include:

- `http_transactions`: completed request/final-response pairs.
- `unpaired_requests`: parsed requests without a safely paired final response.
- `unpaired_responses`: parsed responses that cannot be paired.

`http_messages` still counts parsed HTTP requests and responses individually.
An informational `100 Continue` can be linked to the pending request without
consuming it; `101 Switching Protocols` counts as the final response.

## Constrained matching

Pair only when one TCP direction contains HTTP requests and the reverse
direction contains HTTP responses. Pair FIFO, checking the first-byte capture
times so an earlier orphan response is not attributed to a later request.
Do **not** pretend this is complete transactional decoding: out-of-order capture
timestamps, lost messages, connection reuse, proxy traffic, protocol upgrades,
HTTP/2 multiplexing, and malformed streams can leave messages unpaired or make
pairings incomplete.

## Privacy

`http_start_line` now redacts URI path and query data by default. URI paths can
contain secrets and PII. `--include-values` must be explicitly enabled to
include the request path; query strings are never included in start-line
metadata. This flag also enables raw PII values: **do not use on sensitive
captures unless explicitly authorized**. Reporting is not proof of exfiltration.

## Run locally (after applying patch)

```sh
python -m pytest -q
python examples/generate_demo.py demo.pcap
pcap-pii demo.pcap -o demo-report.json
python -m json.tool demo-report.json
```

## Limitations/follow-up

- Packet times are capture timestamps, not guaranteed true event times; packet
  clocks can be skewed and PCAP capture may start mid-conversation.
- Reported flows are still grouped by bidirectional IP/port pairs; full
  connection identity across reused tuples and sequence-number wraparound
  remains a separate milestone.
- The pipeline only understands supported plaintext HTTP/1.x. HTTPS needs
  explicit decryption for payload PII analysis.
- The current PII detector is rule-based with heuristic, uncalibrated scores;
  a real ML stage, annotated validation data, and calibration are still pending.
- Human-readable masking is not cryptographic protection. Truncated, unsalted
  value fingerprints are not safe as anonymization for low-entropy identifiers;
  this will need hardening before use on sensitive production data.
