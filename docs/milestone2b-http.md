# Milestone 2B — HTTP/1.x reconstruction and field extraction

## Purpose

Once TCP bytes have been reconstructed, the HTTP parser must determine the boundaries of each request/response before any PII is inspected. Incorrect body framing can silently mix content from different messages and create false findings. This update deliberately **stops on ambiguous or malformed framing** rather than guessing.

## Implemented in this patch

- Parse HTTP/1.0 and HTTP/1.1 request/response start lines and bounded headers.
- Split pipelined HTTP messages using `Content-Length`, `Transfer-Encoding: chunked`, and statuses that must not contain bodies (1xx, 204, 304).
- Reject malformed headers, conflicting/duplicate framing headers, unsupported transfer codings, oversized/incomplete bodies and invalid chunk framing.
- Unpack gzip and both zlib-wrapped and raw deflate bodies, enforcing a **2 MiB expanded-body limit**; ignore undecodable/unsupported content encodings rather than scanning compressed bytes as plaintext.
- Locate PII candidate values in request query parameters, JSON objects/arrays, URL-encoded forms, bounded text multipart fields and regular text bodies. Multipart file attachments are deliberately not analysed.
- Bound JSON field expansion and depth to avoid runaway extraction.
- Preserve the existing `HttpMessage`, `parse_http_stream` and `extract_fields` interfaces, so the existing engine/report pipeline remains compatible.

## Verification

From the root of the repository:

```bash
python -m pytest -q
# 48 passed (19 original + 29 new HTTP tests), verified on the bundled project baseline
```

The new tests include a full synthetic capture integration scenario:

1. Create gzip-compressed JSON containing a fake email.
2. Split the HTTP request across TCP segments, captured out of order.
3. Read the PCAP, reassemble TCP, parse HTTP and decompress gzip.
4. Verify the PII detector identifies `json_body.details.email`, records the correct flow/source, and **does not write the raw email** into the default report.

Tests are synthetic; these results are **not** proof of correctness on arbitrary real-world captures.

## Known gaps (must not be described as implemented)

- No HTTP/2 or HTTP/3 parsing. No HTTPS payload inspection without authorised decryption.
- No close-delimited response-body reconstruction, and `HEAD` response handling requires request context. Unframed responses expose headers only; parsing stops at the uncertain boundary.
- Request-response correlation across the two TCP directions is not implemented by this patch; flow IDs still group the two directions.
- Multipart binary file attachments, multipart nested forms, and arbitrary unsupported content/transfer encodings are not inspected.
- No detailed partial/parse-failure statistics yet: uninspectable contents may lead to false negatives.
- No contextual ML, calibrated confidence scores, or labelled model evaluation yet (rules-only baseline).
- The same TCP/PCAP limitations from Milestone 2A still apply: truncated captures, IP fragmentation, sequence wraparound, reused tuples, malicious TCP ambiguities, and memory limits.

## Next logical unit

Add request-response correlation, message timing provenance, and explicit parse/skip reason counters; then strengthen the detector and build **genuine ML inference** with a labelled evaluation set. Keep all test fixtures synthetic; do not commit personal/corporate PCAPs or unmasked report values.
