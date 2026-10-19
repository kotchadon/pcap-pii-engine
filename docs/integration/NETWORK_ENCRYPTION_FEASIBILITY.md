# TLS, QUIC and HTTP/3 feasibility — design only

Status: research and proposed acceptance gates. This branch does **not** implement
TLS record decryption, QUIC packet decryption, HTTP/3 or QPACK. Plaintext HTTP/2
support does not make captured HTTPS readable. No capture or key upload is needed
or authorized by this design. Sources reviewed 2026-10-19.

## Authorized plaintext and TLS

The smallest next extension is a local adapter for application bytes exported by
an authorized endpoint or trusted decryption tool. Preserve the original capture
hash, exporter/version, authorization scope, and transformation identity. An
export without verifiable linkage to original frames is application evidence
only; it must never receive fabricated packet offsets.

A separate optional offline TLS adapter would require explicitly supplied,
connection-scoped secrets and sufficient record/handshake context. TLS 1.2 record
keys depend on the selected algorithms and handshake secrets; a server private
key is not a universal decryption mechanism, particularly with ephemeral
key exchange. TLS 1.3 uses distinct directional traffic secrets and key epochs;
KeyUpdate processing and authenticated record reconstruction are prerequisites.
Authentication failure, missing secrets or missing record sequence context must
produce unavailable/partial states, never guessed plaintext. See RFC 5246 §§6–8
and RFC 8446 §§4.6.3, 5, 7.

Endpoint key logging is technically feasible: OpenSSL documents a key-log
callback emitting NSS-format debugging secrets. This is an explicitly enabled
endpoint capability, not authority to harvest a user's key files. A future
adapter should accept an authenticated local upload handle, never an arbitrary
filesystem path or unrestricted environment-variable search.

Proposed key-material controls:

- Bind a key handle to one authenticated local scan and an explicit capture.
- Keep keys out of ordinary reports, filenames, logs, diagnostics and telemetry.
- Prefer a short-lived isolated worker and memory-only secrets; if unavoidable,
  use owner-only temporary files and remove them on success, failure or cancel.
- Avoid promises of perfect memory zeroization in Python or secure physical
  deletion on copy-on-write storage. Process exit and restricted storage reduce
  exposure but do not prove forensic erasure.
- Audit authorization and use events without logging secret values. Reuse
  current session/token checks and require an explicit local reveal action.

TLS evidence would link decrypted application intervals to authenticated TLS
record ciphertext ranges and their frame references. Mark the edge as a
cryptographic transformation and retain cipher/epoch/validation status. Plaintext
character offsets cannot become exact ciphertext byte highlights.

## QUIC and HTTP/3

QUIC requires a UDP-oriented connection model. Connection IDs and authenticated
ID-management events support migration across address tuples; timestamps or
four-tuples alone cannot establish continuity. Reassembly uses per-stream offsets,
with independent packet-number spaces, duplicate handling, gaps, resets and
conflicting retransmission diagnostics. See RFC 9000 §§2, 5, 9, 12, 19.

QUIC packet protection uses TLS-derived directional secrets at most encryption
levels; Initial secrets have a public derivation based on the initial destination
connection ID. Decoding Initial packets does **not** unlock protected HTTP/3
application data. Packet-number reconstruction, header protection, AEAD checks,
key phases, Retry/version changes and reordered packets need explicit handling.
Use an established maintained implementation, not new cryptographic primitives.
See RFC 9001 §§5–6.

HTTP/3 additionally requires control streams, SETTINGS, request-stream lifecycle,
frame validation and QPACK. QPACK state travels on separate unidirectional
streams. A field block can depend on instructions not yet captured; an unresolved
Required Insert Count is a blocked/unavailable field, not empty headers. Bound
blocked streams and retained dependency bytes. Header evidence must reference
both its field block and relevant QPACK encoder-stream instructions. See RFC 9114
§§4, 6–7 and RFC 9204 §§2, 4–5.

## Proposed delivery gates

1. Deliver the authorized plaintext adapter separately, with synthetic export
   lineage tests and explicit unlinked-source handling.
2. Evaluate a maintained offline TLS/QUIC implementation and its provenance APIs,
   packaging/license/security posture; choose no library solely from protocol
   name recognition. Dependency selection remains open.
3. Set measured limits for ciphertext bytes, records/packets, connections, streams,
   key epochs, decrypted bytes, QPACK table size, blocked streams, buffering and
   processing time before exposing decryption to scans.
4. Validate synthetic TLS 1.2/1.3 and QUIC fixtures for authentication failures,
   wrong/missing keys, key updates, loss, reordering, migration, stream resets,
   QPACK dependencies and cancellation. Cross-check against a pinned independent
   reference tool and preserve disagreements as limitations.
5. Extend the existing evidence contract additively with transformation edges;
   keep masked defaults, paginated output and report/field budgets. Do not merge
   TLS or HTTP/3 into this P0 branch as an untested capability.

## Primary sources

- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246.html)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [OpenSSL — SSL_CTX_set_keylog_callback](https://docs.openssl.org/4.1/man3/SSL_CTX_set_keylog_callback/)
- [RFC 9000 — QUIC transport](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9001 — TLS for QUIC](https://www.rfc-editor.org/rfc/rfc9001.html)
- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [RFC 9204 — QPACK](https://www.rfc-editor.org/rfc/rfc9204.html)
