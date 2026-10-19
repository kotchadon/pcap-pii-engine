# TRACE network evidence contract

Integration candidate, requiring review. Evidence schema `1.0.0`, additive report schema `1.1.0`.
Baseline: main `11d41e8c583231edd86b621d96cc037fe676108f`. No frontend changes.

## Ownership and compatibility

The capture/HTTP/evidence backend owns this contract. ML still receives the exact
ordered `(location, decoded_text)` fields from `extract_fields`; this change does
not change weights, score thresholds, model labels, ML budgets or detector policy.
The existing `field_observer` and `disposition_observer` evaluator hooks retain
their payloads. `field_index` is zero-based in the message's original extracted
field list, including fields excluded by the model. HTTP/1 framing corrections
can legitimately change which messages exist (notably HEAD and CONNECT).

Existing finding/flow/coverage keys remain. Four additive report arrays are
`packet_evidence`, `stream_evidence`, `http_evidence`, `field_evidence`. Receipts
omit these arrays; the streamed report and authenticated paginated APIs contain
them. Consumers must ignore unknown additive keys and reject unsupported major
evidence versions. IDs are deterministic for the same capture and implementation,
not stable across capture editing or future parsing corrections. Scope every ID
by `capture_evidence.capture_sha256`, plus the job ID when using a job API.

## Byte identity and conventions

`capture_evidence`: `capture_sha256` is SHA-256 of every byte read from the same
open file descriptor as parsing, including uninterpreted malformed tails;
`capture_bytes` is that byte count. `identity_status=verified_read` requires
iterator exhaustion and unchanged descriptor identity/size/mtime/ctime before
and after reading. Detected mutation aborts analysis. This is a read-integrity
check, not an external custody signature or protection against a privileged
adversary replacing bytes while preserving all observed file metadata.

`frame_index` is a **one-based capture packet-record ordinal** across PCAPNG
sections. Invalid packet records can leave gaps; non-packet blocks do not count.
All byte ranges elsewhere are **zero-based, half-open** `[start,end)`. File offsets
are absolute; frame offsets start at the captured link-layer bytes; TCP stream
offsets start at the chosen safe directional sequence origin. TCP serial endpoints
are modulo 2^32 and must never be subtracted as ordinary unbounded integers.
`timestamp` is seconds with the recorded interface resolution provided separately;
it is not proof of transmission order or nanosecond arithmetic precision.

## Evidence objects and joins

| Object | Required join and interpretation |
|---|---|
| Packet | `evidence_id=frame_N`, frame/file record and data offsets, captured/wire lengths, timestamp/resolution, linktype, section/interface IDs, truncation and one disposition. Optional `tcp_datagram` contains endpoints, seq/ack/flags, IP family, offsets and checksum statuses. A reassembled datagram is associated with its completing frame; its transport header is **not** necessarily in that frame. |
| Stream summary | `row_type=stream`, `stream_id`, flow/direction, base sequence, safe-prefix length, observed SYN/FIN/RST and diagnostics. Boundary quality always means observations, never proof of a complete capture. |
| Stream source interval | `row_type=source_range`, `stream_id`, `[stream_start,stream_end)`, `frame_id`, `[frame_start,frame_end)`, `[file_start,file_end)`, seq bounds. Each is an exact captured-byte interval supporting the safe prefix. Consistent duplicates choose a deterministic source; this is not a list of every retransmission. |
| HTTP message | `http_message_id`, stream/flow IDs, request association and pairing status, safe start line, framing and source boundaries. HTTP/1 request pairing is best-effort FIFO with direction/order/timing safeguards, not proof of causality. |
| Field | `field_id=message_id_field_N`, `field_index`, message/stream IDs, safe location, source category, ranges, transformations, granularity, decoded span and limitations. No field text is stored. |
| Finding | Existing finding plus `evidence`: message ID, candidate field IDs or exact model field ID, mapping scope and limitations. ML decoded spans use Unicode code points. Rules currently do not provide decoded spans; repeated locations remain candidate fields rather than invented unique identities. |

For each field stream range, fetch source intervals for its `stream_id`, intersect
the two half-open ranges, and translate the intersection by
`file_start + intersection_start - stream_start`. Check full coverage, capture
hash and bounds before reading. Never use timestamps to infer a source interval.
Fragment payload mappings can cross multiple frames; use these intervals rather
than the completing packet's payload offset.

`granularity` values:

* `exact_raw_range`: a source interval directly resolves to captured file bytes.
* `exact_stream_range`: the entire extracted field maps exactly to stream bytes
  using `text_encoding`. Unicode character positions are not byte positions.
* `transformed_source_range`: source bytes support the field through named
  transformations; they are not an exact decoded substring highlight.
* `message_level_only`: only the message is known; no field-byte claim.
* `unavailable`: no supported mapping exists.

Compression, chunking, percent/plus decoding, JSON escapes, lossy charset decoding,
merged headers and multipart parsing are explicit transformations. The backend
conservatively exports `raw_detection_span=unavailable`: even exact field mapping
does not assert a finding-level byte span. ML supplies a separate decoded span;
legacy rules supply candidate field identities. UI must display the distinction,
not label a whole compressed body as the exact PII bytes. At most 64 source ranges
per field and 64 candidates per finding are exported; larger mappings explicitly
fall back to message scope rather than silently appearing exact.

## Privacy and API

Default reports and evidence contain no raw body, header values, request target,
field text, capture bytes, per-field hashes or unsalted detection fingerprints.
Endpoints, timestamps, lengths, safe paths and checksum/sequence metadata remain
investigative metadata and can themselves be sensitive. Existing location masking
is a conservative syntactic filter, not a formal anonymization guarantee.
`include_values=True` remains the existing explicit local raw-value opt-in; it is
not enabled by this evidence feature. No endpoint serves arbitrary file paths,
raw packet bytes, TLS keys or unmasked payloads. Jobs delete uploaded captures
under existing retention behavior; resolving original bytes requires a separately
retained authorized capture with the matching hash. No new raw evidence retention.

Authenticated `GET /api/jobs/{job_id}/{kind}` accepts the four evidence kinds,
`offset>=0`, `1<=limit<=100`, optional exact `evidence_id` and `stream_id` filters
(maximum 160 characters). Same dashboard token/ownership/expiry behavior as
findings pages applies. Filters are bound SQL parameters; IDs are not file paths.
Responses are `{items,total,offset,limit}`. Incomplete jobs or invalid ranges return
400; unknown/expired jobs 404; missing token 403. Field/message/source IDs can be
resolved independently without loading the complete report. No frontend rewrites
are part of this change.

Example (illustrative, not measured traffic):

```json
{"evidence":{"http_message_id":"flow_0001_msg_0001",
 "field_ids":["flow_0001_msg_0001_field_3"],"scope":"field",
 "decoded_text_span":{"start":0,"end":6},"raw_detection_span":"unavailable",
 "limitations":["decoded_character_offsets_are_not_capture_byte_offsets"]}}
```

## Bounds, dispositions and quality

All evidence rows share the configured report-byte budget. Spooling and final
publication remain private/atomic; exhausted budgets fail the scan rather than
publish a success with truncated evidence. Existing packet, payload, flow, RSS,
HTTP and cancellation budgets remain active. Source intervals are separate rows
to keep pages bounded. Fragment buffers and tombstones have additional count,
byte, per-datagram, timestamp and frame-window bounds (see module defaults).

`packet_dispositions` partitions **yielded frames** exactly once. Legacy
`non_tcp_or_unsupported_packets` now also includes fragments awaiting completion;
it must not be read as the count of permanently uninspected datagrams. Fragment
counters are overlapping events, sometimes counted per datagram rather than per
frame; never add them to the partition. Invalid capture records are separate
capture diagnostics. Later conflicting fragment identities invalidate emitted
datagrams before HTTP analysis while within the bounded quarantine horizon.

Keep TCP observed damage, unknown capture completeness, HTTP framing/body coverage
and ML field coverage separate. A successful handshake or a loaded model does not
prove either transport completeness or inference coverage. Checksum mismatch is
reported as possible offload/truncation/corruption, not automatically packet loss.
Fragments beyond the retained identity horizon, delayed tuple reuse, one-sided
captures, encryption and unobserved bytes remain limitations. `analysis_incomplete`
is an aggregate observed-loss flag; false is never proof that all traffic existed
in the capture.

## Integration risks and stop point

PR #23 is frozen and untouched. `engine.py`, `jobs.py`, `dashboard.py` are shared
integration surfaces, so merge resolution must preserve its model-quality hooks
and this contract explicitly. No model artifacts, frozen manifests or frontend
files are modified. The frontend/evaluator team should agree on this contract and
run the serialized examples and evidence tests before building a raw-byte viewer.
An authorization/retention design is required before any future raw-byte API.

## Plaintext HTTP/2 subset

Install the optional `http2` extra (`hpack>=4.1,<5`; tested with 4.1.0).
Only an observed prior-knowledge client preface starts decoding. HEADERS,
CONTINUATION, HPACK and DATA frame bounds are retained separately per direction;
`http_evidence.protocol=h2` adds `http2_stream_id`, `stream_ranges`, and
`contiguous=false`. The outer stream start/end is a bounding interval and may
contain frames from other messages: use `stream_ranges` for actual membership.
Request/response association uses the HTTP/2 stream ID. Only individually complete
messages enter existing field/rules/ML APIs. Interim-only transactions, resets,
missing dependency, unsupported settings, push, CONNECT, truncated frames and
uninspected trailers produce explicit diagnostics/coverage loss. A complete framed
message does not imply its trailers were inspected. HPACK provenance includes
prior same-direction header-block dependencies and is always transformed evidence.

Limits per direction: 16 MiB input, 1,024 frames, 256 streams, 16 KiB frame payload,
64 KiB decoded header block, 256 KiB compressed historical context, 4 MiB aggregate
body bytes. Non-default HPACK/frame-size settings halt conservatively; exact
cross-direction flow-control chronology is not reconstructed. No h2c upgrade,
TLS, HTTP/3, push or CONNECT support is claimed. The legacy
`http2_streams_not_decoded` is a diagnostic counter, not a census of stream IDs;
use `http2_messages_decoded` and explicit per-flow diagnostics for coverage.

Legacy PCAPNG Packet/Simple Packet blocks remain unsupported. Their ordinals
count and `capture_unsupported_packet_records` explicitly marks evidence loss;
they are not silently treated as a complete empty capture.

New field evidence exports only the structural source category in `location` by
default (for example `json_body`), with `field_id`/`field_index` identifying the
field. It does not broaden disclosure of attacker-controlled JSON/query/header
keys from fields that produced no finding. Explicit `include_values=True` may
export their full location. Existing finding locations retain their prior masking
policy for compatibility. Consumers must join by IDs, never by displayed location.
