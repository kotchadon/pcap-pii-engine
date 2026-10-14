# Upstream input assumptions for the contextual ML detector

Audience: the networking / extraction workstream (owners of TCP reassembly, HTTP parsing, capture limits, reporting).
The ML package **does not own and cannot fix** any of the items below; this document states what the model needs from
`(location, text)` extraction and gives independently reproducible cases for upstream validation. A BiLSTM cannot restore
packet bytes that were never captured.

## 1. What the model consumes
`FieldInput(field_index, location, text, context)` - one extracted field. `location` follows `http_extract` naming
(`json_body.a.b[0]`, `form.x`, `query_parameter.q`, `header.name`, `body.text`); `text` is the decoded Unicode string
(UTF-8 or declared charset, `errors="replace"` as in `_decode_text`). Offsets in results are code-point offsets into exactly
that string. The model never sees packets, ports, hosts or timestamps.

## 2. Input-quality policy (implemented in `packet_pii/ml/input_policy.py`, no host changes)
| Situation | Model-side behaviour | Required upstream signal |
|---|---|---|
| Secret-bearing key (password/token/cookie/authorization/session...) | **skipped** (rules own credentials; V1 produced false positives there) | none - decided from `location` |
| Empty text, 1 char, > 30% U+FFFD | skipped (`empty_text`, `too_short`, `mostly_replacement_chars`) | none |
| Truncated / incomplete field text | analysed; findings listed in `partial_evidence` | `context["truncated"]="true"` |
| Field from a stream with a TCP reassembly gap | analysed; `partial_evidence` | `context["stream_gap"]="true"` |
| Capture-level truncation / malformed records | analysed; `partial_evidence` | `context["capture_incomplete"]="true"` (from `summary.analysis_incomplete`) |
| Decode produced replacement characters | analysed; flagged automatically from U+FFFD | `context["decode_replaced"]="true"` (optional) |
| Text longer than the configured limit | `MlValidationError` (whole request) - cap upstream | per-field size cap (<= 65,536 chars) |

**Propagation requirement:** any ML finding on a flagged field must be reported with the same "analysis incomplete / may be
partial" marker the report already carries (`summary.analysis_incomplete`), never as an exhaustive result. The result object
(`PolicyResult.partial_evidence`) exposes the `field_index` set; no raw text is included.

## 3. Cases for upstream validation (acceptance criteria)
Each case lists the property the *extractor* must guarantee. "ML consequence" is why it matters.

| ID | Condition | Upstream acceptance criterion | ML consequence if violated |
|---|---|---|---|
| U1 | Out-of-order TCP segments | Reassembled stream equals the in-order stream byte-for-byte; extracted fields identical to the in-order capture | none if identical; otherwise fused/garbled tokens |
| U2 | Duplicate / retransmitted segments | Each byte contributes once; a value appears once (no `Maria GarciaMaria Garcia`) | duplicated entity strings, wrong boundaries |
| U3 | Overlapping sequence ranges, **conflicting payloads** | Deterministic documented winner AND a conflict flag on affected fields (`stream_gap`/`capture_incomplete`) | model tags whichever bytes won with full confidence |
| U4 | Missing initial / middle / final segment | Gap recorded; fields spanning the gap flagged `truncated`+`stream_gap`; bytes after a gap must **not** be spliced to bytes before it | entity split across the gap becomes two unrelated fragments or a fused token; undetected PII |
| U5 | Reused 4-tuple across connections | Separate flows (SYN/FIN/RST boundaries respected) | cross-connection text concatenation -> spurious multi-entity fields |
| U6 | SYN/FIN/RST lifecycle | Data after RST/FIN not appended to the closed flow | stale text appended to fields |
| U7 | Concurrent flows, persistent HTTP | One request/response per field set; no interleaving between flows | wrong `location`, hence wrong key context |
| U8 | Sequence-number wraparound | Same bytes as without wraparound | as U1 |
| U9 | Truncated / malformed capture | `analysis_incomplete=true`; partial fields flagged | partial entities detected as complete names |
| U10 | Unsupported IP fragmentation / protocols | Explicitly reported as unsupported; no pseudo-fields | none (no field) |
| U11 | Chunked bodies / `Content-Length` shorter than captured | Body bounded by framing; incomplete body flagged `truncated` | trailing bytes of the next message appear in the field |
| U12 | Compressed bodies that fail to decompress | No field emitted (current behaviour) or flagged | garbage text -> false positives |
| U13 | Non-UTF-8 charsets | Declared charset honoured; replacement characters flagged | U+FFFD inside names breaks tokens |
| U14 | Percent-encoded values (`%20`, `+`) | Decoding policy fixed and documented (query/form values are decoded by `parse_qsl`; `header.referer` / `body.text` are not) | the model handles `Maria%20Garcia` and `Maria+Garcia` (trained), but gold-offset tests must state which form is analysed |

Independent reproduction recipe (upstream): build each case with the existing pcap generator, run `analyze()`, and assert (a)
the extracted `(location, text)` list, (b) the flag in `summary`/field metadata. The ML side only needs the flags to be
available per field; the proposed carrier is `FieldInput.context` (strings), which requires **no schema change in `ml/`**.

## 4. What ML cannot do (do not rely on it)
* Recover bytes in a gap, order segments, or choose between conflicting payloads (U3, U4).
* Know that a string is a truncated name: `Maria Gar` is analysed as a name fragment; recall on clipped entities is lower
  (measured on synthetic fields in `V2_EVALUATION.md`, section "Fragments").
* Detect structured secrets/credentials: those remain with the deterministic rules; secret-bearing keys are excluded from tagging.

## 5. Synthetic extracted-field tests (ML-side)
`tests/test_ml_v2_eval.py` and `tests/test_ml_input_probe.py` exercise the policy and the detector on synthetic fields that
represent U2/U4/U9/U13 (duplicated value, fused tokens across a gap, clipped entity, replacement characters). These are
model-behaviour probes, **not** validation of TCP reassembly.
