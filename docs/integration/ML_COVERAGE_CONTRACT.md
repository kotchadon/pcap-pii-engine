# ML coverage contract

Applies to `analyze()` and `analyze_to_report()` on
`feature/trace-scalable-ml-engine`. This is an engine accounting contract for
independent evaluation, not a ground-truth evaluator or a precision/recall claim.

## Configuration and bounded execution

Both entry points accept keyword-only `ml_work_budget: MLWorkBudget | None`.
`MLWorkBudget` is exported by `packet_pii.hybrid` and validates integer values
(excluding booleans) at construction. Capture profiles do not change ML budgets.

| Setting | Standard default | Explicit extended preset | Supported ceiling |
| --- | ---: | ---: | ---: |
| `max_fields_per_batch` | 256 | 256 | 10,000 |
| `max_characters_per_batch` | 131,072 | 131,072 | 2,000,000 |
| `max_total_fields` | 10,000 | 100,000 | 1,000,000 |
| `max_total_characters` | 2,000,000 | 20,000,000 | 200,000,000 |
| `max_field_characters` | 65,536 | 65,536 | 65,536 |

`MLWorkBudget.for_profile('standard'|'extended', **overrides)` selects the
preset. Totals may be zero; batch and per-field limits must be positive. A
field is indivisible. A custom batch character limit smaller than a field
causes an explicit skip, never truncation. Character counts use Python Unicode
code points, including whitespace, not UTF-8 bytes or model tokens. A later
shorter field can fit after a larger field exceeds the remaining character
budget. No time limit is claimed: a single model call is not interruptible.

The detector is supplied by the caller and reused across batches. The engine
uses `iter_http_field_batches`, emits each result batch to the existing report
sink, and discards it before continuing. It does not accumulate scan-wide raw
candidates or predictions. Extraction still materializes one HTTP message's
bounded field list; TCP/session buffering remains governed by `AnalysisLimits`.
`infer_http_fields(fields, detector, *, include_values=False, max_fields=10000,
max_characters=2000000)` remains the legacy materializing adapter.

## Field identities, policy and offsets

`metadata.ml_extraction_policy_version = "http-contextual-identity-v1"` fixes the
current extraction/policy interpretation: all `header.*` fields and existing
reserved credential/contact field paths are excluded from contextual ML but
remain eligible for rules. Among remaining fields, empty strings are counted
as empty. All remaining nonempty fields are eligible, including computational
skips. Policy exclusion takes precedence over empty/invalid/oversized handling.

A field identity is `(flow_id, http_message_id, field_index)`. `field_index` is
the zero-based index in the original `extract_fields(message)` result, including
excluded, empty and skipped entries. It is never renumbered for a batch. The
same location can occur repeatedly; location is not an identity. Flow IDs retain
session suffixes when TCP endpoint tuples are reused. Message IDs retain the
engine's stable timestamp/direction/stream-offset ordering. All finding
flow/message/request provenance remains unchanged.

`span_start` and `span_end` are half-open Unicode code-point offsets into the
exact original extracted field string; `text[start:end]` identifies the span.
They are neither packet byte offsets nor UTF-16 offsets. Text is not normalized,
stripped, or truncated by this adapter. Paths over 1,024 characters are skipped
before constructing strict `FieldInput`; model input validation is unchanged.
Exported locations and values remain masked by default. Coverage rows carry no
raw text, keys, paths or predictions.

## Counts and complete/partial states

For a successful hybrid scan:

```
fields_extracted = ml_fields_excluded_by_policy + ml_fields_empty + ml_fields_eligible
ml_fields_eligible = ml_fields_evaluated + ml_fields_skipped
sum(ml_skip_reasons.values()) = ml_fields_skipped
```

An evaluated field was submitted to a detector call whose outputs passed the
strict model contract, regardless of whether it produced any predictions.

Prediction cache (additive, V2 inference acceleration): within one scan an
identical `(location, text)` pair may reuse an earlier validated neural
prediction instead of running the model again, but only for detectors that
declare `prediction_cache_safe = True` (the BiLSTM ignores `FieldInput.context`).
A reused field is still an *evaluated* field and still consumes the field and
character budgets; it keeps its own message provenance, field index and quality
flags. For a successful hybrid scan:

```
ml_fields_evaluated = ml_fields_model_inferred + ml_prediction_cache_hits
```

`ml_fields_model_inferred` counts fields actually sent to the model (unique
neural evaluations); `ml_prediction_cache_hits` counts fields whose prediction
was reused; `ml_prediction_cache_enabled` says whether reuse was possible. With
the cache disabled, `ml_fields_model_inferred = ml_fields_evaluated`. Rules-only
reports carry `0, 0, false`. The cache is private to the scan's runner, bounded
(65,536 entries / 8,000,000 key characters, fields over 4,096 characters are
never cached, least-recently-used eviction) and never logged or serialised.
`ml_characters_evaluated` sums full original input lengths of those fields.
`ml_predictions_by_label` counts validated emitted spans; predictions are not
field counts. `ml_processing_time_seconds` measures validated inference and
batch finding conversion, excluding parsing, rules, serialization and waiting.
`ml_inference_batches` counts successful nonempty detector calls, not candidate
scan chunks, progress notifications or HTTP messages.

| State | `ml_inference_status` | invoked | complete |
| --- | --- | --- | --- |
| ML not requested | `not_requested` | false | null |
| Model loaded, no eligible work | `not_invoked` | false | true |
| All eligible fields evaluated, zero or more predictions | `completed` | true | true |
| Any eligible field skipped | `partial` | true or false | false |

`ml_inference_invoked` aliases existing `ml_invoked`.
`ml_incomplete` remains `ml_fields_skipped > 0`. `ml_inference_complete` describes
eligible field coverage, so it is vacuously true with no eligible fields when
ML was requested. Rules-only ML counters retain zero for backward compatibility;
the equations above apply only when ML was requested. A successfully published
report has `ml_inference_failed = false`; inference errors fail the scan without
publishing a partial report. Failed/cancelled jobs must not synthesize unknown
report statistics as zero.

`ml_skip_reasons` is a count map, with one primary reason per skipped field,
chosen in this order after policy/empty checks:

1. `ml_field_path_invalid`: empty/non-string model location.
2. `ml_field_path_too_long`: model location exceeds 1,024 characters.
3. `ml_field_too_large`: text exceeds configured per-field safety limit.
4. `ml_batch_character_budget_exceeded`: indivisible field exceeds batch limit.
5. `ml_field_budget_exceeded`: total evaluated-field allowance consumed.
6. `ml_character_budget_exceeded`: field cannot fit remaining character allowance.

Thus a field failing multiple restrictions has one deterministic primary reason;
these are observed reasons, not inferred UI messages. Exceptions/cancellation
are not counted as skipped fields in an uncommitted report.

## Read-only coverage trace, including fields with no prediction

`metadata.ml_coverage_schema_version = "1.0.0"`. The top-level
`ml_field_coverage` array has one row per extracted HTTP message for hybrid
scans, including messages with no eligible fields. Rules-only reports contain
an empty array. A row has this shape:

```json
{
  "flow_id": "flow_0001",
  "http_message_id": "flow_0001_msg_0001",
  "fields_extracted": 5,
  "index_ranges_by_status": {
    "evaluated": [[2, 4]],
    "excluded_by_policy": [[0, 2]],
    "empty": [],
    "skipped": [[4, 5]]
  },
  "skip_reason_index_ranges": {"ml_field_budget_exceeded": [[4, 5]]}
}
```

All ranges are integer half-open `[start, end)` field indices, sorted and
coalesced within each status/reason. Status ranges partition exactly
`[0, fields_extracted)`. Reason ranges partition exactly the skipped indices.
Rows preserve HTTP processing order. This permits independent joins for
zero-prediction fields without assuming every missing finding is a negative.

Ranges are built only for the current bounded message. `analyze_to_report`
spools rows under the same byte budget and atomic publication as findings and
flows; its receipt omits all three arrays. The full JSON download contains them.
The existing `row_observer` receives kind `ml_field_coverage` in addition to
`findings`/`flows`. Observers must tolerate this additive kind. `analyze()` remains
an explicitly materializing convenience API under its report/memory budgets.

## Progress, cancellation, failures and independent protocol coverage

Progress callback dictionaries use stage `ml_inference` and contain cumulative
observed `packets`, `endpoint_pairs`, `sessions`, `http_messages`, `findings`,
`ml_fields_eligible`, `ml_fields_evaluated`, `ml_fields_skipped`,
`ml_characters_evaluated`, `ml_inference_batches`, and `elapsed_seconds`.
Counters describe processed chunks, not a precomputed whole-capture denominator;
no percentage is implied. The engine calls progress before and after each batch
and after bounded chunks of skipped/excluded fields. Raising from a callback
cancels further work without retry; existing job machinery publishes cancellation
state. A model exception fails closed. Neither path publishes a completed JSON
report; temporary spool/index cleanup remains the owning context's responsibility.
A previously published target survives failure when overwrite was requested.

`analysis_incomplete` additionally incorporates observed capture damage, TCP gaps
and definite incomplete HTTP framing. Flow `http_diagnostics` includes sanitized
reason/start stream-byte offset/incomplete boolean plus directional endpoints;
flow ID supplies session provenance. `http_incomplete_streams` counts directions
with definite terminal incomplete framing. `http_uncertain_streams` counts
ambiguous/unparseable or unsupported tails. Uncertainty is not fabricated TCP
loss; absence of FIN is not proof of truncation or completeness.

Without paired request-method context, a short response body is reported as
`http_response_body_framing_unknown` (uncertainty): HEAD and successful CONNECT
responses can legally omit bodies. Such responses remain unparsed under the
existing parser contract. Request-body truncation and recognizable unfinished
headers remain definite observations. `analysis_incomplete = false` does not
override these uncertainty diagnostics or justify a full-file inspection claim.

An evaluator may claim all **extracted eligible** fields were evaluated only
when ML was requested and `ml_inference_complete` is true, with consistent
coverage rows/counts. This is not full capture/application coverage. For a
full-file claim, inspect capture/TCP/HTTP diagnostics and unsupported/encrypted
traffic separately, including `http_uncertain_streams`; absent observable damage
does not prove no traffic was missing. Model version comes from the loaded
validated detector and is repeated on ML findings. Scores retain their typed,
uncalibrated meaning; no calibrated probability, accuracy or recall is implied.
