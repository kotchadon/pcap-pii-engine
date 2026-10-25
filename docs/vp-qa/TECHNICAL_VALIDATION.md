# TRACE - independent technical validation (QA)

Branch `feature/trace-independent-vp-qa`, based on `origin/feature/vp-live-evidence-showcase` @ `86ad303` (latest UI + hybrid + showcase).
Added only `tests/test_vp_qa_*.py` and `docs/vp-qa/`; no application code, frontend, model weight, dataset or existing test was changed.
A finding means potential exposure of personal-looking data in unencrypted HTTP/1.x; it is not proof of exfiltration, theft or misuse.
Everything below is synthetic and fictional (RFC 5737 addresses, `example.test` hosts, invented people). Each claim names the test or file that checks it;
`pytest tests/test_vp_qa_*.py` reproduces all of it (checkpoint-pinned tests skip, they never weaken, if the checkpoint changes).

<!-- vp-qa-measured: {"model_version": "bilstm-v2-d1f9e9fb9a2b", "packets": 95, "flows": 12, "http_messages": 24, "rules_findings": 19, "ml_findings": 12, "ml_fields_evaluated": 48, "ml_fields_excluded_by_policy": 99, "potential_leaks_hybrid": 31, "potential_leaks_rules_only": 19} -->
The comment above is recomputed from a fresh engine run by `test_technical_validation_measured_block_matches_a_fresh_run`; the document cannot drift from the code.

## 1. Architecture actually implemented (read from the repository)
| Stage | Where | Notes verified by test |
|---|---|---|
| Capture ingest (classic PCAP / PCAPNG), bounded | `capture.py`, `engine.AnalysisLimits` | counts of packets/unsupported packets (`test_non_http_tcp_and_non_tcp_packets_are_counted_not_guessed`) |
| IPv4/TCP decode, per-direction reassembly | `engine.analyze` -> `reassemble` | reorder/duplicate/overlap identical; head/middle loss flagged (`test_vp_qa_tcp_uncertainty.py`) |
| HTTP/1.x parse, chunked + gzip/deflate, field extraction (`header.*`, `query_parameter.*`, `form.*`, `json_body.*`, `body.text`) | `http_extract.py` | malformed matrix (`test_malformed_http_*`) |
| Deterministic rules | `detect.py` (`detect_fields`) | identical in both modes (`test_rules_findings_are_identical_in_rules_only_and_hybrid`) |
| Contextual model (optional) | `hybrid.py::infer_http_fields` -> `ml/infer.py::BiLSTMDetector` (V2 = 3-seed BiLSTM ensemble, CPU, loaded with `weights_only=True`, checksums verified) | `import torch` never happens in rules-only (`test_rules_only_analysis_runs_with_pytorch_blocked`) |
| Policy between them | `hybrid._excluded`: `header.*`, secret-bearing keys, reserved contact/number keys (`email|phone|card|ip|content_length`) are **not** given to the model; fields > 65,536 chars are skipped and counted | spy-detector test (`test_no_credential_field_or_header_is_ever_given_to_the_model`), independent recount (`test_ml_field_accounting_matches_independent_recount`) |
| Report | `engine.analyze` -> `{metadata, summary, flows, findings, limitations}` | provenance schema pinned (`test_provenance_fields_and_detector_separation`) |
| Local dashboard | `dashboard.py` (+ `dashboard_static/`) `POST /api/showcase`, `X-Detection-Mode: rules|hybrid` | API result equals direct engine call with the real model (`test_dashboard_api_matches_direct_engine_with_real_model`) |

Provenance per finding: `detector` (`rule` or `bilstm`), `flow_id`, `http_message_id`, `http_request_id`, `http_message_type`, timestamp, endpoints, masked `value`,
`location`; ML findings add `model_version`, `span_start/span_end` (code-point offsets into the field), `field_index`, `confidence_type = uncalibrated_model_score`.
Rule findings carry **no** model fields. `confidence` is a heuristic for rules and a raw model score for ML - they are never merged.

## 2. Test methodology
* **Real components, no mock model.** The existing showcase tests use `MockV2` (a string search that injects findings) or avoid asserting model output; the QA suite uses the real V2 ensemble and asserts what it actually returns.
* **Three kinds of test:** (a) *invariants* (counts, provenance, masking, rules unchanged by ML) - hard assertions; (b) *characterisation* of research-model outputs, pinned to the checkpoint version - honest records of hits, misses and false positives, never forced positive; (c) `xfail(strict=True)` for behaviour a reviewer would expect but which was **not** delivered when the QA was written (findings F-03..F-07). F-03 to F-07 have since been fixed and converted to normal tests; no strict xfail remains.
* **Own PCAP builder** (`test_vp_qa_support.py`) so tests do not depend on another engineer's fixture helpers, except where the showcase itself is under test.
* **Spy detector** records exactly what is handed to a model, so secret-handling is verified independent of any model.
* **Inventory (118 tests, all passing on this branch; originally 100 with 5 strict xfail):** live showcase 21 · model-ready/zero-findings 6 · adversarial 52 · TCP uncertainty 18 · secrets 6 · scientific claims 15. Behaviour fixed after the QA run is covered by the regression tests cited in section 5.
* The independent benchmark (`challenge_v1`, 1,058 fields) was **not** used to tune or select anything; it was only read for reporting.

## 3. Observed live results - 12-conversation showcase, real V2 ensemble
Generated by `examples/generate_showcase.py` and analysed by `engine.analyze` (no precomputed output). Identical network counts in both modes:

| Quantity | Rules-only | Hybrid |
|---|---|---|
| Packets / flows / HTTP flows | 95 / 12 / 12 | 95 / 12 / 12 |
| HTTP messages / transactions / unpaired | 24 / 12 / 0 | 24 / 12 / 0 |
| Stream gaps / truncated / malformed / `analysis_incomplete` | 0 / 0 / 0 / false | 0 / 0 / 0 / false |
| Rule findings | 19 (EMAIL 10, CREDENTIAL_OR_TOKEN 2, USERNAME 2, PERSON_NAME_CANDIDATE 2, PHONE 2, CREDIT_CARD 1) | 19 (identical list) |
| ML fields evaluated / excluded by policy / skipped | 0 / 0 / 0 | **48 / 99 / 0** (99 = 85 headers + 13 reserved contact/number keys + 1 `password`) |
| ML findings | 0 | **12** (6 PERSON_NAME, 6 USERNAME) |
| `potential_leaks` (= rules + ML findings) | 19 | 31 |
| Detection method / model version | `rules_only` / - | `rules_plus_bilstm` / `bilstm-v2-d1f9e9fb9a2b`, `min_score` 0.35 |
| `processing_time_seconds` (this 4-vCPU container, one run) | 0.005 | 2.85 (48 fields, 3-member CPU ensemble) |
| One-off model load (outside `analyze`) | - | about 4.4 s |

The 12 contextual predictions (masked as shown in the report; fixture-author intent in the last column):
| Flow | Field | Label | Span | Raw score | Assessment |
|---|---|---|---|---|---|
| 1 | `json_body.shipping.recipient` | PERSON_NAME | 0-21 | 0.9995 | planted name - hit |
| 1 | `json_body.audit.actor` | USERNAME | 0-12 | 0.9228 | planted handle - hit |
| 2 | `json_body.username` | USERNAME | 0-12 | 0.9868 | hit (rule also fires) |
| 4 | `json_body.order.currency` (`AUD`) | PERSON_NAME | 0-3 | 0.7824 | **false-positive candidate** |
| 5 | `form.full_name` | PERSON_NAME | 0-11 | 0.9999 | hit (rule also fires) |
| 6 | `json_body.audit.actor` | USERNAME | 0-12 | 0.9228 | hit |
| 7 | `json_body.shipping.recipient` | PERSON_NAME | 0-21 | 0.9995 | hit |
| 9 | `json_body.note` | PERSON_NAME | 17-29 | 0.8582 | **false positive** (ordinary words) |
| 9 | `json_body.note` | USERNAME | 53-64 | 0.5651 | **false positive** (ordinary words) |
| 10 | `json_body.geo.place` (`Madison`, a city) | PERSON_NAME | 0-7 | 0.5539 | **false-positive candidate** (the planted hard negative) |
| 11 | `json_body.username` | USERNAME | 0-13 | 0.9900 | hit (rule also fires) |
| 12 | `json_body.user` | USERNAME | 0-12 | 0.9770 | hit |

* **Miss:** `json_body.full_name` in flow 3 (`Alex Example`) - evaluated, no span; only the deterministic rule reported it (`test_known_model_miss_is_reported_not_hidden`).
* **Correct non-finding:** the planted company hard negative (`Johnson & Johnson`, flow 9 `billed_to`).
* Tally: 8 of 9 planted person/username fields hit, 4 false-positive candidates. **n = 9 on a hand-authored fixture whose strings were copied from the model's own demo; this is an observation, not precision/recall.** None of these strings occurs as an entity in the V2 training/validation/calibration data (`test_showcase_strings_are_absent_from_v2_training_data`).
* 3 field locations are flagged by both rules and ML, so 31 findings cover 27 distinct field locations (`test_overlapping_signals_are_reported_as_distinct_locations`); the UI says signals may overlap.

### Why "model ready" can coexist with zero ML findings (`test_vp_qa_model_ready_zero_findings.py`)
"Ready" = checkpoint loaded; "invoked" = `analyze(..., ml_detector=)` ran; "evaluated" = eligible fields passed to the model; "findings" = spans returned. Five independent causes, each reproduced:
1. everything sensitive is excluded by policy (credentials/contact/headers): 0 evaluated, rules still fire;
2. eligible benign fields: model ran (>= 6 fields), found nothing;
3. no readable HTTP (TLS-like bytes): nothing to evaluate, capture **not** shown clean;
4. names/usernames in HTTP headers: excluded from ML by design (blind spot; rules do not detect names either);
5. a genuine model miss on an eligible field (`Alex Example`).
So `ML = 0` is not evidence of absence, and "model ready" is not a result.

## 4. Machine-learning evaluation (offline, synthetic - not this file)
From `docs/ml/results/v2_eval_*.json` (exact span + label, micro-F1, 1,000-resample bootstrap CI). **These are research numbers on synthetic data and are not the accuracy of any uploaded capture.**
| Benchmark | BiLSTM V2 | BiLSTM V1 | Research strong-rules baseline | Live engine rules (`detect.py`) | Rules-first hybrid |
|---|---|---|---|---|---|
| Frozen out-of-generator **synthetic challenge** (1,058 fields; P 0.836, R 0.801) | **0.818** (0.794-0.840) | 0.559 | 0.317 | 0.134 | 0.801 |
| V1 frozen synthetic test (reported once) | 0.927 | 0.755 | 0.908 | 0.312 | 0.948 |
| V2 validation / calibration (in-generator; used for selection - not independent) | 0.958 / 0.946 | 0.505 / 0.428 | 0.423 / 0.368 | 0.081 | 0.902 / 0.898 |
* The engineering target (>= 0.88 on the independent set) was **not** met; `test_headline_f1_is_below_the_declared_target_and_says_so`.
* The dashboard's four offline tiles equal the committed results (`test_ui_offline_numbers_equal_committed_challenge_results`) and are labelled "not live file accuracy".
* The "strong rules 31.7%" tile is a **research baseline**; the rule engine inside the live app scored 13.4% on the same set (finding F-07).
* Scores are raw ensemble-averaged tag probabilities, **uncalibrated**: expected calibration error 0.01 on in-generator dev but 0.07 on the challenge set (spans scored 0.5-0.7 were right about half the time). Verified in the report metadata and by `test_report_and_findings_label_scores_as_uncalibrated`.
* Live-file precision/recall/F1 are not measured (and cannot be computed): no ground truth exists for an uploaded PCAP.

## 5. Findings register and status on `feature/trace-ml-completeness-groundtruth-v1`
The register was produced by the original QA run (PR #15). The engineering follow-up on this branch fixed F-03 to F-11; each former strict `xfail` was turned into a normal passing regression test **without changing its expectation** (the expectation was already "this should work"). F-07 (dashboard labelling) was fixed with the Model Laboratory rework.
| ID | Finding (original) | Status | Regression evidence | Severity |
|---|---|---|---|---|
| F-03 | A JSON key longer than 1,024 characters aborted the **entire** hybrid analysis (`MlValidationError`). | **Fixed.** The field is skipped, counted in `ml_fields_skipped`, the analysis is flagged incomplete, the key is never echoed. | `test_overlong_json_key_is_skipped_counted_and_flagged_not_fatal` | High |
| F-04 | `auth` matched without a word boundary: `author`, `authority`, `authentic` became CREDENTIAL_OR_TOKEN and were hidden from the model. | **Fixed.** Credential keys are matched as tokens (camelCase/punctuation-aware). | `test_author_key_is_not_a_credential_and_reaches_the_model`, `test_genuine_credential_keys_are_still_credentials`, `test_credential_lookalike_keys_are_not_credentials` | Medium |
| F-05 | Losing the **last** segment of a request dropped it with `stream_gaps = 0` and `analysis_incomplete = false`. | **Fixed.** An HTTP-looking unterminated tail is counted (`unterminated_http_messages`) and flags the analysis incomplete. Nothing is inferred from it. | `test_missing_tail_segment_is_flagged_incomplete`, `test_complete_and_non_http_streams_are_not_flagged_unterminated` | High |
| F-06 | Bare `token`, `jwt`, `sid`, `passphrase`, `private_key`, `id_token`, `otp`, `pin` were not credential keys. | **Fixed.** They are credentials (reported masked) and excluded from model input; metadata-style keys such as `token_type`/`max_tokens` are not. | `test_bare_token_parameter_is_a_credential_and_never_reaches_the_model`, `test_genuine_credential_keys_are_still_credentials` | Medium |
| F-07 | The "OFFLINE STRONG RULES F1 31.7%" tile did not say it is a research baseline (live rules: 13.4%). | **Fixed.** `/api/benchmark` serves both comparators with explicit labels (research baseline vs the live rule engine) and the target status; the Model Laboratory renders them. | `test_benchmark_comparators_are_labelled_research_baseline_vs_live_rule_engine` | Low |
| F-08 | `potential_leaks` counted findings, not distinct exposed locations (31 findings / 27 locations in the showcase). | **Fixed (additive).** `potential_leaks` is unchanged for compatibility; `distinct_exposed_locations`, `locations_flagged_by_rules/model/both` are new. No values are retained to compute them. | `test_overlapping_signals_are_reported_as_distinct_locations` | Low |
| F-09 | Undecodable bodies, HTTP/2 and IP fragments produced no findings and no incompleteness flag. | **Fixed.** Bodies not inspected and unsupported/incomplete network states are counted by reason and flag the analysis incomplete. Integrated main supports bounded plaintext HTTP/2 with HPACK: valid control-only traffic has no messages/findings, while unavailable HPACK remains explicitly incomplete. Non-TCP and TLS traffic is counted but is out of scope and does not flag. | `test_undecodable_content_encodings_yield_no_findings_but_are_counted_and_flagged`, `test_decodable_and_empty_bodies_are_not_reported_as_skipped`, `test_http2_control_only_preface_has_no_fabricated_findings`, `test_ip_fragment_is_counted_by_reason_and_flagged_incomplete`, `test_ipv6_extension_header_is_counted_as_possibly_hiding_tcp` | Medium |
| F-10 | `hybrid.py` did not carry the ML package's input-quality flags. | **Fixed.** Gap, capture-incomplete, unterminated and replacement-character flags are passed in `FieldInput.context` (the V2 model ignores context, so predictions are unchanged) and attached to each ML finding as `input_quality`. Fields that are mostly U+FFFD are excluded by policy. | `tests/test_input_quality.py` | Medium |
| F-11 | The static limitation text said wraparound and tuple reuse were unsupported. | **Fixed upstream and here.** Wraparound and reused 4-tuples are handled (`test_sequence_number_wraparound_is_reassembled`, `test_reused_four_tuple_is_split_into_separate_flows_and_both_users_are_found`); the fragment caveat was reworded because fragments are now flagged. | those two tests | Info |

## 6. Known failure modes
* **Model false positives (observed):** currency code `AUD`, ordinary words in a note, city names that are also given names (`Madison`, `Austin`), organisations that look like names (`Morgan Stanley`, `Harper Collins`), a product under `name` (`AirLoom Mini`). On a 20-field adversarial negative set 6 were flagged (30%) - a worst-case set, **not** a false-positive rate for real traffic (`test_company_and_city_false_positives_are_visible_and_labelled_experimental`).
* **Model misses / weak formats:** second and third names in a list, positional CSV (found only at raw score < 0.6), chat-style prefixes (right handle plus a false positive), short cryptic handles under cryptic keys (`v`, `u`), emoji inside a handle truncates the span (`test_known_weak_formats_*`, `test_emoji_inside_a_username_*`).
* **Works as observed (not a guarantee):** unusual field names the rules ignore (`attendee`, `gamertag`, `acct_holder`, `screen_name`), Greek/Korean/Arabic/Cyrillic/accented names with correct code-point offsets, lower/upper-case variants.
* **Network:** tail-segment loss (F-05, now flagged), conflicting overlapping retransmissions (the disputed region is excluded and flagged incomplete, whatever the arrival order), reused 4-tuples (split into separate flows), IP fragments (now flagged), non-HTTP payloads.
* **Rules:** keyword-based; names appear only in fields literally called `full_name|first_name|last_name`; `username|user_name|login` for usernames; F-04/F-06 are fixed.

## 7. Unsupported or unverified protocols / cases
| Case | Status |
|---|---|
| HTTPS/TLS payloads | not decoded (stated in every report); TLS-like bytes produce no messages - tested |
| HTTP/2, HTTP/3/QUIC, WebSocket frames, gRPC | not decoded; HTTP/2 preface tested; the others are **untested** |
| IPv6, UDP, other L4 | counted as unsupported (tested with a UDP + IPv6 frame) |
| IP fragmentation | unsupported; counted by reason and flagged incomplete |
| TCP: reused 4-tuple, tail loss, conflicting payload | reused tuples split into flows; tail loss and conflicting payload are flagged incomplete; conflicting bytes are excluded, not guessed (tested) |
| Content encodings other than gzip/deflate; bodies > 2 MiB | not inspected; counted by reason and flagged incomplete |
| PCAPNG, VLAN/Ethernet variants, jumbo captures | not exercised by this QA suite (other branches own large-capture performance) |
| Base64/URL-encoded/obfuscated PII, PII in headers/cookies for the model | not detected by the model (headers excluded by policy) |

## 8. Demonstrated vs not demonstrated
**Demonstrated by executed tests:** the engine reconstructs the 12 showcase conversations deterministically; rule findings are unaffected by the model; the V2 checkpoint loads and runs on CPU offline with verified integrity; provenance and masking are present and consistent; no fictional credential reaches the model, the default report, logs or stdout; hybrid failure modes and silent-loss cases are characterised; headline numbers shown in the UI equal the committed evaluation and are labelled as offline/synthetic.
**Not demonstrated / unverified:** accuracy on any real capture (no labelled real data exists); false-positive rate on real traffic; behaviour on large or PCAPNG captures with the hybrid enabled; behaviour on HTTP/2+, QUIC and WebSocket; any calibration of model scores (they remain uncalibrated); that any finding corresponds to harm, theft or exfiltration (the tool cannot establish it).

## 9. Prioritised next steps (as originally written; items 1, 3, 4 (F-08/F-10) and 6 (F-11) are done on this branch)
1. **P0 - robustness:** make hybrid skip-and-count over-long keys/fields instead of aborting (F-03); flag an unterminated HTTP message at end of stream as incomplete (F-05). Flip the strict xfails to normal tests.
2. **P0 - evidence quality:** build a small *labelled* PCAP corpus (fictional or consented, replayed through real stacks, with field-level ground truth) so that precision and recall on capture-like data can be measured at all (they cannot be measured today).
3. **P1 - rules:** word-boundary the `auth` pattern and add bare `token|jwt|sid|passphrase|private_key|otp|pin` (F-04, F-06); both change what the model sees.
4. **P1 - hybrid semantics:** de-duplicate/merge overlapping rule+ML findings for display and counts (F-08); pass the ML package's `input_policy` quality flags into findings (F-10); decide whether header fields (e.g. `From:`, `X-Forwarded-User`) should reach the model.
5. **P1 - model:** fresh `challenge_v2`, then add the formats the failure analysis shows are missing (CSV rows, name lists, chat prefixes) and person-named organisations/cities as hard negatives; keep the 0.88 target honest.
6. **P2 - labelling:** relabel the "strong rules" tile (F-07); refresh the static limitation text (F-11).
7. **P2 - coverage:** HTTP/2 and WebSocket detection of *presence* (even without decoding) so "no findings" can say "unsupported traffic present"; brotli/zstd decoding or an explicit skipped-body counter.

## 10. Reproduce
```bash
git switch feature/trace-independent-vp-qa
python -m pytest -q tests/test_vp_qa_*.py -rx        # real V2 ensemble required for the model tests (needs PyTorch); others run without it
```
