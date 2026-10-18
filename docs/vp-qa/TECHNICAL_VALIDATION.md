# TRACE - independent technical validation (QA)

**Scalability follow-up (2026-10-18):** F-03 and F-05 are addressed on
`feature/trace-scalable-ml-engine`. Their former strict xfails are now required
regressions: overlong paths are skipped with a reason, and incomplete request
framing sets `analysis_incomplete`. Response body framing without request-method
context remains explicit uncertainty (HEAD/CONNECT). The original measured
model results and findings register below are historical QA evidence, not a
fresh benchmark of this branch. See `../integration/ML_COVERAGE_CONTRACT.md`.

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
* **Three kinds of test:** (a) *invariants* (counts, provenance, masking, rules unchanged by ML) - hard assertions; (b) *characterisation* of research-model outputs, pinned to the checkpoint version - honest records of hits, misses and false positives, never forced positive; (c) `xfail(strict=True)` for behaviour a reviewer would expect but which is **not** delivered today (findings F-03..F-07) - if another engineer fixes it, the test goes red and the document must be updated.
* **Own PCAP builder** (`test_vp_qa_support.py`) so tests do not depend on another engineer's fixture helpers, except where the showcase itself is under test.
* **Spy detector** records exactly what is handed to a model, so secret-handling is verified independent of any model.
* **Inventory (100 tests; 95 pass, 5 strict xfail):** live showcase 21 · model-ready/zero-findings 6 · adversarial 34 · TCP uncertainty 17 · secrets 7 · scientific claims 15.
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
* 3 field locations are flagged by both rules and ML, so 31 findings cover 27 distinct field locations (`test_overlapping_signals_are_counted_twice_in_potential_leaks`); the UI says signals may overlap.

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

## 5. Findings register (new, from this QA; none fixed here)
| ID | Finding | Evidence (test) | Severity | Suggested owner |
|---|---|---|---|---|
| F-03 | A JSON key longer than 1,024 characters aborts the **entire** hybrid analysis (`MlValidationError` from `FieldInput`); rules-only completes. The dashboard would report "Capture rejected". | `test_overlong_json_key_preserves_analysis_and_valid_following_field` + strict xfail | High (input-triggered failure) | hybrid / backend |
| F-04 | `SECRET_KEYS` matches `auth` without a word boundary: `author`, `authority`, `authentic` become CREDENTIAL_OR_TOKEN and the field is also excluded from the model - a person's name under `author` is labelled a credential. | `test_author_key_is_classified_as_credential_and_never_reaches_the_model` + strict xfail | Medium | rules |
| F-05 | Losing the **last** segment of a request drops the whole request while `stream_gaps = 0` and `analysis_incomplete = false`. Head/middle loss is correctly flagged. | `test_missing_tail_segment_is_observable_http_incompleteness` + strict xfail | High (silent evidence loss) | network |
| F-06 | Bare `token`, `jwt`, `sid`, `passphrase`, `private_key`, `id_token`, `otp`, `pin` are not credential keys: `?token=...` is neither reported as a credential nor excluded from the model's input (the default report still does not echo it). | `test_bare_token_parameter_is_not_recognised_as_a_credential_current_behaviour` + strict xfail | Medium | rules / hybrid |
| F-07 | Dashboard tile "OFFLINE STRONG RULES F1 31.7%" does not say it is a research baseline (live rules: 13.4%). | `test_strong_rules_figure_is_a_research_baseline_not_the_live_rules_engine` + strict xfail | Low (labelling) | frontend |
| F-08 | `potential_leaks` counts findings, not distinct exposed values (31 findings / 27 locations in the showcase). | `test_overlapping_signals_are_counted_twice_in_potential_leaks` | Low | backend / frontend |
| F-09 | Undecodable bodies (`Content-Encoding: br`/`zstd`, corrupt gzip, expansion > 2 MiB) and HTTP/2 yield no findings and **no** incompleteness flag; IP fragments are counted as unsupported but also not flagged incomplete. | `test_undecodable_content_encodings_*`, `test_http2_*`, `test_ip_fragment_*` | Medium | network |
| F-10 | `hybrid.py` does not use the ML package's input-quality policy: upstream truncation/gap/replacement-character flags are not passed to the model or attached per finding; only the capture-level `analysis_incomplete` exists. | code read + `test_hybrid_mode_does_not_launder_an_incomplete_capture` (flag preserved globally) | Medium | hybrid |
| F-11 | The static limitation string still says "No ... sequence wraparound/reused-tuple separation"; wraparound actually reassembles correctly in test, reused 4-tuples lose data but are flagged incomplete. | `test_sequence_number_wraparound_is_reassembled`, `test_reused_four_tuple_*` | Info | network |

## 6. Known failure modes
* **Model false positives (observed):** currency code `AUD`, ordinary words in a note, city names that are also given names (`Madison`, `Austin`), organisations that look like names (`Morgan Stanley`, `Harper Collins`), a product under `name` (`AirLoom Mini`). On a 20-field adversarial negative set 6 were flagged (30%) - a worst-case set, **not** a false-positive rate for real traffic (`test_company_and_city_false_positives_are_visible_and_labelled_experimental`).
* **Model misses / weak formats:** second and third names in a list, positional CSV (found only at raw score < 0.6), chat-style prefixes (right handle plus a false positive), short cryptic handles under cryptic keys (`v`, `u`), emoji inside a handle truncates the span (`test_known_weak_formats_*`, `test_emoji_inside_a_username_*`).
* **Works as observed (not a guarantee):** unusual field names the rules ignore (`attendee`, `gamertag`, `acct_holder`, `screen_name`), Greek/Korean/Arabic/Cyrillic/accented names with correct code-point offsets, lower/upper-case variants.
* **Network:** tail-segment loss (F-05), conflicting retransmissions resolved by first arrival and flagged incomplete, reused 4-tuples, IP fragments, non-HTTP payloads.
* **Rules:** keyword-based; names appear only in fields literally called `full_name|first_name|last_name`; `username|user_name|login` for usernames; F-04/F-06.

## 7. Unsupported or unverified protocols / cases
| Case | Status |
|---|---|
| HTTPS/TLS payloads | not decoded (stated in every report); TLS-like bytes produce no messages - tested |
| HTTP/2, HTTP/3/QUIC, WebSocket frames, gRPC | not decoded; HTTP/2 preface tested; the others are **untested** |
| IPv6, UDP, other L4 | counted as unsupported (tested with a UDP + IPv6 frame) |
| IP fragmentation | unsupported; counted, not flagged (F-09) |
| TCP: reused 4-tuple, tail loss, conflicting payload | data loss or arrival-dependent result (tested); only some are flagged |
| Content encodings other than gzip/deflate; bodies > 2 MiB | silently not inspected (F-09) |
| PCAPNG, VLAN/Ethernet variants, jumbo captures | not exercised by this QA suite (other branches own large-capture performance) |
| Base64/URL-encoded/obfuscated PII, PII in headers/cookies for the model | not detected by the model (headers excluded by policy) |

## 8. Demonstrated vs not demonstrated
**Demonstrated by executed tests:** the engine reconstructs the 12 showcase conversations deterministically; rule findings are unaffected by the model; the V2 checkpoint loads and runs on CPU offline with verified integrity; provenance and masking are present and consistent; no fictional credential reaches the model, the default report, logs or stdout; hybrid failure modes and silent-loss cases are characterised; headline numbers shown in the UI equal the committed evaluation and are labelled as offline/synthetic.
**Not demonstrated / unverified:** accuracy on any real capture (no labelled real data exists); false-positive rate on real traffic; behaviour on large or PCAPNG captures with the hybrid enabled; behaviour on HTTP/2+, QUIC and WebSocket; any calibration of model scores (they remain uncalibrated); that any finding corresponds to harm, theft or exfiltration (the tool cannot establish it).

## 9. Prioritised next steps
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
