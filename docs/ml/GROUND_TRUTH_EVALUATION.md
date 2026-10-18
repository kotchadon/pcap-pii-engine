# File-specific ground-truth evaluation

TRACE can score its detections for **one specific capture** when an independent, verified annotation manifest for that capture is supplied. Without a manifest, TRACE reports **no** accuracy for an uploaded file: "File-specific accuracy unavailable: no verified ground-truth annotations provided."

These numbers are **not** the offline benchmark. The 81.8 % F1 (95 % CI 79.4-84.0) in `V2_EVALUATION.md` is a different, synthetic, 1,058-field challenge set and says nothing about any uploaded file. Nothing in this document is a claim about real-world production accuracy.

## What is evaluated

* Labels: `PERSON_NAME` and `USERNAME` only (the two labels the contextual model emits). Rule findings of other types (email, phone, card, IP, credential) are counted by type under `out_of_scope_detections`; they are neither true nor false positives here.
* Unit: an **exact span** inside one decoded HTTP field: same message, same field, same label, same start and end (Unicode code points). A boundary near-miss is one false positive **and** one false negative.
* Systems, scored on the same fields:
  * `rules_only` - the deterministic rules. The key-based rules (`username`/`login`, `full_name`/`first_name`/`last_name`) flag the whole field value, so they are scored as whole-field spans.
  * `model_only` - contextual BiLSTM predictions only.
  * `rules_plus_model` - union of both; an identical span from both counts once (`true_positives_by_detector` shows `bilstm+rule`).
* Fields the model is not allowed to see by policy (HTTP headers, credential-named fields) **are scored**: a gold span there is a model false negative of type `excluded_by_policy`.

## Manifest (`schemas/ground-truth-v1.schema.json`)

A manifest binds annotations to one capture and to the exact decoded text of every annotated field:

* `capture.sha256` - the evaluator refuses to run on a file with a different SHA-256 (or size).
* Each field is addressed by `flow.client`/`flow.server` (`ip:port`), optional `flow.session`, `message.type`, `message.ordinal` (1-based among same-direction messages), `location` (e.g. `json_body.profile.displayName`) and `occurrence`; it carries `text_sha256` and `text_length` of the decoded text, so an annotation can never silently attach to different data.
* `spans` are `{start, end, label}`; an **empty list is an explicit negative** that contributes false positives.
* `provenance.label_source` is `constructed_by_generator` or `human_annotation`; `labels_derived_from_model_output` must be the literal `false`. The evaluator never generates reference labels from any detector.
* `annotation_scope`: `all_fields_in_listed_messages` (every extracted field of each listed message must be listed; otherwise the result is partial) or `listed_fields_only`.
* Validation is strict (unknown properties rejected, span bounds, no overlapping spans, unique ids and addresses, ≤ 16 MiB, ≤ 100,000 fields). The Python validator needs no extra dependency; `jsonschema` is only used by tests.

## Result semantics

* `status: complete` - every manifest field was aligned and every requested system could score it. `status: partial` - some could not be scored; the result says so in `scope` and lists the reasons. **Partial metrics are never full-file accuracy.**
* Unaligned fields: `message_not_found`, `field_not_found`, `text_mismatch`. If nothing aligns the evaluation is rejected.
* Model systems exclude fields the model never evaluated because a work budget skipped them (`unscored_fields: {"skipped:field_budget": n}`); rules-only still scores them.
* Precision/recall/F1 per label, micro and macro. Zero denominators are `null` with an explanation, never 0 or 1: precision is undefined with no predictions, recall with no gold spans, F1 if either is. Macro averages the labels that have gold support and is `null` if any averaged value is undefined.
* 95 % Wilson intervals are given for precision and recall, treating spans as independent. No F1 interval is computed, and with ~60 gold spans the intervals are wide.
* Error samples contain field ids and offsets only. The exported JSON never contains field text, values or locations.
* The result records SHA-256 of capture and manifest, model version, analysis/schema versions, ML work limits, UTC timestamp and scope notes. Export with `pcap-pii-evaluate ... -o result.json` (mode 0600, refuses overwrite unless asked).

## Controlled fixture (`examples/groundtruth/`)

`generate_groundtruth_fixture.py` builds a deterministic, fully fictional capture and manifest: 144 HTTP messages (72 request/response pairs) in 70 TCP conversations (JSON, form, query strings, gzip and chunked bodies, keep-alive pairs, response bodies, free-text mentions, Unicode and hyphenated names). **740 fields: 61 contain 64 gold spans (39 PERSON_NAME, 25 USERNAME); 679 are explicit negatives**, among them 45 hard-negative fields (companies, places, products, identifier / given-name / title look-alikes, UI labels, contact points).

* Labels are constructed: the script inserts each name, records its span while building the text, and imports nothing from TRACE or any model (a test asserts this).
* The scenario table was written before any model was run on it and is **frozen**. After the first V2 run an evaluator bug was found (fields excluded by model policy had not been recorded, so 499 fields were wrongly unscored); the bug was fixed and the run repeated. The fixture was not touched, and the first run's numbers are not reported.
* Independence check (`scripts/groundtruth/check_overlap.py`, run before evaluating): none of the 64 gold strings appears verbatim as a labelled span in V2's train, validation, calibration or challenge data. Common first names and templates inevitably resemble training data; this is a leakage check, not a proof of independence.
* The capture is 47 KB (SHA-256 `16591312ec3884b5e94daeeeed153bc636031e07ac84d4a93562382135cccdea`), the manifest SHA-256 is `8c540feb5399cc576c237af395f7508cb1620c3cae8d6f2a2cf5f882dc53a30a`. A test regenerates both byte-for-byte.

### Result: V2 (`bilstm-v2-d1f9e9fb9a2b`, `min_score` 0.35), `standard` ML budget, status **complete**

All 740 fields aligned; the model evaluated all 241 eligible fields (coverage complete); `analysis_incomplete` is false.

| System | TP | FP | FN | Precision (95 % CI) | Recall (95 % CI) | F1 (micro) | Macro F1 |
|---|---|---|---|---|---|---|---|
| rules only | 11 | 1 | 53 | 0.917 (0.646-0.985) | 0.172 (0.099-0.282) | 0.290 | 0.295 |
| **model only (V2)** | 48 | 31 | 16 | 0.608 (0.497-0.708) | 0.750 (0.632-0.840) | **0.671** | 0.714 |
| rules + model | 48 | 32 | 16 | 0.600 (0.491-0.700) | 0.750 (0.632-0.840) | 0.667 | 0.706 |

Per label (model only): PERSON_NAME TP 26 / FP 27 / FN 13 (P 0.491, R 0.667, F1 0.565); USERNAME TP 22 / FP 4 / FN 3 (P 0.846, R 0.880, F1 0.863).

Errors (model only), every one listed by type in the result file:

* **Boundary mismatches: 10 FP + 10 FN** (each near-miss costs both). In 9 of the 10, the model stops at a hyphen inside a surname (`Okonkwo-Hale` predicted as `Okonkwo`); the tenth extends a first name over the following word. 16 of the 39 gold person names contain a hyphen (41 %; a deliberate diversity choice that, in hindsight, over-represents the pattern), and the model cut 9 of those 16 at the hyphen. This weakness therefore weighs heavily on this fixture; do not read it as a rate for real traffic.
* **False positives in negative fields: 21** (of 679 negatives; 12 in hard-negative categories, 9 among 143 ordinary body negatives; none among the 491 header negatives). Hard-negative categories with at least one false positive: company names 1/6, given-name look-alikes 2/5, identifier look-alikes 2/7, organisation/place 2/5, place names 2/6, product names 2/3, title look-alike 1/1.
* **Misses: 4**, and **2 policy exclusions** (names in custom headers, which the model never sees by policy; the rules do not catch them either).
* Rules only: 1 false positive (the literal label text `Username` in a field called `username_field_label`), 53 misses; the rules have no generic name detector, so recall is low by construction.
* Combining rules with the model added one false positive and no true positives over the model alone: the rules' 11 true positives are a subset of the model's.

With 64 gold spans the intervals are wide, the fixture is synthetic and hand-designed, and one pattern (hyphenated surnames, 41 % of gold person names) is over-represented. These are honest, reproducible measurements on this file - not an accuracy figure for TRACE.

## VP showcase annotated as a demonstration (`showcase_demo.manifest.json`)

The 12-conversation showcase was designed by the TRACE team. Its hand annotations (12 fields: 9 gold spans, 3 deliberate negatives, `annotation_scope: listed_fields_only`) demonstrate the evaluator on a familiar file. They are labelled `hand_designed_demonstration` and are **not an independent benchmark**.

| System | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| rules only | 4 | 0 | 5 | 1.000 | 0.444 | 0.615 |
| model only (V2) | 8 | 2 | 1 | 0.800 | 0.889 | 0.842 |
| rules + model | 9 | 2 | 0 | 0.818 | 1.000 | 0.900 |

The two model false positives are the deliberate negatives `Johnson & Johnson` and `Madison` (the known failure modes the showcase was built to show). Nine spans cannot support any general claim.

## Reproduce

```bash
python -m pip install -e '.[ml]'
python examples/generate_groundtruth_fixture.py /tmp/gt          # byte-identical to examples/groundtruth/*
python scripts/groundtruth/check_overlap.py                      # leakage check against V2 data
pcap-pii-evaluate examples/groundtruth/controlled_fixture_v1.pcap \
    examples/groundtruth/controlled_fixture_v1.manifest.json \
    --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2 -o /tmp/result.json
python scripts/groundtruth/build_showcase_manifest.py            # regenerates the showcase manifest
```

Committed results: `docs/ml/results/groundtruth_controlled_v1_v2.json`, `docs/ml/results/groundtruth_showcase_demo_v2.json`. `tests/test_groundtruth.py` recomputes them (tolerating one borderline span per count across platforms) and fails if the evaluator, fixture or model drift.

## What this does not show

* Accuracy on any real or third-party capture, on other entity types, or on HTTPS, HTTP/2, QUIC or non-HTTP traffic.
* Calibration: model scores remain uncalibrated raw scores; none is used here.
* Anything about the model beyond V2 on this file. Per the milestone rules, the model, its threshold and the existing evaluation results were not changed, and the fixture was not adapted after seeing model errors.
