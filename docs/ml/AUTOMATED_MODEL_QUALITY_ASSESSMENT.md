# Automated Model Quality Assessment (context-matched synthetic probes)

Every completed **AI-assisted hybrid** scan now automatically produces model-quality diagnostics, with no manifest and no user action. The headline is named **Context-matched synthetic probe F1**. It is *not* precision, recall or F1 on the uploaded capture: that capture is unlabelled, and a model cannot be its own ground truth. When an independent ground-truth manifest *is* supplied, the genuine manifest-based evaluation (`GROUND_TRUTH_EVALUATION.md`) remains a separate, higher-evidence section and is never combined with probe metrics. The offline 81.8 % benchmark is likewise separate.

Required disclosure, shown directly with the metrics: *"These metrics are measured on automatically generated, labelled synthetic probes matched to aspects of this capture's structure. They are not precision, recall or F1 measured on the original uploaded traffic."*

## Architecture and lifecycle

```
upload ─▶ scan job (unchanged: rules + bounded ML, streamed report) ──▶ status "completed"  (analysis lock released)
              │ same pass, in-memory only
              └─ ContextSampler (enums + counters)  ──▶ context summary
                                                         │
                separate thread, own budget, no analysis lock
                                                         ▼
              generate_suite (deterministic, frozen, hashed) ─▶ real V2 via the bounded MLBatchRunner ─▶ exact-span scoring
              + stability variants + rules disagreement + boundary tags + applicability ─▶ job.assessment
```

* States: `pending`, `running`, `complete`, `partial`, `failed`, `cancelled`, `unavailable`. Rules-only scans, scans with no eligible fields, and servers started with `--assessment-probes 0` are `unavailable` with a reason and **no metrics**.
* The stage starts only after the scan is already `completed`, runs in its own thread, and does **not** hold the analysis lock. Detector calls are serialised per batch (`SharedDetector`), so a new scan never waits for the whole assessment.
* A probe failure, cancellation or timeout leaves the completed scan report, its coverage and `analysis_incomplete` untouched; the failure message is generic (no model or field text).
* Starting a new scan cancels the previous scan's running assessment. Results are job-scoped (`GET /api/jobs/<id>/assessment`, `POST /api/jobs/<id>/assessment/cancel`); the UI clears assessment state when a new scan begins, so a failed or cancelled scan cannot show earlier scores.
* No second capture scan and no re-inference of original fields: the summary is collected during the one scan. Original-scan and assessment have separate elapsed times and counters (`workload`, `budget`); probe counts never enter the report's ML coverage numbers.

## Privacy-safe context sampling

Only bounded structural metadata is kept; **no raw field value, field name, URL, IP or credential** is stored or exported. Per stratum `(location category, name class, nesting depth, direction, HTTP method class, body-encoding class)` the summary holds a count, shape buckets (single/two/few/sentence tokens), length buckets, and three flags (non-ASCII, digit, separator). Field names are *classified*, never copied: a leaf is mapped to an allowlisted generic word (e.g. `author`, `user`, `message`) or to `value`. Policy-excluded fields (headers, credential-like names) are counted but not sampled. The summary does not grow with the capture (a 48,000-field stress capture yields a summary under 30 KB, asserted by a test) and is order-independent.

Strata are chosen by a defined, prediction-independent rule: round-robin over location categories (alphabetical), within a category by descending count then key, up to `max_strata`.

## Independent probe construction

`generate_suite(summary, budget, seed)` takes no detector. For each sampled context it builds, from fixed fictional pools and a SHA-256 of `(seed, context, case)`:

* **Positives:** full names, hyphenated surnames, Unicode names, single-token names (where plausible), names inside sentences; usernames with letters/digits/underscores, with periods/hyphens, and embedded `@mentions`/log lines - also under non-name field classes (ambiguous contexts).
* **Hard negatives:** companies, places (incl. given-name look-alikes), products, technical identifiers, log messages, UI labels, dates/times, person-like look-alikes (`Johnson & Johnson`, `Madison Avenue`).

Spans are constructed with the text. Gold never comes from model output, confidence, rules or ensemble agreement. The suite is frozen: its hash (`probe_set_hash`) is recorded, re-verified after inference, and never edited from results. Generator `probe-gen/1`, templates `probe-templates/1`, default seed `20250602`. A test verifies that no pool string (all name/username combinations) appears verbatim among V2's train, validation, calibration or challenge gold spans; eight single first names that did overlap were replaced **before** the reported runs.

## Metrics

Exact-span, same convention and code as the ground-truth evaluator (`groundtruth.prf`, its false-positive/false-negative classifier): TP/FP/FN, precision, recall, micro F1, per label (PERSON_NAME, USERNAME), zero denominators are `null` with an explanation. Boundary near-misses (overlapping, same label, different bounds) are counted **separately** as `near_miss_*` and get no true-positive credit. False positives on negative probes are reported with a Wilson interval. The headline interval is a **cluster bootstrap over probe contexts** (400 rounds, deterministic), shown only with ≥ 8 contexts; it understates uncertainty because template-generated probes are dependent.

Diagnostics (never accuracy): *stability* (predictions unchanged under trailing period / `Note: ` prefix / quotes on ≤ 90 base probes), *boundary sensitivity* by tag (hyphenated, unicode, single-token, embedded, ...), *independent-detector disagreement* against the deterministic rules (mechanistically distinct from the BiLSTM; counts only, neither is truth; the three ensemble members are **not** used as independent validators), and *applicability* (share of eligible fields covered by sampled contexts; `limited` if < 60 % coverage, < 3 contexts, > 50 % of fields policy-excluded, or unscored probes).

Partial runs: unscored probes (time/field budget, policy exclusion) are listed by reason; status is `partial` and metrics describe the scored subset only; if nothing could be scored the status is `failed` and no metrics appear.

## Resource use (defaults, MacBook Air-sized)

`max_probes` 480, `max_characters` 60,000, model time 20 s, 128 fields/batch, 24 contexts, 90 stability bases (+270 variant fields), output ≤ 200 KB; absolute ceilings enforced. Measured here: the 188-probe reproduction case runs in 0.3 s (0.12 s model time, 2 batches); the 203-probe showcase assessment in 0.7 s after the scan; the memory is a few KB of probe text plus the summary. Peak process memory is dominated by the model, which is already loaded.

## Reproduction case (fictional)

`python scripts/probe/reproduce.py [--model]` builds a structural summary from made-up shapes (`examples/probe/reproduction_summary.json`), the frozen suite metadata (`reproduction_suite_meta.json`, probe-set hash `404b056e...2481`, 188 probes: 92 positive / 96 negative) and, with `--model`, the real V2 result `docs/ml/results/probe_reproduction_v2.json`. Tests regenerate the hash exactly and recompute V2 within a one-or-two-span tolerance.

| Real V2 (`bilstm-v2-d1f9e9fb9a2b`) on the reproduction suite | value |
|---|---|
| Context-matched synthetic probe F1 | **0.539** (cluster-bootstrap 0.500-0.576) |
| Precision / recall | 0.515 / 0.565 (TP 52, FP 49, FN 40) |
| PERSON_NAME P / R / F1 | 0.465 / 0.589 / 0.520 |
| USERNAME P / R / F1 | 0.633 / 0.528 / 0.576 |
| Near-miss FN / FP (shown apart) | 7 / 7 (mostly hyphenated surnames) |
| Negative probes with a prediction | 37 of 96 (38.5 %) |
| Usernames written `word.word-NN` | 0 of 12 found exactly |
| Stability (identical predictions) | quoted 91 %, label prefix 81 %, trailing period 76 % |

These are measurements of V2 on synthetic probes: they reveal weaknesses (separator usernames, hyphenated surnames, look-alike negatives) but are not an estimate of accuracy on any real capture. The probe suite was not changed after seeing results.

## Failure modes and limits

No eligible contexts, all probes excluded/skipped, model failure, cancellation, or an oversized output → no metrics (reason shown). Probe values are synthetic and template-based; method/direction/encoding strata do not change the model's input. Contexts whose field names are not in the allowlist are probed under the neutral name `value`, so unusual vocabularies are under-represented (see applicability). The assessment says nothing about HTTPS, HTTP/2 or non-HTTP traffic, and it cannot detect a model that is good on probes but poor on real data.
