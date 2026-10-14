# V2 evaluation

Everything below is regenerated from `docs/ml/results/v2_eval_*.json` by `scripts/ml/render_v2_docs.py`. Metric: **exact span + label**
(`start`, `end`, `label` all equal), micro over PERSON_NAME and USERNAME; macro = mean of the two per-label F1. CIs: percentile bootstrap over
examples (1,000 resamples; paired for differences). All data is synthetic.

## 1. Headline

| Question | Answer |
|---|---|
| Did the improved contextual model reach **>= 0.88** exact-span micro-F1 on an independent held-out set? | **No.** Frozen out-of-generator challenge benchmark (1,058 fields): **0.818** (95% CI 0.794-0.840); V1 was 0.559 on the same set. |
| Where was it >= 0.88? | V2 development val/calib (0.958 / 0.946; **in-generator, selection data - not an independent result**) and the V1 frozen test (0.927; Regime A, V2 never trained on that generator, reported once). |
| BiLSTM-only vs strong rules, **same frozen set** | Challenge: 0.818 vs 0.317 (BiLSTM wins, paired dF1 +0.501, CI +0.459..+0.539). V1 test: 0.927 vs 0.908 (BiLSTM wins by +0.020, CI +0.005..+0.035). The stretch objective (> 0.908 strong-rules F1) is met on the V1 frozen test, where strong rules score exactly 0.908. |
| Does a rules-first hybrid help? | **Depends on the benchmark.** V1 test: yes (rules-first 0.948 > rules 0.908 and > BiLSTM 0.927). Challenge and V2 dev: **no** - the hybrid is far above rules-only but *below* BiLSTM-only (0.801 vs 0.818 on the challenge) because the rules add false positives faster than true detections. |
| Is the score a probability? | No. Raw tag-probability average; labelled `uncalibrated_model_score`. ECE of score vs span correctness: dev 0.0102, challenge 0.072 (over-confident under shift). |

Do **not** read the 0.958 / 0.946 dev numbers or the V1-test 0.927 as real-world accuracy.

## 2. Systems compared (identical inputs, identical metric)
* **Strong key-aware rules** - `baseline.strong_rules`, definition unchanged since V1 (historical comparison). Authored from general knowledge of key names and
  textual cues before any model result existed. It was not modified for V2.
* **Host engine `detect.py`** - the real `packet_pii.detect.detect_fields` (called read-only from the evaluation script): USERNAME for `username|user_name|login`
  keys and PERSON_NAME_CANDIDATE for `full_name|first_name|last_name` keys, whole value. Different (much narrower) coverage than the strong baseline.
* **BiLSTM V1** - unchanged V1 checkpoint (sha256 `972a87f2...495d6a`), `min_score` 0.25.
* **BiLSTM V2** - 3-member probability-averaging ensemble of V1-architecture BiLSTMs trained on V2.2 data; `min_score` 0.35 (chosen on V2 calib).
* **Hybrids** (evaluation-only; no engine change): *rules-first* keeps every strong-rule span and adds an ML span only if it overlaps no rule span and its raw score >= tau_add;
  *rules-first + veto* additionally drops ambiguous-key (`name`, `author`) rule spans that ML does not confirm at tau_veto; *union* is the naive set union.
  Thresholds chosen on V2 calib: {"tau_add": 0.35, "tau_union": 0.35, "tau_veto": 0.0} (tau_veto 0.0 = veto never helped on calib).
  Rule heuristics and ML scores are never merged into one number.

## 3. Independent challenge benchmark (frozen, out-of-generator synthetic; 1,058 fields, 504 PERSON_NAME + 324 USERNAME entities, 313 entity-free)
| System | P | R | micro-F1 | 95% CI (bootstrap) | macro-F1 | PERSON F1 (n) | USERNAME F1 (n) | FP | FN |
|---|---|---|---|---|---|---|---|---|---|
| Majority (predict nothing) | 0.000 | 0.000 | **0.000** | 0.000-0.000 | 0.000 | 0.000 (504) | 0.000 (324) | 0 | 828 |
| Strong key-aware rules (historical baseline, unchanged) | 0.742 | 0.202 | **0.317** | 0.279-0.352 | 0.332 | 0.263 (504) | 0.400 (324) | 58 | 661 |
| Host engine `detect.py` (actual) | 0.895 | 0.072 | **0.134** | 0.104-0.167 | 0.141 | 0.107 (504) | 0.175 (324) | 7 | 768 |
| BiLSTM V1 (`bilstm-v1-972a87f2b6db`) | 0.683 | 0.473 | **0.559** | 0.523-0.593 | 0.561 | 0.556 (504) | 0.566 (324) | 182 | 436 |
| **BiLSTM V2** ensemble (`bilstm-v2-d1f9e9fb9a2b`) | 0.836 | 0.801 | **0.818** | 0.794-0.840 | 0.829 | 0.787 (504) | 0.871 (324) | 130 | 165 |
| Hybrid rules-first + V2 | 0.804 | 0.798 | **0.801** | 0.777-0.824 | 0.812 | 0.771 (504) | 0.853 (324) | 161 | 167 |
| Hybrid rules-first + veto + V2 | 0.812 | 0.798 | **0.805** | 0.781-0.828 | 0.815 | 0.777 (504) | 0.853 (324) | 153 | 167 |
| Hybrid union + V2 (naive) | 0.793 | 0.807 | **0.800** | 0.776-0.823 | 0.814 | 0.763 (504) | 0.865 (324) | 174 | 160 |
| V2 member seed 11 | 0.842 | 0.752 | **0.795** | 0.770-0.819 | 0.805 | 0.766 (504) | 0.845 (324) | 117 | 205 |
| V2 member seed 12 | 0.794 | 0.786 | **0.790** | 0.767-0.813 | 0.800 | 0.762 (504) | 0.837 (324) | 169 | 177 |
| V2 member seed 13 | 0.830 | 0.786 | **0.808** | 0.784-0.829 | 0.819 | 0.773 (504) | 0.866 (324) | 133 | 177 |

Seed variation (single members, challenge): mean 0.7974 +/- 0.0075 (values [0.7946, 0.79, 0.8077]); the 3-member ensemble is 0.818.

Recall on unseen context / hard negatives (unseen = relative to the V2 training set):

| System | recall: unseen-key fields (n) | recall: seen-key | recall: unseen context (n) | recall: seen context | FP rate on entity-free fields | FP rate on hard-negative fields |
|---|---|---|---|---|---|---|
| Strong key-aware rules (historical baseline, unchanged) | 0.2809 (178) | 0.18 | 0.048 (375) | 0.3289 | 0.1022 | 0.1371 |
| Host engine `detect.py` (actual) | 0.1348 (178) | 0.0554 | 0.0 (375) | 0.1325 | 0.0 | 0.0 |
| BiLSTM V1 (`bilstm-v1-972a87f2b6db`) | 0.7079 (178) | 0.4092 | 0.32 (375) | 0.6004 | 0.2588 | 0.2893 |
| **BiLSTM V2** ensemble (`bilstm-v2-d1f9e9fb9a2b`) | 0.8258 (178) | 0.7938 | 0.6693 (375) | 0.9095 | 0.2173 | 0.264 |
| Hybrid rules-first + V2 | 0.8315 (178) | 0.7892 | 0.672 (375) | 0.9029 | 0.2524 | 0.3147 |

F1 by data source / field type (challenge):

| source | Strong key-aware rules (historical baseline, unchanged) | BiLSTM V1 (`bilstm-v1-972a87f2b6db`) | BiLSTM V2 ensemble (`bilstm-v2-d1f9e9fb9a2b`) | Hybrid rules-first + V2 |
|---|---|---|---|---|
| chat | 0.368 | 0.558 | 0.678 | 0.678 |
| csv | 0.000 | 0.000 | 0.364 | 0.364 |
| email | 0.421 | 0.226 | 0.806 | 0.763 |
| form | 0.710 | 0.819 | 0.904 | 0.904 |
| header | 0.000 | 0.691 | 0.974 | 0.974 |
| json_neg | 0.000 | 0.000 | 0.000 | 0.000 |
| json_nested | 0.515 | 0.763 | 0.919 | 0.888 |
| log | 0.222 | 0.303 | 0.880 | 0.822 |
| narrative | 0.060 | 0.280 | 0.685 | 0.687 |
| query | 0.311 | 0.750 | 0.903 | 0.917 |
| short | 0.000 | 0.581 | 0.970 | 0.970 |
| sql | 0.000 | 0.593 | 0.571 | 0.571 |
| vcs | 0.000 | 0.000 | 0.880 | 0.880 |
| xml | 0.000 | 0.700 | 0.960 | 0.960 |
| yaml | 0.000 | 0.300 | 0.765 | 0.743 |

Hybrid contribution on the challenge (vs the strong-rules system alone):

| Hybrid policy | micro-F1 | extra true detections vs rules | extra false positives vs rules | rule detections lost | dF1 vs rules (95% CI) | dF1 vs BiLSTM-only |
|---|---|---|---|---|---|---|
| Hybrid rules-first + V2 | 0.801 | 494 | 103 | 0 | +0.484 (+0.446, +0.519) | -0.017 |
| Hybrid rules-first + veto + V2 | 0.805 | 494 | 95 | 0 | +0.488 (+0.449, +0.522) | -0.013 |
| Hybrid union + V2 (naive) | 0.800 | 501 | 116 | 0 | +0.483 (+0.445, +0.518) | -0.018 |

BiLSTM V2 raw-score threshold sweep (challenge):

| min_score | 0.00 | 0.10 | 0.25 | 0.50 | 0.75 | 0.90 | 0.97 |
|---|---|---|---|---|---|---|---|
| precision | 0.836 | 0.836 | 0.836 | 0.839 | 0.899 | 0.949 | 0.976 |
| recall | 0.801 | 0.801 | 0.801 | 0.789 | 0.713 | 0.629 | 0.542 |
| f1 | 0.818 | 0.818 | 0.818 | 0.813 | 0.795 | 0.757 | 0.697 |

## 4. Regime A - V1 frozen test (V1 generator, seed 1234; evaluated once with the predeclared protocol, never used for V2 selection)
| System | P | R | micro-F1 | 95% CI (bootstrap) | macro-F1 | PERSON F1 (n) | USERNAME F1 (n) | FP | FN |
|---|---|---|---|---|---|---|---|---|---|
| Majority (predict nothing) | 0.000 | 0.000 | **0.000** | 0.000-0.000 | 0.000 | 0.000 (1147) | 0.000 (795) | 0 | 1942 |
| Strong key-aware rules (historical baseline, unchanged) | 0.973 | 0.851 | **0.908** | 0.896-0.918 | 0.914 | 0.877 (1147) | 0.951 (795) | 46 | 290 |
| Host engine `detect.py` (actual) | 1.000 | 0.185 | **0.312** | 0.288-0.336 | 0.324 | 0.233 (1147) | 0.415 (795) | 0 | 1583 |
| BiLSTM V1 (`bilstm-v1-972a87f2b6db`) | 0.802 | 0.714 | **0.755** | 0.740-0.770 | 0.753 | 0.763 (1147) | 0.744 (795) | 341 | 556 |
| **BiLSTM V2** ensemble (`bilstm-v2-d1f9e9fb9a2b`) | 0.909 | 0.946 | **0.927** | 0.917-0.936 | 0.931 | 0.905 (1147) | 0.958 (795) | 185 | 104 |
| Hybrid rules-first + V2 | 0.916 | 0.982 | **0.948** | 0.939-0.956 | 0.950 | 0.939 (1147) | 0.960 (795) | 174 | 36 |
| Hybrid rules-first + veto + V2 | 0.916 | 0.982 | **0.948** | 0.939-0.956 | 0.950 | 0.939 (1147) | 0.960 (795) | 174 | 36 |
| Hybrid union + V2 (naive) | 0.892 | 0.985 | **0.936** | 0.927-0.944 | 0.940 | 0.921 (1147) | 0.959 (795) | 231 | 29 |

| Hybrid policy | micro-F1 | extra true detections vs rules | extra false positives vs rules | rule detections lost | dF1 vs rules (95% CI) | dF1 vs BiLSTM-only |
|---|---|---|---|---|---|---|
| Hybrid rules-first + V2 | 0.948 | 254 | 128 | 0 | +0.040 (+0.029, +0.050) | +0.021 |
| Hybrid rules-first + veto + V2 | 0.948 | 254 | 128 | 0 | +0.040 (+0.029, +0.050) | +0.021 |
| Hybrid union + V2 (naive) | 0.936 | 261 | 185 | 0 | +0.029 (+0.018, +0.041) | +0.009 |

## 5. V2 development distribution (selection data - in-generator)
Validation (3,000 fields):

| System | P | R | micro-F1 | 95% CI (bootstrap) | macro-F1 | PERSON F1 (n) | USERNAME F1 (n) | FP | FN |
|---|---|---|---|---|---|---|---|---|---|
| Majority (predict nothing) | 0.000 | 0.000 | **0.000** | 0.000-0.000 | 0.000 | 0.000 (1361) | 0.000 (1113) | 0 | 2474 |
| Strong key-aware rules (historical baseline, unchanged) | 0.776 | 0.291 | **0.423** | 0.403-0.444 | 0.419 | 0.245 (1361) | 0.594 (1113) | 208 | 1754 |
| Host engine `detect.py` (actual) | 0.637 | 0.043 | **0.081** | 0.068-0.096 | 0.080 | 0.089 (1361) | 0.071 (1113) | 61 | 2367 |
| BiLSTM V1 (`bilstm-v1-972a87f2b6db`) | 0.613 | 0.430 | **0.505** | 0.487-0.524 | 0.506 | 0.500 (1361) | 0.511 (1113) | 672 | 1411 |
| **BiLSTM V2** ensemble (`bilstm-v2-d1f9e9fb9a2b`) | 0.958 | 0.958 | **0.958** | 0.951-0.965 | 0.959 | 0.951 (1361) | 0.967 (1113) | 104 | 103 |
| Hybrid rules-first + V2 | 0.884 | 0.922 | **0.902** | 0.892-0.913 | 0.903 | 0.892 (1361) | 0.915 (1113) | 299 | 194 |
| Hybrid rules-first + veto + V2 | 0.885 | 0.922 | **0.903** | 0.892-0.913 | 0.904 | 0.893 (1361) | 0.915 (1113) | 296 | 194 |
| Hybrid union + V2 (naive) | 0.886 | 0.967 | **0.925** | 0.916-0.933 | 0.925 | 0.922 (1361) | 0.928 (1113) | 307 | 82 |
| V2 member seed 11 | 0.955 | 0.934 | **0.944** | 0.936-0.952 | 0.945 | 0.934 (1361) | 0.955 (1113) | 110 | 164 |
| V2 member seed 12 | 0.922 | 0.952 | **0.937** | 0.928-0.945 | 0.939 | 0.919 (1361) | 0.960 (1113) | 199 | 119 |
| V2 member seed 13 | 0.945 | 0.952 | **0.949** | 0.941-0.956 | 0.949 | 0.942 (1361) | 0.957 (1113) | 136 | 119 |

Calibration (3,000 fields; threshold selection only):

| System | P | R | micro-F1 | 95% CI (bootstrap) | macro-F1 | PERSON F1 (n) | USERNAME F1 (n) | FP | FN |
|---|---|---|---|---|---|---|---|---|---|
| Majority (predict nothing) | 0.000 | 0.000 | **0.000** | 0.000-0.000 | 0.000 | 0.000 (1367) | 0.000 (1131) | 0 | 2498 |
| Strong key-aware rules (historical baseline, unchanged) | 0.772 | 0.242 | **0.368** | 0.348-0.389 | 0.371 | 0.277 (1367) | 0.465 (1131) | 178 | 1894 |
| Host engine `detect.py` (actual) | 0.632 | 0.043 | **0.081** | 0.068-0.095 | 0.080 | 0.091 (1367) | 0.069 (1131) | 63 | 2390 |
| BiLSTM V1 (`bilstm-v1-972a87f2b6db`) | 0.551 | 0.349 | **0.428** | 0.407-0.447 | 0.423 | 0.463 (1367) | 0.383 (1131) | 711 | 1625 |
| **BiLSTM V2** ensemble (`bilstm-v2-d1f9e9fb9a2b`) | 0.950 | 0.942 | **0.946** | 0.937-0.954 | 0.947 | 0.935 (1367) | 0.960 (1131) | 124 | 145 |
| Hybrid rules-first + V2 | 0.887 | 0.908 | **0.898** | 0.886-0.908 | 0.899 | 0.889 (1367) | 0.908 (1131) | 288 | 229 |
| Hybrid rules-first + veto + V2 | 0.888 | 0.908 | **0.898** | 0.886-0.908 | 0.899 | 0.890 (1367) | 0.908 (1131) | 287 | 229 |
| Hybrid union + V2 (naive) | 0.890 | 0.950 | **0.919** | 0.910-0.927 | 0.919 | 0.915 (1367) | 0.924 (1131) | 293 | 125 |

Seed variation (single members): val 0.9431 +/- 0.0049, calib 0.9365 +/- 0.0047.
Ensembling three seeds adds about +0.015 over the member mean on val (no member was cherry-picked).

| System | recall: unseen-key fields (n) | recall: seen-key | recall: unseen context (n) | recall: seen context | FP rate on entity-free fields | FP rate on hard-negative fields |
|---|---|---|---|---|---|---|
| Strong key-aware rules (historical baseline, unchanged) | 0.0893 (56) | 0.2957 | 0.2799 (536) | 0.2941 | 0.079 | 0.0806 |
| BiLSTM V1 (`bilstm-v1-972a87f2b6db`) | 0.6071 (56) | 0.4256 | 0.3134 (536) | 0.4618 | 0.315 | 0.3178 |
| **BiLSTM V2** ensemble (`bilstm-v2-d1f9e9fb9a2b`) | 0.9821 (56) | 0.9578 | 0.8955 (536) | 0.9757 | 0.0447 | 0.0456 |
| Hybrid rules-first + V2 | 0.9464 (56) | 0.921 | 0.8955 (536) | 0.9288 | 0.1157 | 0.118 |

| Hybrid policy | micro-F1 | extra true detections vs rules | extra false positives vs rules | rule detections lost | dF1 vs rules (95% CI) | dF1 vs BiLSTM-only |
|---|---|---|---|---|---|---|
| Hybrid rules-first + V2 | 0.902 | 1560 | 91 | 0 | +0.479 (+0.459, +0.500) | -0.056 |
| Hybrid rules-first + veto + V2 | 0.903 | 1560 | 88 | 0 | +0.480 (+0.460, +0.501) | -0.055 |
| Hybrid union + V2 (naive) | 0.925 | 1672 | 99 | 0 | +0.501 (+0.480, +0.523) | -0.033 |

## 6. Throughput and latency (CPU, 4 vCPU Linux container; short synthetic fields - not a long-body benchmark)
| model | batched fields/s | single-field latency (ms) |
|---|---|---|
| s11 | 2190.4 | 1.8 |
| v1 | 2475.7 | 1.98 |
| v2 | 1216.8 | 4.26 |

The ensemble costs about 3x a single member (~4 ms per single field, ~1,200 fields/s batched). Apple Silicon CPU: not measured here (the container is x86-64).

## 7. Calibration (separate analysis)
Raw span score = mean over the span's tokens of the ensemble-averaged softmax probability of the chosen BIO tag. It is **not calibrated**. Reliability on
the dev set is good (ECE 0.0102) but degrades under distribution shift (challenge ECE 0.072; spans scored 0.5-0.7 are correct only
~45-50% of the time). A calibration map fitted on the in-generator calib split would not transfer to real traffic, so none is shipped; scores remain
`ScoreType.UNCALIBRATED_MODEL_SCORE`.

## 8. Failure analysis on the challenge benchmark (V2; reporting only - the benchmark was not used to tune anything)
Error taxonomy (spans): {"FP_no_gold_overlap": 105, "FN_missed_entirely": 139, "FP_boundary_overlap": 23, "FN_boundary_overlap": 24, "FP_label_confusion_same_span": 2, "FN_label_confusion_same_span": 2}. By label: 118 of 130 false positives are PERSON_NAME; missed entities are 100 PERSON_NAME and 65 USERNAME.
Label confusions on an identical span are rare (2 + 2): the problem is *whether* a span is an entity and where it starts, not which kind.

Most frequent false-positive frames that overlap no gold entity (count of spans; `{...}` are slots in the hand-written frame):

* `json_neg`: `{ORGP}` x12
* `chat`: `[{TIME}] <{H}> anyone around?` x7
* `sql`: `SELECT * FROM users WHERE username = '{H}'` x7
* `log`: `{DATE} {TIME} WARN login throttled for {H} (attempt 4/5)` x7
* `json_neg`: `{CITYP}` x6
* `form`: `{ORGP}` x6
* `narrative`: `{N} from {ORG} will join the call.` x6
* `narrative`: `Meeting with {ORG} about {WORD}` x6

Frames with the most errors (tp / fp / fn over the frame's fields):

* `json_nested`: `{H}` (62 / 1 / 16)
* `narrative`: `Called {N} twice, no answer; will try {FN2} tomorrow.` (1 / 3 / 11)
* `chat`: `[{TIME}] <{H}> anyone around?` (1 / 7 / 6)
* `json_neg`: `{ORGP}` (0 / 12 / 0)
* `narrative`: `Interview panel: {N}, {N2}, {N3}.` (7 / 1 / 11)
* `csv`: `user,role\n{H},admin\n{H2},viewer` (0 / 0 / 12)
* `email`: `To: {N}; {N2}\ncc: {ORG} Billing` (5 / 4 / 7)
* `narrative`: `{N} from {ORG} will join the call.` (3 / 6 / 4)
* `narrative`: `{FN} said {FN2} would be late.` (4 / 1 / 8)
* `json_nested`: `{H}/{SLUG}` (1 / 2 / 6)

Reading: false positives concentrate on **person-named organisations** (`Johnson & Johnson`-style values under company keys), product names under `name` keys and
city names that are also given names; misses concentrate on **formats and frames the training generator never produced** (positional CSV rows, multi-person lists,
"X said Y would be late", IRC-style prefixes) and on **handles under generic keys**. Unseen-context recall is
0.6693 against 0.9095 for seen contexts: the evidence points to frame/format coverage (seen vs unseen contexts differ by 24 points) rather than model capacity; this is a hypothesis, not tested here.
Complete list: `docs/ml/results/v2_challenge_failure_taxonomy.json`.

## 9. Fragments / upstream defects (model behaviour on synthetic extracted fields; NOT TCP-reassembly validation)
Single-entity V2 *validation* fields, 600 per row, perturbed as an upstream defect might:

| perturbation of a val field | exact original span | any overlap | any span | n |
|---|---|---|---|---|
| baseline | 0.978 | 0.985 | 0.985 | 600 |
| clipped_mid_entity | 0.736 | 0.844 | 0.844 | 590 |
| entity_tail_cut_after_entity | 0.930 | 0.938 | 0.938 | 600 |
| entity_head_cut_before_entity | 0.870 | 0.877 | 0.877 | 600 |
| duplicated_value | 0.000 | 0.977 | 0.977 | 600 |
| gap_inside_entity_fused | 0.000 | 0.000 | 0.829 | 252 |
| replacement_char_in_entity | 0.082 | 0.726 | 0.726 | 599 |
| long_field_entity_after_3000_tokens | 0.645 | 0.702 | 0.878 | 600 |
| fused_with_preceding_word | 0.412 | 0.867 | 0.867 | 211 |

`clipped_mid_entity` and `duplicated_value` still overlap the original entity in most cases, but exact offsets are not preserved; `gap_inside_entity_fused`
(bytes of a name joined across a gap) is the failure the model cannot recover from; `replacement_char_in_entity` mostly loses the exact span. The input policy
flags such fields (`partial_evidence`); see `UPSTREAM_INPUT_ASSUMPTIONS.md`. Entities are also split by the 192-token windows in very long fields.

## 10. Limitations of this evaluation
Synthetic only; one author for generator, baseline and challenge; the challenge shares annotation conventions and some natural cue phrases ("Dear", "Hello") with training;
challenge is a single draw (CI half-width ~ 0.02); strong-rule performance is highly sensitive to whether the benchmark's cues were anticipated (0.908 on the V1 test,
0.317 on the challenge); Apple Silicon timing not measured; no real HTTP traffic; no human re-annotation.
