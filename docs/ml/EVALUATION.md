# Evaluation

Protocol (identical for all systems): exact match of `(start, end, label)` per example; micro/macro over `PERSON_NAME`, `USERNAME`.
Operating point `min_score=0.25`, chosen on the **calibration** split (not val, not test).
Raw numbers: `docs/ml/results/exp1_dev.json` (val, calib), `final_test.json` (test, evaluated once with `--final`), `exp2_ctxdropout_train.json`.

## Commands (actually run)
```
python scripts/ml/train.py --out src/packet_pii/ml/artifacts/bilstm_v1 --seed 1337 --epochs 30 --patience 6 --max-minutes 12
python scripts/ml/evaluate.py --checkpoint src/packet_pii/ml/artifacts/bilstm_v1 --splits val,calib --out docs/ml/results/exp1_dev.json
python scripts/ml/evaluate.py --checkpoint src/packet_pii/ml/artifacts/bilstm_v1 --splits test --final --out docs/ml/results/final_test.json
```
Environment: Python 3.13, torch 2.14.1 (CPU execution, 4 threads), Linux x86-64 4 vCPU. Training: 14 epochs, 1 m 55 s, early-stopped; best epoch 8.

## Results (exact-span, micro)
| Split | System | Precision | Recall | F1 |
|---|---|---|---|---|
| val | **BiLSTM** | 0.852 | 0.738 | 0.791 |
| val | strong key-aware rules | 0.998 | 0.813 | 0.896 |
| val | existing `detect.py` key rules | 1.000 | 0.182 | 0.307 |
| calib | **BiLSTM** | 0.825 | 0.850 | 0.837 |
| calib | strong key-aware rules | 0.902 | 0.744 | 0.816 |
| **test** | **BiLSTM** | **0.803** | **0.714** | **0.756** (macro 0.753) |
| **test** | strong key-aware rules | 0.973 | 0.851 | **0.908** (macro 0.914) |
| test | existing `detect.py` key rules | 1.000 | 0.185 | 0.312 |
| test | majority (predict nothing) | 0 | 0 | 0 |

**The BiLSTM does not beat the strong rules baseline on the frozen test split (0.756 vs 0.908).** It is far above the existing `detect.py` key rules (0.312), which only look at 3 key names, and it did beat the strong rules on the calibration split (0.837 vs 0.816), so the gap depends on which held-out frames/keys a split contains - the validation/test variance is large. The baseline was authored by the same person as the generator (see DATASET.md).

Test per class: PERSON_NAME P 0.766 / R 0.759 / F1 0.763 (support 1147); USERNAME P 0.873 / R 0.648 / F1 0.744 (support 795). Counts: TP 1386, FP 341, FN 556. Val-vs-test gap: 0.791 -> 0.756 (calib 0.837); epoch-to-epoch val F1 swung 0.70-0.79, so differences of a few points are within noise (single seed).

### Threshold sweep, test (raw score cut-off)
| min_score | 0.00 | 0.25 | 0.50 | 0.75 | 0.90 | 0.99 |
|---|---|---|---|---|---|---|
| precision | 0.799 | 0.803 | 0.805 | 0.851 | 0.899 | 0.948 |
| recall | 0.716 | 0.714 | 0.692 | 0.640 | 0.600 | 0.489 |

### Failure analysis (test)
* Recall by kind: `url` 0.47, `text_user` 0.57, `text_mixed` 0.62, `text_person` 0.66, `field_user` 0.70, `field_person` 0.77, kv 0.82, first/last fields ~1.0.
* Unseen field keys: on validation, field recall is 0.93 when every key token is in the vocabulary but 0.60 when a key token is unseen (e.g. `attendee`, `gamertag`). A focused fix (experiment 2: randomly mask key tokens with prob 0.3 during training) did **not** improve validation F1 (0.770 vs 0.789) and was rejected; it is kept as an off-by-default option (`--ctx-dropout`).
* False positives: greetings/capitalised sentence words (`Signed`, `Congratulations`, `Hello`, `everyone`), city/product names in `Welcome to X`, `product=X Go`, and lowercase handles labelled as names. Handles that look like names (`aflonoutman`) get `PERSON_NAME`.
* Unseen frames: `Signed in as @x`, `/api/v2/accounts/x/settings` are often missed.
* Training loss falls to ~0.001 while val F1 plateaus ~0.75-0.79: the model memorises training frames; more frame diversity (real data) would help more than more epochs.

### Scores / calibration
Span score = mean softmax probability of chosen tags (**uncalibrated**). Expected calibration error of the score vs. span correctness: val 0.068, calib 0.123, test 0.134 (over-confident at the high end). A calibrated estimate was **not** produced: only 1,500 synthetic calibration examples from the same generator would not justify a calibration claim for real traffic. Reported scores are labelled `uncalibrated_model_score`. Rule heuristics and model scores are never merged.

### CPU inference
Single field ~2-3 ms; ~3,000-4,400 short fields/s batched (4 vCPU, this container; synthetic short texts - not a benchmark of long bodies).

### Data hygiene notes
Error-analysis samples in `docs/ml/results/*.json` contain **offsets, labels, kinds and lengths only**; raw field text, locations and entity strings are exported only with `evaluate.py --include-text`. `entity_metrics` counts predictions for ids absent from the gold set as false positives. The result files were regenerated from the unchanged checkpoint after these fixes; all metrics, sweeps, baselines and counts are byte-for-byte equal in value to the earlier run (only timings and the sample format differ).

The test split was read only by the final `--final` run. During development the *baselines* were run once on val and test as a sanity check and were not changed afterwards. Two training experiments were run (the allowed maximum); exp 2 was selected against on validation only.
