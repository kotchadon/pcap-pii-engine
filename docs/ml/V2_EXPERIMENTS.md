# V2 experiments

All runs: CPU, deterministic seeds, early stopping (patience 4) on **V2 validation entity micro-F1**, wall-clock cap 25-32 min, operating threshold chosen on V2 calib.
The independent challenge benchmark was **frozen before** any V2 model was evaluated on it and was not used for any choice below. The V1 `--ctx-dropout 0.3`
experiment (negative evidence in V1) was not repeated. Raw records: `docs/ml/results/v2_experiments.json`; commands are stored in each record (`cli`).

## Predeclared matrix and what it answers
| ID | question |
|---|---|
| E0 | Is the V1 architecture enough once the data is fixed? (isolates the data effect: V1 model val F1 on V2 val is 0.505) |
| E1 | Does broadcasting a field-key summary to every position (instead of relying on the LSTM to carry it) help unseen keys? |
| E2 | Do wider char-CNN kernels help unseen words / username shapes? |
| E3 | Does oversampling hard negatives (x2) reduce false positives? |
| R2-a/b/c | Repeat E0 / E3 / E2+E3 on data **v2.2** (adds ~140 subject- and mid-position frames after the V2.1 diagnostic "span over-extended onto a following verb"), then two extra seeds of the winner. |

## Results (validation = selection data; differences below ~0.007 are within seed noise)
| ID | data | change vs E0 | params | epochs | train s | val F1 @calib-thr | calib F1 | val unseen-context recall | val hard-neg FP rate |
|---|---|---|---|---|---|---|---|---|---|
| E0 | v2.1 | V1 architecture on V2.1 data (isolates the data effect) | 953,821 | 11 | 808 | 0.9458 | 0.9343 | 0.8795 | 0.0382 |
| E1 | v2.1 | E0 + key-summary broadcast | 982,397 | 10 | 762 | 0.9390 | 0.9506 | 0.8399 | 0.0742 |
| E2 | v2.1 | E0 + char-CNN widths (2,3,4) x 64 filters | 1,074,925 | 12 | 1556 | 0.9468 | 0.9498 | 0.864 | 0.0225 |
| E3 | v2.1 | E0 + hard-negative oversampling (x2) | 953,821 | 14 | 1239 | 0.9529 | 0.9469 | 0.883 | 0.0258 |
| R2-a (seed 11) | v2.2 | E0 config on V2.2 data | 973,725 | 9 | 831 | 0.9440 | 0.9357 | 0.8545 | 0.0491 |
| R2-a (seed 12) | v2.2 | same, seed 12 | 973,725 | 12 | 1017 | 0.9368 | 0.9427 | 0.8974 | 0.0502 |
| R2-a (seed 13) | v2.2 | same, seed 13 | 973,725 | 12 | 1016 | 0.9486 | 0.9312 | 0.8657 | 0.0467 |
| R2-b | v2.2 | E0 + hard-negative oversampling | 973,725 | 9 | 1053 | 0.9318 | 0.9412 | 0.8582 | 0.0467 |
| R2-c | v2.2 | hn-boost + char widths (2,3,4) x 64 | 1,094,829 | 8 | 2070 | 0.9294 | 0.9360 | 0.8078 | 0.0222 |

Seed noise of the E0 configuration on v2.2: val 0.9431 +/- 0.0049 (3 seeds).

## Decisions
1. **Data was the dominant lever.** V1 model on V2 val: 0.505; V1 *architecture* trained on V2 data (E0): 0.946. Same architecture, different data.
2. **No architectural change beat the baseline beyond seed noise**: key broadcast (E1) -0.007 val / +0.016 calib with 2x the false positives on hard negatives (0.074 vs 0.038);
   wide char-CNN (E2) +0.001 with the lowest hard-negative FP rate (0.023) but 2x training time and lower multi-entity recall; hard-negative oversampling (E3) +0.007 on v2.1 val
   but -0.012 on v2.2 (R2-b). Per the "do not add complexity without evidence" rule the V1 architecture (word + shape + char-CNN, 1-layer BiLSTM 96x2, ~0.97 M parameters
   because the vocabulary is larger) was kept.
3. **Seed ensembling is the one change that helped consistently**: the 3-seed probability-averaging ensemble gives val 0.958 / calib 0.946 vs member mean 0.943 / 0.937.
   It was adopted using dev data only, without choosing a "best" seed. Cost: 3x inference and a 12 MB artifact (each member directory is also a valid single checkpoint).
4. **Data iteration v2.1 -> v2.2** was driven by a *validation* diagnostic (template `{P} requested a refund of {NUM}`: 0/23 exact matches, span over-extended to the verb),
   not by the challenge set. It also exposed a data bug (a template present in two banks leaked across splits), fixed with a uniqueness test before the v2.2 runs reported above.
5. Selection summary: final = R2-a configuration x seeds {11, 12, 13} (ensemble), threshold 0.35 (calib), hybrid thresholds from calib.

## Not done (time-boxed)
Key-path subword/embedding transfer, a CRF layer, two-layer LSTMs, pretrained embeddings (no downloads), per-label thresholds, and any change informed by the challenge
failure analysis - the latter would require a fresh `challenge_v2` to keep the evidence honest.
