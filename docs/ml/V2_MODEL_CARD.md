# Model card - `bilstm-v2-d1f9e9fb9a2b` (BiLSTM V2, 3-member ensemble)

**Status: research prototype for demonstration. Not validated on real traffic. Keep ML disabled by default in the host engine.**
V1 (`bilstm-v1-972a87f2b6db`, sha256 `972a87f2b6db8b701ba43a63d1949ca0dc7684ec67c2c2a304ebbbaa19495d6a`) is untouched and remains the fallback.

| | |
|---|---|
| Task | Tag `PERSON_NAME` / `USERNAME` spans in text extracted from HTTP fields, given the field location (key path). Labels and `EntitySpan` contract unchanged from V1. |
| Architecture | Per member: word embedding (64) + orthographic-shape embedding + key/text flag + char-CNN (48 filters, width 3) -> 1-layer **bidirectional LSTM** (96 per direction, packed sequences) -> linear to 5 BIO tags; BIO-constrained Viterbi. ~0.97 M parameters (vocabulary ~12 k). Ensemble = average of the three members' per-token tag probabilities before decoding. |
| Training data | 30,000 synthetic fields (`datasets/v2/`, data v2.2, see `V2_DATASET_AND_GENERALISATION.md`); lexicons from a frozen Faker dump (MIT). No real or proprietary data. |
| Selection | Configuration chosen on V2 validation micro-F1; operating threshold `min_score = 0.35` chosen on V2 calibration split; seeds 11/12/13 all kept (no cherry-picking). The challenge benchmark was not used for any choice. |
| Artifact | `src/packet_pii/ml/artifacts/bilstm_v2/` (**12 MB**: `ensemble.json` + `seed11|seed12|seed13/{model.pt, meta.json}`, 3.9 MB weights each). Each member directory is also a valid single checkpoint (`BiLSTMDetector(".../bilstm_v2/seed13")`). |
| Integrity | `model.pt` loaded with `torch.load(weights_only=True)`; per-member SHA-256 verified against `meta.json` and `ensemble.json`; ensemble version = sha256 of the member digests; config/vocab consistency, shape check, path-escape check. Member digests: seed11 `bebfc0c9...011db5`, seed12 `de292058...216dd5`, seed13 `46bd48b8...d4262` (full values in `ensemble.json`). |
| Runtime | CPU only, no network access; ~4 ms per single field, ~1,200 short fields/s batched (4 vCPU). Rules-only host engine does not import PyTorch. |
| Scores | Raw ensemble-averaged tag probability; `ScoreType.UNCALIBRATED_MODEL_SCORE`. Not a probability of correctness (ECE 0.07 on the challenge benchmark). |

## Measured performance (exact span + label; see `V2_EVALUATION.md`)
| Benchmark | BiLSTM V2 | BiLSTM V1 | Strong rules | Host `detect.py` | Rules-first hybrid |
|---|---|---|---|---|---|
| Frozen challenge (independent, out-of-generator, synthetic; n=1,058) | **0.818** (0.794-0.840) | 0.559 | 0.317 | 0.134 | 0.801 |
| V1 frozen test (Regime A, V1 generator; n=2,500) | 0.927 | 0.755 | 0.908 | 0.312 | 0.948 |
| V2 val / calib (in-generator, selection data) | 0.958 / 0.946 | 0.505 / 0.428 | 0.423 / 0.368 | 0.081 | 0.902 / 0.898 |

The **>= 0.88 target was not reached on the independent benchmark.** Challenge precision 0.836 / recall 0.801 (130 FP, 165 FN).

## Intended use
Optional second-opinion signal alongside the deterministic rules for names and usernames in already-extracted HTTP fields, with human review; research and demonstration.

## Out of scope / do not use for
Sole-detector deployment; compliance or legal determinations; structured secrets (passwords, tokens, cards, e-mail, phone, IP - owned by the rules; secret-bearing keys are excluded by the input policy);
raw packet data; reconstructing missing/garbled stream bytes; non-English prose beyond the sampled names/cues.

## Known limitations
* Synthetic training and evaluation only; no real HTTP traffic, no human annotation.
* Unseen frames and formats: recall on challenge spans whose left context never occurred in training is 0.67 vs 0.91 when seen. Positional CSV rows, multi-person lists and IRC/chat prefixes are weak.
* False positives on person-named organisations (`Johnson & Johnson`), product names under `name` keys, and city names that are also given names (e.g. `Madison` scored 0.55 in the demo).
* Entities straddling the 192-token windows of very long fields are split; truncated/fused/garbled field text degrades exact offsets (see fragment table in `V2_EVALUATION.md`).
* Three-member ensemble triples inference cost; single members score 0.79-0.81 on the challenge benchmark.
* Single data seed; challenge CI half-width ~ 0.02; names in evaluation sets are partly common names also present in training lexicons.

## Recommendation
Do not enable by default. Suitable for the Sunday demonstration as an optional, clearly labelled experimental detector, positioned honestly as ~0.82 F1 on an independent synthetic benchmark. Before any customer-facing claim:
build `challenge_v2` (fresh), add the formats listed above to the generator, and validate on consented/synthetic-replayed real HTTP fields.

## Deployment coverage and file-specific accuracy (added with the ML-coverage milestone)

Inference in TRACE is budgeted (`standard` 10,000 / `extended` 100,000 / `complete` 1,000,000 eligible fields); the report states whether the model examined all, some or none of the eligible fields, and a partial scan is flagged incomplete. The 81.8 % offline F1 above is a synthetic-benchmark figure. File-specific metrics exist only with a verified ground-truth manifest; the only such measurements so far (controlled synthetic fixture: model-only micro F1 0.671, P 0.608, R 0.750; hand-designed showcase demonstration: F1 0.842) are in `GROUND_TRUTH_EVALUATION.md` with their limits. They are not real-world accuracy figures.
