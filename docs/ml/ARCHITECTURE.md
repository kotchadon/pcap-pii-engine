# ML architecture (BiLSTM contextual PII, v1)

Everything lives in `src/packet_pii/ml/`; the packet pipeline, rules engine, CLI and report schema are untouched.

| Module | Needs torch | Role |
|---|---|---|
| `schema.py`, `detector.py` | no | Existing contract: `FieldInput`, `EntitySpan`, `ContextualPIIDetector.predict_fields`, `run_detector` |
| `spans.py` | no | Tokenizer with code-point offsets, gold-span -> BIO alignment (strict, never drops), BIO-constrained Viterbi, tags -> spans |
| `encoding.py` | no | Vocabulary (train only), orthographic shape classes, field-key ("location") tokens, chunking |
| `data.py` | no | Synthetic dataset generator, splits, leakage report |
| `baseline.py`, `metrics.py` | no | Rule baselines; exact-span entity P/R/F1 |
| `bilstm.py` | **yes** | Model, collation, training loop, checkpoint save/load |
| `infer.py` | **yes** | `BiLSTMDetector` (implements the existing contract) |

`import packet_pii.ml` never imports torch (tested with `torch` blocked). Install the extra with `pip install '.[ml]'`.

## Model
Input sequence = `[field-key tokens] <sep> [text tokens]`, e.g. `json_body.user.fullName` -> `json body user full name <sep> Maria ...`.
The key gives the context ("this is a name field") without changing the `FieldInput` contract. Only text positions are labelled/decoded.

Per token: word embedding (lowercased, 64-d, `<unk>` for words unseen in train) + orthographic-shape embedding (8-d: lower / Capitalised / UPPER / mixed / digits / alnum / underscore / punct / caseless script) + context-flag embedding (key vs text) + char-CNN (24-d chars, 48 filters, width 3, masked max-pool) -> dropout -> **1-layer bidirectional LSTM** (hidden 96 per direction, packed sequences so padding never reaches the LSTM) -> dropout -> linear to 5 BIO tags (`O, B/I-PERSON_NAME, B/I-USERNAME`). ~0.34M parameters, 1.4 MB.

* Loss: cross-entropy with `ignore_index=-100` on padding and key positions.
* Unknown words: the char-CNN + shape features still describe them, and *word dropout* (p=0.15 on text tokens) trains the `<unk>` embedding, so unseen tokens never receive an untrained random vector.
* Decoding: Viterbi over log-probabilities with BIO transition constraints (no `I-X` after `O`/other labels). Span score = mean probability of the chosen tags = **raw, uncalibrated model score** (`ScoreType.UNCALIBRATED_MODEL_SCORE`).
* Bounds: `max_seq=192` tokens per forward pass; longer fields are split into non-overlapping token windows (an entity straddling a window edge is split - documented limitation). `run_detector` additionally caps fields at 65,536 chars / 10,000 fields.
* Training: AdamW (lr 2e-3, wd 1e-2), batch 64, grad-clip 1.0, seed 1337, early stopping (patience 6) on **validation entity micro-F1**, best checkpoint kept, wall-clock limit.
* Checkpoint = directory: `model.pt` (tensors only, loaded with `torch.load(weights_only=True)`), `meta.json` (config, vocab, version `bilstm-v1-<sha256[:12]>`, `min_score`, training history, sha256 of `model.pt`). Loading verifies checksum, config bounds and tensor shapes; corrupt/missing files raise `CheckpointError`.

## Why earlier BiLSTM attempts can fail (checked here)
Label misalignment (guarded: strict alignment + tests, generator asserts every gold span aligns), padding leaking into the LSTM (packed sequences; test asserts padded == unpadded outputs), OOV handling (`<unk>` + word dropout), template overfitting / leakage (family- and lexicon-disjoint splits), and missing key context (key tokens in the input). Not claimed to reproduce the earlier 0-1.5% result.
