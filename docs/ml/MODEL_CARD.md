# Model card - `bilstm-v1-972a87f2b6db`

* **Task**: tag `PERSON_NAME` / `USERNAME` spans in text extracted from HTTP fields, given the field key.
* **Architecture**: char-CNN + word/shape embeddings, 1-layer BiLSTM (96x2), BIO + Viterbi. 0.34M params, CPU.
* **Artifact**: `src/packet_pii/ml/artifacts/bilstm_v1/` (`model.pt` 1.4 MB, sha256 `972a87f2b6db8b701ba43a63d1949ca0dc7684ec67c2c2a304ebbbaa19495d6a`; `meta.json` holds config, vocab, history, `min_score=0.25`).
* **Training data**: 9,000 synthetic examples, fake identities only (DATASET.md). No real or proprietary data.
* **Measured** (synthetic held-out test, exact span): P 0.803 / R 0.714 / F1 0.756; strong key-aware rules F1 0.908; existing key rules F1 0.312.
* **Scores**: raw, uncalibrated (`uncalibrated_model_score`); not probabilities.
* **Intended use**: research/evaluation, optional second-opinion signal alongside the rules engine.
* **Not intended / not validated**: production use as a sole detector; real network traffic; non-English prose beyond the sampled Unicode names; long documents (window-split); adversarial input; legal/compliance determinations.
* **Known limitations**: trained and tested only on template-generated data from one generator; weak on unseen field keys and unseen sentence frames; confuses greeting words, city/product names and name-like handles; entities crossing 192-token windows are split; single seed, no confidence intervals; scores over-confident.
* **Recommendation**: **keep ML disabled in the host engine.** On the frozen test split the BiLSTM does not outperform a generous field-key-aware rules baseline, and nothing here supports a client-ready contextual detector. Next steps: annotate a small sample of real (consented/synthetic-replayed) HTTP fields, evaluate rules+BiLSTM combination, multiple seeds.
* **Privacy/safety**: the detector never logs or stores text; error messages carry only indices/lengths; checkpoints load with `weights_only=True` plus checksum verification; no network access at runtime.
