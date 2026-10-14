# V2 failure audit - why BiLSTM V1 generalises poorly

Scope: V1 checkpoint `bilstm-v1-972a87f2b6db` (sha256 `972a87f2...495d6a`, verified unchanged), audited on **V1 train / val / calib
only**. The V1 frozen test split was not read. Evidence: `scripts/ml/audit_v1.py` -> `docs/ml/results/v2_audit_v1.json`
(aggregate counts only, no raw text). Repository state at audit time: `main` = `4d311d1` (PR #5 merged), 172 tests passing,
host engine does not import `packet_pii.ml` (ML is opt-in, unchanged).

## Summary of root causes (ranked by measured impact)

| # | Finding | Evidence (V1, dev data) | Consequence |
|---|---|---|---|
| 1 | **The model learned frames and keys, not entity semantics** | Entity swapped for a *city name* in the same frame is still tagged (exact span) in **68.5%** of cases (any overlap 86.7%); a person name dropped into a neutral frame ("Welcome to X!") is tagged only 23.9% | Greeting/cue frames fire regardless of what fills the slot -> city/company/product false positives |
| 2 | **Key-to-label shortcut** | 46 distinct keys in train, 45 of 46 map to a single label (only `name` is ambiguous); person value under a *username* key is labelled USERNAME in **51%**; replacing the key by a neutral word drops field-person recall to **0.49**; recall 0.746 (all key tokens seen) vs **0.486** (some key token unseen); field-user recall 1.00 seen vs **0.558** unseen | Large recall drop on unseen HTTP field names (`attendee`, `gamertag`) |
| 3 | **Template starvation** | Only **44** free-text templates (mean 111 train examples each); train loss -> 0.0009 while validation micro-F1 over the last 10 epochs is 0.738 +/- 0.027 | Memorisation of generated sentence structure |
| 4 | **Surface-form shortcut** | 91% of train person spans are capitalised, 21% of username spans; 46% of negative field values are capitalised; lower-case entities are ~half of all false negatives on calib (84/166) | "Capitalised => person, lower => username" |
| 5 | **Split-level variance is a template-mix effect** | Per-template recall (31 templates with >= 15 spans on val+calib): min 0.0, max 1.0, std **0.34**, 7 templates below 0.5; val/calib/test contain only 6-15 held-out templates each | The 0.791 / 0.837 / 0.756 spread is largely *which templates land in the split* (plus the 0.027 epoch noise); threshold is not the cause (val F1 0.790 / 0.791 / 0.783 / 0.756 at 0.10 / 0.25 / 0.50 / 0.75) |
| 6 | **Boundary errors are a quarter of all errors** | calib: 64 FP + 64 FN are partial overlaps with gold (middle initials, `Last, First`, multi-token handles); 13+13 label confusions on an identical span (PERSON vs USERNAME) | Needs boundary-diverse training data, not a decoder change (Viterbi already enforces BIO) |
| 7 | Non-ASCII is *not* the dominant failure | FN 4/78 (calib) and 18/55 (val) on non-ASCII spans | Keep Unicode in data, do not prioritise |

Pure false positives (no overlap with any gold span; calib 122): 60 city/company/product/file/word fills, 9 negative field values,
~53 other. Greeting/cue words account for only 8 on val - the bigger problem is that the *slot* fires on any capitalised filler (finding 1).

## Hypotheses tested and verdicts

* **A. Overfitting / template dependence - confirmed** (1, 3, 4). Not a capacity problem: training loss ~0.
* **B. Unseen keys - confirmed, and caused by the training distribution**, not by tokenisation: key tokens are already split on
  `_ . [ ] -` and camelCase and fed to a char-CNN, but with 46 keys of which 45 are perfectly predictive, the model has no pressure to
  use the *value* when the key is unfamiliar. V1 `--ctx-dropout 0.3` (mask key tokens) did not help (val 0.770 vs 0.789): masking
  removes the cue without teaching an alternative one, because negatives and positives are not separable by value form in V1 data.
* **C. False positives - confirmed as frame reliance** (1) plus the lack of *frame-sharing* negatives (V1 negatives use different frames).
* **D. False negatives - confirmed**: unseen cue frames and lowercase/handle-like entities; URL-path and "signed in as @x" cues were
  held out entirely.
* **E. Evaluation instability - explained**: small number of held-out templates per split (5) + epoch noise (3); not thresholds (5).

## Prioritised experimental plan (what V2 implements)

1. **Data first** (addresses 1-6): `data2.py` - 6.5k first / 7.4k last names, 4.4k cities, 2.8k companies, 5.6k usernames from a frozen
   Faker lexicon dump, hash-partitioned across splits; ~300 hash-partitioned cue frames; a key grammar (role x head, snake / camel / kebab
   / UPPER / dotted, nested JSON paths, flat form/query keys mirroring `http_extract`); **frame-sharing hard negatives** (the same cue with
   person / non-person fills); neutral keys with person *and* non-person values; person-like company names and user-like ids; case noise
   applied identically to positives and negatives; truncation and U+FFFD noise.
2. **Independent challenge benchmark** (`challenge.py`, frozen before any V2 model result was seen): hand-written lexicons and frames,
   unseen keys, 30% entity-free examples including person-named companies / city-named people.
3. **One-at-a-time model changes**, selected on V2 validation only: E0 V1 architecture on V2 data (isolates the data effect);
   E1 key-summary broadcast to every position; E2 wider char-CNN; E3 hard-negative oversampling; E4 stronger lexical regularisation.
4. **Operating point from a separate calibration split**; raw scores stay labelled uncalibrated; reliability reported.
5. **Fair three-system evaluation** (rules / BiLSTM / rules-first hybrid) incl. unseen-key and unseen-context recall, paired bootstrap CIs.
6. **Input-quality policy** for upstream truncation, gaps and replacement characters (`input_policy.py`,
   `UPSTREAM_INPUT_ASSUMPTIONS.md`) - ML cannot repair missing bytes.

Not pursued: bigger models / more epochs (loss already ~0), CRF layer (BIO errors are boundary-data errors, not illegal transitions),
repeating ctx-dropout 0.3 (negative evidence).

---

## Appendix - the same probes re-run on the delivered V2 ensemble (V1 *dev* data only; V1 test not read)
`python scripts/ml/audit_v1.py --checkpoint src/packet_pii/ml/artifacts/bilstm_v2 --out docs/ml/results/v2_audit_v2_on_v1dev.json`
(V1 val/calib are out-of-distribution for V2: different generator, vocabulary and frames.)

| Probe (V1 val / calib) | V1 | V2 | Verdict |
|---|---|---|---|
| Micro-F1 on V1 val / calib | 0.791 / 0.837 | **0.980 / 0.907** | large gain out-of-generator |
| Person value under a *username* key labelled USERNAME (key shortcut) | 51% | **0%** | fixed |
| field_person recall with the key replaced by a neutral word / key removed | 0.49 / 0.49 | **0.993 / 0.958** | fixed (value-based evidence now used) |
| field_person recall, all key tokens seen | 0.746 | 0.993 | fixed (V2 vocabulary covers every key in this set, so unseen-key recall is not measurable here; see challenge slices) |
| Person name inserted into a neutral frame ("Welcome to X!", ...) tagged | 23.9% | **11.4%** | improved |
| Entity replaced by a city name, same frame, still tagged exactly | 68.5% | **85.1%** | **NOT improved (worse)** - the probe mixes *strong-cue* frames ("My name is X"), which V2 deliberately never negates (annotation rule), and unfamiliar pseudo-city strings; not resolved. The challenge set still shows organisation / city false positives (V2 challenge false-positive rate on hard-negative fields 0.26). |
| Boundary errors on calib (FP + FN partial overlaps) | 64 + 64 | **0 + 0** | fixed on this distribution; 23 + 24 remain on the challenge set |
| Per-template recall std (31 templates) / templates < 0.5 | 0.342 / 7 | 0.256 / 3 | variance reduced, not gone |

Conclusion: the key-shortcut, surface-form and boundary root causes (2, 4, 6) were fixed; the frame-reliance cause (1) is only partly addressed; the template-mix
variance (5) persists whenever frames are held out.
