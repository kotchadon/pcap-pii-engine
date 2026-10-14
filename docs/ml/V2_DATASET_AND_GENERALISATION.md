# V2 dataset strategy and generalisation protocol

All data is **synthetic**. Nothing here is real network traffic, real PII, or a downloaded annotated corpus. No private captures,
credentials or client data were used or uploaded.

## Three evaluation regimes

| Regime | Purpose | Data | Used for model selection? |
|---|---|---|---|
| A - reproducibility | Historical comparison with V1 | V1 generator + V1 frozen test (`data.py`, seed 1234), V1 reports unchanged | **No** (reported once, at the end, with the predeclared protocol) |
| B - development | Train / select / calibrate V2 | `data2.py`: train 30,000 / val 3,000 / calib 3,000 | val = checkpoint + config selection; calib = operating threshold and hybrid thresholds |
| C - independent challenge | Out-of-generator validation | `challenge.py` -> frozen `datasets/challenge_v1.jsonl.gz` (1,058 fields) | **No. Never.** Frozen before any V2 model was evaluated on it |

Regime C is **"out-of-generator synthetic validation"**. It is authored in a separate module with hand-written lexicons and
hand-written frames (no import of `data2` lexicons, cue banks or key grammar), but by the same engineer/tool as the rest of the ML
workstream - it is *not* independent human annotation and *not* real-world validation.

### Challenge freeze
`docs/ml/results/challenge_v1_manifest.json` records sha256 of the JSONL (`tests/test_ml_v2_data.py::test_challenge_is_frozen`
fails if the file changes; a revision must be a new `challenge_v2`). The freeze commit precedes every V2 evaluation on it.

## Provenance of the V2 development lexicons
`scripts/ml/build_lexicons.py` dumps names, cities, companies, usernames, job titles, streets, words and user-agent strings from
**Faker 40.43.0** (MIT licence; generated from published name/place lists, no real individuals) over 24 Latin-script and 11 other
locales (ja, ru, zh, ko, el, uk, he, ar, th, hi, fa) into `datasets/lexicons_v2.json` (frozen; Faker is not a runtime or generation
dependency). 6,526 first names, 7,425 last names, 4,374 cities, 2,766 companies, 5,572 usernames. Cross-category collisions are removed
(a city / company / username equal to any person-name token is dropped). Public annotated NER corpora (CoNLL, OntoNotes, WikiANN, ...) were
considered and **not used**: their annotation conventions (every PER mention in news prose) and licences (several non-commercial or
restricted) do not match HTTP-field PERSON/USERNAME labelling, and no large download was authorised.

## Generator design (`data2.py`)
* **Kinds / sources** (train counts): person fields 2,992 + display 590, username fields 2,482, first/last 1,753, hard-negative fields 3,559,
  neutral-key fields 1,489, free-text person 3,930 / username 2,783 / mixed 860 / entity-free 1,424, narrative (2-3 frames, multi-entity) 1,584,
  key-value / cookie / query strings 2,380, logs 1,147, URL paths 1,248, headers 1,180, markup / embedded JSON 599.
* **Locations** mirror `http_extract`: `json_body.<nested path with [i]>`, `form.<key>`, `query_parameter.<key>`, `header.<name>`, `body.text`
  (11,140 distinct train locations). Key grammar: person roles (~100) x heads, bare roles, snake/camel/kebab/UPPER/dotted/concatenated styles,
  neutral keys (`value`, `q`, `data`...). Role words are hash-partitioned across splits (+20% common) so validation contains unseen keys.
* **Cue frames**: 248 hand-written cue templates (person weak/strong, username explicit/weak, mixed, log, URL, markup), hash-partitioned:
  train 142, val 24, calib 24, **common 58** (shared by design: "Dear {P},", "Logged in as {U}" ...). Val/calib draw 60% of their frames
  from split-exclusive templates (`exclusive_template` tag).
* **Frame-sharing hard negatives**: weak person cues are filled with job titles / teams / organisations / cities / products
  ("Dear Hiring Manager,", "Assigned to Engineering", "Contact Acme Labs"); weak username cues with organisations / places / products; explicit
  cues are never negated (no label noise). Key-level negatives: `user_id`, `session_id`, `user_agent`, `email`, `company_name`, `name` with an
  organisation / product / file / UUID value; person-looking companies ("Smith-Jones and Kirby"), neutral keys with person and non-person values.
* **Entity forms**: `First Last`, `Last, First`, `First M. Last`, `F. Last`, 3-token names, first / last only, CJK `LastFirst`, honorific-prefixed
  (honorific excluded from the span), `Name <email>` (e-mail local part is **not** an entity), handles from Faker usernames (55%), name-derived
  patterns (`jsmith`, `maria.garcia`, `maria_99`, 30%) and word-pair handles (15%); same-script name pairing; percent / plus encoding in query strings.
* **Noise**: case style applied identically to entities AND negatives (78% as-is / lower / UPPER / Title); NBSP, double-space and tab;
  wrapper quotes / brackets; lower-cased frame literals, list prefixes, dropped final punctuation; 3.3% truncated fields (spans clipped);
  1% with U+FFFD; Unicode names in 8 scripts.
* **Not generated** (documented gaps): real prose, HTML-escaped entities, base64 bodies, non-UTF-8 byte noise, names with embedded digits,
  non-English cue phrases beyond ~12, multi-line signature blocks longer than 3 lines.

## Label conventions
One span per person name (middle initial and `Last, First` included); first-name-only and last-name-only are `PERSON_NAME`; honorifics (`Mr.`,
`Dr.`), `@`, quotes and brackets excluded; USERNAME = human-chosen account handle (including name-like handles under username cues), not numeric
ids, hashes, UUIDs, hostnames or e-mail addresses; organisations, places, products, files, job titles and person-named companies / cities are
not entities. `display_name` / `nickname` fields take the label of the *value form* (name-like -> PERSON_NAME, handle-like -> USERNAME), a documented
ambiguity. Character offsets: code points, half-open; every example is checked at generation time (`spans_to_tags` strict alignment) and by
`tests/test_ml_v2_data.py` (bounds, non-overlap, no leading/trailing whitespace inside spans, token alignment).

## Leakage and overlap audit (`docs/ml/results/v2_dataset_manifest.json`)
| Check | Result |
|---|---|
| exact (location, text) duplicates across splits with entities | **0** (27 entity-free duplicates: fixed header values such as `content-type: application/json`) |
| cue templates shared across splits other than the designated *common* set | **0** |
| lexical items (names, cities, companies, usernames, words, ...) shared across splits | **0** (hash-partitioned by string) |
| entity strings shared between splits (case-insensitive) | 4 train-calib/train-val (`m`, `an`, `cor`, `de`: initials and name particles) |
| entity *tokens* shared (alphabetic, len > 1) train-val | 31, all sub-tokens of multi-part names / handles (`maria`, `anna`, `van`, `de`, `per`...) |
| common-cue share of cue-based examples | train 30.1% / val 36.0% / calib 32.9% |

Realism of the exclusion rules: partitioning *every* lexical item makes evaluation names unseen, which is **stricter than deployment** (real
traffic reuses common names) - it measures generalisation to new strings, and likely understates recall on very common names. Conversely the
partition cannot reproduce real-world category confusion (e.g. a person who is also a place name), so false-positive behaviour on such strings is
checked only in the challenge set (`Jackson`, `Madison`, `Johnson & Johnson`). The 58 common cues overlap in all splits, so validation partly
measures *seen* frames; `evaluate_v2.py` therefore reports recall separately for unseen-context spans and unseen-key examples (defined relative to the
V2 training set).

## Class balance (train)
PERSON_NAME 13,569 / USERNAME 11,306 entities; 9,083 of 30,000 examples (30.3%) contain no entity; 9,330 carry the `hard_negative` tag;
6,435 contain non-ASCII entities; 2,808 have >= 2 entities. Challenge: 504 PERSON_NAME / 324 USERNAME / 313 entity-free (29.6%) / 197 hard negatives.
