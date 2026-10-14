# Dataset (synthetic, reproducible)

`python scripts/ml/make_dataset.py --out build/ml/data --manifest docs/ml/results/dataset_manifest.json` (seed 1234; ~1 s).
Committed: generator + `docs/ml/results/dataset_manifest.json` (counts, SHA-256 per split). The JSONL files are regenerated, not committed.

**Everything is fake.** Names are hand-written lists (Latin, accented, Cyrillic, Greek, CJK) plus procedurally generated pseudo-words; no downloads, no real people, no licensing issues.

| Split | Examples | Entities | Role |
|---|---|---|---|
| train | 9000 | PERSON_NAME + USERNAME | fit weights, build vocabulary |
| val | 1500 | 1145 | pick checkpoint (entity F1) |
| calib | 1500 | 1106 | pick the `min_score` operating point; reliability check |
| test | 2500 | 1942 | frozen; evaluated once at the end |

Sizes: see manifest for exact per-label/per-kind counts. Roughly 25-30% of examples contain no entity.

## Content (kinds)
`field_person / field_first / field_last / field_user` (JSON/form/query values under many key paths), `field_neg` (hard negatives under name-like keys: `name`, `title`, `team`, `user_agent`, `user_id`, filenames, product/company/city names, hostnames, hex ids), `text_person / text_user / text_mixed` (free-text messages, greetings, signatures, logs), `kv` (cookies, query strings, log lines, profile blocks), `url` (paths such as `/users/<handle>`), `text_neg` (no-PII sentences incl. "Hi everyone", "Welcome to <city>"). Mixed case/upper/lower, Unicode names, `L, F` and `F M. L` forms, handle patterns (`jsmith`, `Dark_Pixel42`, `xXnameXx`, `a.b`).

Labelling convention: a person's full name is **one** span; first-name-only and last-name-only are `PERSON_NAME`; honorifics, `@`, and prefixes are excluded; user ids / session ids / hostnames are negatives.

## Leakage prevention (verified by tests and `leakage_report`)
1. **Template families are split-exclusive** for free-text, kv, url and negative-text frames (0 shared templates/skeletons).
2. **Every lexical pool is hash-partitioned** (first/last names, handle words, cities, companies, products, file stems, words): 0 words shared across splits, so no identity - and no negative word - recurs. This also stops "unseen word => PERSON" from being a shortcut.
3. 0 exact (location, text) duplicates across splits; 0 gold entity strings shared with train.
4. Field-value examples share a few very common key paths (`username`, `name`, ...) across splits by design (1,309 shared (key, shape) skeletons); each split also has exclusive key names.
5. Within a split, exact duplicates are dropped and counted.

## Honest limits
* The data is *template-generated*. A held-out test of unseen frames and names measures generalisation across **my generator's** variety, not real HTTP traffic. No claim about real-world accuracy follows.
* The same author wrote the generator and the rule baseline; the baseline's cues overlap conceptually with the frames ("my name is", "Dear", `/users/`). This favours the baseline.
* Tokenisation assumes percent-decoded text (`%20` inside a name would merge tokens).
* Pseudo-names share a phoneme inventory with pseudo-handles/cities, so some distinctions must come from context alone.
