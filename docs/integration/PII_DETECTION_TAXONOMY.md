# TRACE PII detection taxonomy — identity & demographic categories (v1)

Status: additive contract for the rules detector. Implementation: `src/packet_pii/identity_rules.py`, called from
`packet_pii.detect.detect_fields()`. Tests: `tests/test_identity_rules.py`, `tests/test_identity_integration.py`.
Synthetic validation: `scripts/evaluate_identity_rules.py` → `docs/integration/results/identity_rules_validation_v1.json`.

## Scope (read first)

* **Explicit transmission only.** A category is reported only when a value is *explicitly transmitted* under an
  *explicitly labelled* structured field: a JSON key path, a URL query parameter, a form field or an HTTP header name.
* **No inference.** TRACE never infers age, sex, gender or identity from names, usernames, titles, photos, free text,
  writing style or anything indirect. `body.text` (unstructured text) is never inspected by these rules.
* **Two independent conditions per finding.** (1) the field key is on an exact allowlist (no substring matching), and
  (2) the value passes the category's format/vocabulary check. Either failing → no finding.
* **Detector attribution.** Every finding below has `detector: "rule"`. The contextual BiLSTM V2 is trained and validated
  only for `PERSON_NAME` and `USERNAME`; it never emits these categories, and Hybrid mode runs these same rules unchanged.
* **Scores are heuristics.** `confidence` is an ordinal statement of evidence strength chosen by hand. It is **not** a
  calibrated probability and is not measured accuracy.

## Existing categories (unchanged)

| Category | Detector | Notes |
|---|---|---|
| `EMAIL`, `IP_ADDRESS`, `PHONE`, `CREDIT_CARD`, `CREDENTIAL_OR_TOKEN`, `USERNAME`, `PERSON_NAME_CANDIDATE` | rule | Behaviour, scores, ordering and masking are byte-identical to `main` (verified on 1,329 fixed messages). |
| `PERSON_NAME`, `USERNAME` | bilstm (Hybrid) | Unchanged. Ground-truth and probe evaluation stay restricted to these labels. |

## Key matching

A location such as `json_body.users[0].profile.age` is split on `.`, `[`, `]`; array indices are dropped; the source
prefix (`json_body`, `query_parameter`, `form`, `header`) is removed; a leading `x-` is removed from header names. A key is
compared after lower-casing and deleting only the separators `_ - : whitespace`, so `userAge`, `user_age`, `user-age`
compare equal. Any other character is kept, so `âge` or full-width `ａｇｅ` never collapse into `age`, and `page`, `stage`,
`message`, `agent`, `usage`, `max_age`, `sexuality`, `section`, `sextant`, `gendered_content` never match.

*Nearest meaningful parent*: walking up from the leaf, generic wrappers (`data, payload, body, attributes, attrs, params,
fields, properties, props, info, details, traits, values`) are skipped. *Person context* parents: `user, profile, person,
people, customer, member, patient, subscriber, player, demographic(s), viewer, buyer, applicant, me, self, participant,
respondent, student, employee, traveler/traveller, passenger, guest, visitor, user_properties, user_attributes, user_data,
user_info, user_profile, personal_data, personal_info, personal_details, customer_info, profile_info, member_info`
(simple plurals accepted). Parsing is linear, bounded to the last 1,024 path characters / 8 segments, and cached for
locations ≤ 256 characters.

## Category contracts

### `APPLE_ADVERTISING_ID`

| Field | Contract |
|---|---|
| Display label | Apple advertising identifier (IDFA) |
| Semantic definition | A value transmitted under a field that names Apple's Identifier for Advertisers, or a generic advertising-ID field whose platform is established as Apple by independent context. |
| Detection source | Rules |
| Qualifying context | Keys `idfa`, `ios_idfa`, `apple_idfa`, `ios_advertising_id`, `apple_advertising_id`, `ios_ad_id`, `apple_ad_id`, `ios_ifa`, `apple_ifa` (any case/separator). Or a generic key (see `ADVERTISING_ID`) with exactly one platform = Apple from: a parent path segment token (`ios, ipados, iphone, ipad, apple`), or a platform field (`os, os_name, platform, platform_name, device_os, os_type, device_platform, operating_system`) whose value is `iOS`/`iPadOS`/`iPhone OS`/`tvOS` (optional version) in an enclosing scope (same JSON object or an ancestor; query/form/header fields are message-wide). |
| Accepted value forms | Canonical UUID `8-4-4-4-12` hex, upper or lower case, nothing else in the field. |
| Validation | Exact-length anchored UUID check; nil UUID `00000000-…` and max UUID `ffffffff-…` rejected. |
| Exclusions | Zeroed IDFA (ATT denied / limit ad tracking): **not reported** — it carries no identifier. Unhyphenated, hashed (`idfa_hash`), prefixed/suffixed values; keys that only contain `idfa` (`myidfa`, `idfa_enabled`); generic UUIDs (request, correlation, session, transaction, record IDs); `ad_id`/`adid` (advertisement / Adjust IDs). If context names Android too, the finding is downgraded to `ADVERTISING_ID`. |
| Masking | `ab***yz` (first 2 + last 2 of 36 characters) unless raw values are explicitly authorised. |
| Score semantics | 0.90 platform-specific key; 0.88 generic key + one context platform. Heuristic, not probability. |
| False-positive risks | Developer/test UUIDs placed under an `idfa` key; non-Apple values under a mislabelled key. |
| Evidence expectations | The field location and the masked value; platform evidence is the key itself or the sibling/ancestor field named above. |
| Limitations | Syntactic + contextual only: cannot verify the value was issued by Apple or assigned to this device. The User-Agent is deliberately not used as platform evidence. |

### `ANDROID_ADVERTISING_ID`

| Field | Contract |
|---|---|
| Display label | Android advertising ID (AAID/GAID) |
| Semantic definition | A value transmitted under a field that names the Google/Android advertising ID, or a generic advertising-ID field whose platform is established as Android by independent context. |
| Detection source | Rules |
| Qualifying context | Keys `gaid`, `aaid`, `android_advertising_id`, `google_advertising_id`, `android_ad_id`, `google_ad_id`, `gps_adid`, `android_ifa`. Or a generic key with exactly one platform = Android: parent token `android, google, gms`, or a platform field valued `Android` (optional version). |
| Accepted value forms / Validation | As `APPLE_ADVERTISING_ID`. |
| Exclusions | Zeroed GAID (user opted out) not reported. **Not** advertising IDs: Android ID / SSAID (→ `DEVICE_ID`), App Set ID, Firebase Installation ID (unclassified, see deferred), Google account IDs, session IDs, generic device UUIDs. Conflicting Apple context → `ADVERTISING_ID`. |
| Masking / Score | As `APPLE_ADVERTISING_ID` (0.90 / 0.88). |
| False-positive risks / Limitations | As `APPLE_ADVERTISING_ID`. |

### `ADVERTISING_ID` (platform not established)

| Field | Contract |
|---|---|
| Display label | Advertising identifier (platform not established) |
| Semantic definition | An advertising identifier whose platform TRACE could not establish, either because no platform evidence exists or because evidence conflicts. TRACE never assigns such a value to Apple or Android. |
| Qualifying context | Generic keys `advertising_id`, `advertising_identifier`, `ifa` (OpenRTB), `maid`, `mobile_advertising_id`, `mobile_ad_id`, `device_advertising_id` with zero or conflicting platform evidence; or a platform-specific key with conflicting evidence. |
| Validation / Exclusions / Masking | As `APPLE_ADVERTISING_ID` (zeroed values not reported). |
| Score | 0.86 heuristic. |
| Limitations | Platform evidence in a *sibling array element* (e.g. `events[0].os` vs `events[1].advertising_id`) is intentionally ignored. |

### `AGE`

| Field | Contract |
|---|---|
| Display label | Age (explicitly transmitted) |
| Semantic definition | A person's age in years, explicitly transmitted under an age-labelled field. It does **not** mean TRACE inferred an age. Distinct from date of birth and birth year (not detected). |
| Qualifying context | Bare `age` at the root of a query/form/JSON body, or whose nearest meaningful parent is a person context (`user.age`, `profile.age`, `data.customer.age`, `users[2].age`, `traits.age`). Prefixed keys `user_age, person_age, customer_age, member_age, patient_age, profile_age, age_years, age_in_years`. Never in HTTP headers (the standard `Age` header is a cache age). |
| Accepted value forms | Integer 1–120 without sign/leading zero/decimals, optional unit `y`, `yr(s)`, `year(s)`, optional `old` (`27`, `27 years`, `27y`). Surrounding whitespace tolerated. |
| Validation | Anchored bounded regex + integer range. |
| Exclusions | `0` (common unset default), > 120, decimals (`27.0`), negative, dates, years (`1990`), age ranges/brackets (`25-34`), `27 days`; `cache.age`, `product.age`, `item.age`, `account.age`; `page`, `retry_count`, `max_age`, `age_group`. |
| Masking | Always `[REDACTED]` (a partial mask would disclose the value). |
| Score | 0.85 heuristic. |
| False-positive risks | A root-level `age` that is a content filter (`/movies?age=18`) or a person-context field that holds a non-person age. |
| Limitations | Unknown intermediate parents (`user.meta.age`) are not accepted (false negative by design). |

### `GENDER`

| Field | Contract |
|---|---|
| Display label | Gender (explicitly transmitted) |
| Semantic definition | A value transmitted under a field explicitly labelled *gender*. Reported as labelled by the sender; TRACE does not equate it with sex. |
| Qualifying context | Bare `gender` (root or person-context parent); `user_gender, person_gender, customer_gender, member_gender, patient_gender, profile_gender, gender_identity`. Not in headers. |
| Accepted value forms | Case/separator-insensitive terms: `male, female, man, woman, non-binary/nonbinary, genderqueer, agender, genderfluid, bigender, two-spirit, transgender, trans man, trans woman, transgender man/woman, trans male/female, intersex`; single letters `M`/`F` (documented mapping, e.g. OpenRTB `user.gender`). Not binary-only. |
| Exclusions | `O`, `U`, `X` and all numeric codes (`0/1/2/9`) — meaning not reliably determinable, left unclassified. Non-disclosures (`unknown`, `other`, `prefer not to say`, empty). Product attributes (`product.gender = womens`), `gendered_content`, `sexuality`. |
| Masking | Always `[REDACTED]`. |
| Score | 0.85 for a listed term; 0.82 for `M`/`F`. Heuristic. |
| False-positive risks | Person-context parents used for non-persons (e.g. `voice.profile.gender` for a TTS voice). |
| Limitations | Cannot tell self-identified gender from an administrative field the sender calls "gender". |

### `SEX`

| Field | Contract |
|---|---|
| Display label | Sex (explicitly transmitted) |
| Semantic definition | A value transmitted under a field explicitly labelled *sex*, including sex assigned at birth and legal/administrative sex markers. The field location tells which. Not equated with gender identity. |
| Qualifying context | Bare `sex` (root or person-context parent); `user_sex, person_sex, customer_sex, member_sex, patient_sex, profile_sex, sex_at_birth, assigned_sex_at_birth, birth_sex, biological_sex, legal_sex, administrative_sex`. |
| Accepted value forms / Exclusions | Same vocabulary and exclusions as `GENDER` (`X` is left unclassified). |
| Masking / Score | `[REDACTED]`; 0.85 / 0.82. |
| Limitations | Does not distinguish biological, birth-assigned and legal sex beyond what the field name states. |

### `DEVICE_ID`

| Field | Contract |
|---|---|
| Display label | Device identifier |
| Semantic definition | A persistent device or vendor-scoped device identifier explicitly labelled as such. Not an advertising ID. |
| Qualifying context | Keys `device_id, android_id, ssaid, idfv, identifier_for_vendor, udid, hardware_id, hwid`; `device.id/uuid/guid`. |
| Accepted value forms | Opaque token `[A-Za-z0-9][A-Za-z0-9._:-]*`, 8–128 chars, at least one digit. |
| Exclusions | Placeholders (`unknown`, `null`, `test`, …), all-zero, nil/max UUID, values with spaces, values without digits (`unknown-device`), App Set ID, Firebase Installation ID, `device.model`. |
| Masking | `ab***yz`; values ≤ 8 characters → `****`. |
| Score | 0.84 heuristic. |
| False-positive risks | Model numbers placed under `device_id` (`SM-G991B`). |
| Limitations | Cannot tell hardware-bound from app-generated identifiers. |

### `USER_ACCOUNT_ID`

| Field | Contract |
|---|---|
| Display label | User / account identifier |
| Semantic definition | A pseudonymous identifier for a user, account, customer, member, subscriber, player, profile or patient, explicitly labelled as such. |
| Qualifying context | Keys `user_id, account_id, customer_id, member_id, subscriber_id, player_id, profile_id, customer_number, account_number`; `<parent>.id/uuid/guid` where the **immediate** parent is `user, account, customer, member, subscriber, player, profile, patient`. |
| Accepted value forms | Opaque token `[A-Za-z0-9][A-Za-z0-9._:-]*`, 1–128 chars. |
| Exclusions | Bare `id`, `order.id`, `contact.id`, `uid` (ambiguous), `client_id` (an application), `request_id`; placeholders (`anonymous`, `guest`, `null`, `0`, `-1`, …); values with spaces or `@` (e-mail-shaped IDs stay `EMAIL`). `session_id` stays `CREDENTIAL_OR_TOKEN`. |
| Masking | `ab***yz`; values ≤ 8 characters → `****` (short numeric IDs would otherwise be nearly fully disclosed). |
| Score | 0.82 heuristic. |
| False-positive risks | Service/robot accounts; tenant/organisation IDs under `account_id`. |
| Limitations | Does not establish that the identifier links to a real person. |

## Thresholds, ordering, deduplication, limits

All new scores are ≥ the default threshold 0.8, so every category is reported by default. Threshold semantics are
unchanged: `0.86` keeps only advertising IDs, `0.95` keeps none of the new categories. At most one identity category is
emitted per field; output order follows field order; deduplication and the 10,000-findings-per-message cap are the
existing `detect_fields()` ones.

## Privacy

Values are masked by default (`include_values=False`); raw values appear only through the existing explicit
`include_values=True` path. Report exports still drop the unsalted `fingerprint`. Nothing is logged; the location cache
holds field *names* only (bounded LRU, 16,384 entries, same pattern as the credential-key cache). The validation results
file contains no field values.

## Integration

`HTTP field → detect_fields() → Detection(pii_type, location, confidence, value, detector='rule', fingerprint) → engine
provenance → report finding`. No changes to the engine, TCP/HTTP reconstruction, ML inference, ground-truth manifests or
ML coverage. `schemas/report-v1.schema.json` already allows any non-empty `pii_type`, so the change is additive.
Ground-truth evaluation (`groundtruth.py`) counts the new categories as out-of-scope rule findings, and both the
`evaluate_v2.py` host-rules baseline and the PR #23 probe evaluator keep only `USERNAME`/`PERSON_NAME_CANDIDATE`, so
PERSON_NAME/USERNAME F1 is unaffected.

This taxonomy does not assume any field of the upcoming network-evidence API. Evidence for these findings is the existing
`location` + masked `value` + message provenance.

**Dashboard follow-up (owner: UI).** `dashboard_static/app.js` hard-codes the job-report type filter list and has
per-category explanations only for the old categories. New categories currently fall through to the generic rules
explanation and are missing from the job-report filter dropdown. Suggested explanation text is the *Semantic definition*
row of each table above, plus "explicitly transmitted, not inferred".

## Synthetic validation (v1)

*Synthetic rule-validation results for newly introduced categories — not real-world or deployment accuracy.* 79
hand-written fictional messages / 145 fields, labelled by the author from these definitions (not from detector output),
scored at field level at threshold 0.8. 8 messages are deliberate **hard cases** the conservative rules are expected to
miss or misclassify.

| Subset | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| All cases | 47 | 4 | 5 | 0.922 | 0.904 | 0.913 |
| Excluding hard cases | 47 | 0 | 0 | 1.000 | 1.000 | 1.000 |

The 1.000 row measures conformance to this specification on cases written by the same author; it is not evidence of
real-world accuracy. All 9 errors are hard cases: IDFA with platform only in the User-Agent (reported as
`ADVERTISING_ID`), unhyphenated IDFA, `user.meta.age`, OpenRTB `O`, `uid` (false negatives); `/movies?age=18`, TTS
`voice.profile.gender`, `device_id = SM-G991B` (false positives). Per-category figures and the confusion list are in
`docs/integration/results/identity_rules_validation_v1.json` (reproduced by a test).

## Performance (rules only, no PCAP, no ML)

`python scripts/bench_identity_rules.py` (200,000 synthetic fields / 5,000 messages, best of 5, vs `main`):

* Traffic without identity fields: +1.6 % to +7.9 % across runs (one cached key lookup per field).
* Identity-heavy traffic (≈ 1 in 4 fields is an identity field): +17 % to +32 %, which tracks the 44 % more findings
  emitted (each finding is hashed and masked like any existing finding).
* Pathological inputs (100,000-character values, 50,000-segment keys, 50,000 `[`) complete well under the 2 s test bound;
  all regexes are anchored with no nested quantifiers.

## Deferred (not detected; insufficient evidence for low-noise rules)

Date of birth / birth year (separate category needed), age ranges, sexual orientation (special category, needs its own
review), App Set ID, Firebase Installation ID / app instance IDs, Google account IDs, `uid`, hashed advertising IDs
(MD5/SHA-1 of IDFA/GAID), unhyphenated UUID forms, IMEI/MEID/serial numbers (need checksum/format work), and
User-Agent-based platform attribution.
