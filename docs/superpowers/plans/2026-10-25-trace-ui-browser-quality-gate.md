# TRACE UI quality gate — execution plan (25 October 2026)

> Ownership: ChatGPT implements and verifies. Claude is reserved for V3 and only a narrow optional review.

**Goal:** Make the real-browser UI suite mandatory on CI before changing result semantics or the Inspector. No changes to ML, engine or HTTP reconstruction.

## Scope

- [x] Retain the existing full pytest job and frozen ground-truth fixture check.
- [x] Add a separate Linux Chromium job using the supported Python Playwright installation method.
- [x] Change the browser fixture so `TRACE_REQUIRE_BROWSER=1` fails if Playwright or Chromium is missing, rather than skipping.
- [x] Capture non-sensitive screenshots from a synthetic fixture at 1440/1024/390.
- [ ] Confirm GitHub executes all browser journeys and inspect any failure, including screenshot artifacts.
- [ ] Run final branch CI to completion; do not merge before its results are known.

## Verification

```sh
TRACE_REQUIRE_BROWSER=1 TRACE_UI_ARTIFACT_DIR=artifacts/trace-ui python -m pytest -q tests/test_experience_journeys.py tests/test_http_investigation_ui.py
python -m pytest -q
```

The browser suite must report zero skipped browser fixtures. Optional ML or platform tests in the **full pytest** job remain separately disclosed; their skip count is not a pass.

## Follow-on work (separate PRs)

1. Analysis Scope & Trust: clarify inspected versus not inspectable only from actual report fields, with dedicated tests for encrypted-only, partial-ML, gaps, and no-findings captures.
2. Inspector usability refinements: grouping, persistent context, no copied raw sensitive content.
3. Search and timeline: require separate narrowly reviewed evidence API enhancements after performance V3 stabilises.
