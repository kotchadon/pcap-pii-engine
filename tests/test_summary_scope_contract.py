"""Truthful Analysis Scope contract for the Summary experience.

A displayed scan-status badge is NOT proof that all encrypted/unsupported content
was inspected. These structural checks complement real browser behavior tests.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "src/packet_pii/dashboard_static/index.html"
JS = ROOT / "src/packet_pii/dashboard_static/app.js"


def test_summary_exposes_three_separate_analysis_scope_explanations():
    html = HTML.read_text(encoding="utf-8")
    for element_id in ("scope-summary", "scope-examined", "scope-partial", "scope-uninspectable"):
        assert f'id="{element_id}"' in html, f"Missing scope explanation {element_id}"
    for label in ("Web conversations checked", "Anything that needs attention", "Other network activity"):
        assert label in html, f"Missing scope category {label}"


def test_zero_findings_never_claim_all_personal_data_is_absent():
    js = JS.read_text(encoding="utf-8")
    assert "No personal information detected" not in js
    assert "No potential findings in inspected content" in js
    assert "scope-examined" in js and "scope-partial" in js
    assert "scope-uninspectable" in js
