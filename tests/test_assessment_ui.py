"""Model Laboratory: Automated Model Quality Assessment section (static contract + real Chromium flow)."""
import re
from pathlib import Path

from test_model_lab_ui import browser_page, finish_scan  # noqa: F401  (fixture re-export)

STATIC = Path(__file__).resolve().parents[1] / 'src' / 'packet_pii' / 'dashboard_static'
HTML = (STATIC / 'index.html').read_text(encoding='utf-8')
LAB = (STATIC / 'lab.js').read_text(encoding='utf-8')
DISCLOSURE = ("These metrics are measured on automatically generated, labelled synthetic probes matched to aspects of this capture's "
              "structure. They are not precision, recall or F1 measured on the original uploaded traffic.")
FORBIDDEN = ('actual pcap accuracy', 'file-specific accuracy:', 'real-world accuracy', 'verified accuracy on the uploaded', 'percentage of correct findings')


def section(html):
    start = html.index('id="lab-assessment"')
    return html[start:html.index('id="lab-groundtruth"', start)]


def test_assessment_section_exists_between_live_analysis_and_ground_truth_with_the_exact_disclosure():
    html_order = [HTML.index(x) for x in ('id="lab-live"', 'id="lab-assessment"', 'id="lab-groundtruth"', 'id="lab-benchmark"')]
    assert html_order == sorted(html_order)
    block = section(HTML)
    assert 'Automated Model Quality Assessment' in block and DISCLOSURE in block
    assert 'CONTEXT-MATCHED SYNTHETIC PROBE METRIC' in block
    assert block.index(DISCLOSURE) < block.index('id="qa-table"')            # disclosure sits directly above the metrics
    lowered = block.lower()
    assert not [p for p in FORBIDDEN if p in lowered]
    assert 'File-specific accuracy unavailable: no verified ground-truth annotations provided.' in HTML      # ground-truth section intact
    assert 'View published synthetic benchmark' in HTML                                                    # benchmark still separate


def test_lab_js_renders_assessment_states_text_only_and_never_names_probe_metrics_as_accuracy():
    for state in ('pending', 'running', 'complete', 'partial', 'failed', 'cancelled', 'unavailable'):
        assert state in LAB
    assert 'Context-matched synthetic probe F1' in LAB and "DISCLOSURE" in LAB
    assert 'PARTIAL: only ' in LAB and 'LIMITED applicability' in LAB and 'not full probe-set metrics' in LAB
    assert 'innerHTML' not in LAB and 'eval(' not in LAB
    assert not [p for p in FORBIDDEN if p in LAB.lower()]
    assert '/assessment' in LAB and 'qa.token' in LAB                       # stale responses from a previous scan are ignored
    used = set(re.findall(r"q\('([\w-]+)'\)", LAB)) | set(re.findall(r"set\('([\w-]+)'", LAB)) | set(re.findall(r"qaList\('([\w-]+)'", LAB))
    assert used - set(re.findall(r'id="([^"]+)"', HTML)) == set()


def test_browser_assessment_appears_is_labelled_and_never_carries_over(browser_page):  # noqa: F811
    page, problems, tmp = browser_page
    page.check('input[name=scan-mode][value=hybrid]')
    page.click('#sample')
    finish_scan(page)
    page.click('[data-tab=model]')
    page.wait_for_selector('#qa-chip:has-text("COMPLETE")', timeout=30000)
    headline = page.inner_text('#qa-headline')
    assert headline.startswith('Context-matched synthetic probe F1') and 'synthetic probes only' in headline
    assert DISCLOSURE in page.inner_text('#qa-disclosure') and page.is_visible('#qa-body')
    table = page.inner_text('#qa-table')
    assert 'Context-matched synthetic probe F1 (micro)' in table and 'n/a' in table             # silent test model: undefined, not 0 or 1
    assert 'PERSON NAME probes' in table and 'USERNAME probes' in table
    text = page.inner_text('#lab-assessment').lower()
    assert not [p for p in FORBIDDEN if p in text]
    for needle in ('probe-set hash', 'generator probe-gen/1', 'seed 20250602', 'boundary diagnostics', 'false positives on negative probes'):
        assert needle in text
    assert 'ML coverage' in page.inner_text('#lab-live') or page.is_visible('#coverage-chip')   # live coverage remains a separate section
    # a following rules-only scan must not inherit the previous metrics
    page.click('[data-tab=overview]')
    page.check('input[name=scan-mode][value=rules]')
    page.click('#sample')
    finish_scan(page)
    page.click('[data-tab=model]')
    page.wait_for_selector('#qa-chip:has-text("UNAVAILABLE")', timeout=15000)
    assert page.is_hidden('#qa-body') and 'synthetic probe F1:' not in page.inner_text('#qa-headline')
    assert page.is_visible('#gt-unavailable') and problems == []
