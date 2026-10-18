"""Model Laboratory: static contract checks (always run) and a real-Chromium flow (skipped when no browser is available)."""
import json
import re
import shutil
import threading
import time
from pathlib import Path

import pytest

from packet_pii.dashboard import DashboardServer
from test_ml_runner import Stub, capture
from test_vp_qa_support import build_pcap, conversation, ok_response, post_json

STATIC = Path(__file__).resolve().parents[1] / 'src' / 'packet_pii' / 'dashboard_static'
HTML = (STATIC / 'index.html').read_text(encoding='utf-8')
LAB = (STATIC / 'lab.js').read_text(encoding='utf-8')
APP = (STATIC / 'app.js').read_text(encoding='utf-8')


def test_model_lab_has_separate_live_ground_truth_and_benchmark_sections():
    for heading in ('Live Capture Analysis', 'Ground-Truth Evaluation', 'Published synthetic benchmark'):
        assert heading in HTML
    assert HTML.index('Live Capture Analysis') < HTML.index('Ground-Truth Evaluation') < HTML.index('Published synthetic benchmark')
    assert 'File-specific accuracy unavailable: no verified ground-truth annotations provided.' in HTML
    assert 'not this file’s accuracy' in HTML and 'id="gt-results" class="gt-results hidden"' in HTML    # results hidden until verified


def test_every_element_id_used_by_lab_js_exists_in_the_page():
    ids = set(re.findall(r'id="([^"]+)"', HTML))
    used = set(re.findall(r"q\('([\w-]+)'\)", LAB)) | set(re.findall(r"set\('([\w-]+)'", LAB))
    assert used - ids == set()


def test_partial_coverage_banner_wording_and_no_innerhtml():
    assert "'ML coverage limit reached. Analysed '" in LAB and "' eligible fields ('" in LAB and "'%). Results are incomplete.'" in LAB
    assert 'innerHTML' not in LAB and 'insertAdjacentHTML' not in LAB and 'eval(' not in LAB            # CSP-safe, text-only rendering
    assert 'style=' not in HTML.replace('<meta', '')                                                  # CSP forbids inline style attributes
    for state in ('complete', 'partial', 'no_eligible_fields', 'not_requested', 'unavailable', 'failed'):
        assert state in LAB


def test_lab_js_never_computes_accuracy_and_labels_partial_evaluations():
    assert 'These are NOT full-file metrics' in LAB and 'PARTIAL evaluation' in LAB
    assert not re.search(r'f1\s*=\s*2\s*\*', LAB) and 'tp/(tp' not in LAB.replace(' ', '')             # metrics come only from the server


def test_app_js_sends_ml_coverage_and_manifest_headers_through_the_lab():
    assert 'TraceLab.scanHeaders()' in APP and "'X-ML-Coverage'" in LAB and "'X-Ground-Truth-Manifest'" in LAB
    assert '/lab.js' in HTML and HTML.index('/lab.js') < HTML.index('/app.js')


CHROME = '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'


@pytest.fixture
def browser_page(tmp_path):
    sync_api = pytest.importorskip('playwright.sync_api')
    exe = next((p for p in (CHROME, shutil.which('chromium'), shutil.which('google-chrome')) if p and Path(p).exists()), None)
    if exe is None:
        pytest.skip('no Chromium available')
    server = DashboardServer(('127.0.0.1', 0), ml_detector=Stub())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    with sync_api.sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(executable_path=exe, args=['--no-sandbox'])
        except Exception as exc:                                     # pragma: no cover - environment dependent
            pytest.skip(f'cannot launch Chromium: {exc}')
        page = browser.new_page(viewport={'width': 1300, 'height': 1400})
        problems = []
        page.on('pageerror', lambda e: problems.append(str(e)))
        page.on('console', lambda m: problems.append(m.text) if m.type == 'error' and 'status of 4' not in m.text else None)
        page.on('response', lambda r: problems.append(f'{r.status} {r.url}') if r.status >= 400 and 'favicon' not in r.url else None)
        page.goto(f'http://127.0.0.1:{server.server_port}/')
        page.wait_for_selector('#sample')
        yield page, problems, tmp_path
        browser.close()
    server.shutdown()
    server.server_close()


def finish_scan(page, timeout=60000):
    page.wait_for_selector('#statusbar:not(.hidden)')
    page.wait_for_selector('#statusbar.hidden', state='attached', timeout=timeout)


def test_browser_partial_then_complete_coverage_and_ground_truth_flow(browser_page, tmp_path):
    page, problems, tmp = browser_page
    big = capture(tmp, messages=12, fields=40)                       # 12 x (40 + 1) = 492 eligible fields
    page.check('input[name=scan-mode][value=hybrid]')
    page.wait_for_selector('#ml-profile-row:not(.hidden)')
    page.click('[data-tab=model]')
    assert 'File-specific accuracy unavailable' in page.inner_text('#gt-unavailable')
    page.click('[data-tab=overview]')
    page.set_input_files('#file', str(big))
    finish_scan(page)
    page.click('[data-tab=model]')
    assert page.inner_text('#coverage-chip') == 'COMPLETE' and page.is_hidden('#coverage-banner')
    assert '492 of 492 eligible fields (100%)' in page.inner_text('#coverage-headline')
    # the real server default budget (10,000 fields) is not reachable with a small file, so assert the not-requested state too
    page.click('[data-tab=overview]')
    page.check('input[name=scan-mode][value=rules]')
    page.set_input_files('#file', str(big))                           # same file again: must re-trigger
    finish_scan(page)
    page.click('[data-tab=model]')
    assert page.inner_text('#coverage-chip') == 'NOT REQUESTED' and page.is_hidden('#ml-profile-row')
    # ground truth against the showcase
    page.click('#gt-demo')
    page.wait_for_selector('#gt-clear:not(.hidden)')
    assert 'hand-designed demonstration' in page.inner_text('#gt-manifest-info').lower()
    page.click('[data-tab=overview]')
    page.click('#sample')
    finish_scan(page)
    page.click('[data-tab=model]')
    page.wait_for_selector('#gt-results:not(.hidden)')
    assert page.is_hidden('#gt-unavailable') and 'Verified manifest' in page.inner_text('#gt-status')
    rows = page.inner_text('#gt-body')
    assert 'Rules only' in rows and 'Model only' not in rows           # rules-only scan: no model systems
    # a different capture with the same manifest: unavailable, never someone else's accuracy
    page.click('[data-tab=overview]')
    page.set_input_files('#file', str(big))
    finish_scan(page)
    page.click('[data-tab=model]')
    assert page.is_hidden('#gt-results') and 'SHA-256' in page.inner_text('#gt-unavailable')
    page.click('#gt-clear')
    assert 'File-specific accuracy unavailable: no verified ground-truth annotations provided.' in page.inner_text('#gt-unavailable')
    assert problems == []
