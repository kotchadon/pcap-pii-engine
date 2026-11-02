"""Real-browser journeys for the redesigned TRACE experience (Chromium via Playwright).

These drive the actual dashboard server and the real engine. They are skipped when Playwright
or Chromium is unavailable; they are not replaced by DOM mocks.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import threading
from pathlib import Path

import pytest

from packet_pii.dashboard import DashboardServer

STATIC = Path(__file__).resolve().parents[1] / 'src' / 'packet_pii' / 'dashboard_static'
CHROME = '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'
HOSTILE = ('<html><head><link rel="stylesheet" href="http://example.invalid/s.css"></head>'
           '<body onload="window.__pwned=1"><script>window.__pwned=2</script>'
           '<img src="http://example.invalid/p.png" onerror="window.__pwned=3"><a href="javascript:window.__pwned=4">x</a></body></html>')


@pytest.fixture
def browser():
    # In developer environments the browser suite may be optional. In CI it is
    # required: an absent Playwright/Chromium installation MUST fail the job.
    required = os.environ.get('TRACE_REQUIRE_BROWSER') == '1'
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        if required:
            pytest.fail(f'Chromium UI tests required but Playwright is unavailable: {exc}')
        pytest.skip('Playwright unavailable')
    with sync_playwright() as pw:
        exe = next((p for p in (CHROME, pw.chromium.executable_path,
                                shutil.which('chromium'), shutil.which('google-chrome'))
                    if p and Path(p).exists()), None)
        if exe is None:
            if required:
                pytest.fail('Chromium UI tests required but no matching browser is installed')
            pytest.skip('no Chromium available')
        try:
            b = pw.chromium.launch(executable_path=exe, args=['--no-sandbox'])
        except Exception as exc:  # pragma: no cover - environment dependent
            if required:
                pytest.fail(f'Chromium UI tests required but browser launch failed: {exc}')
            pytest.skip(f'cannot launch Chromium: {exc}')
        yield b
        b.close()


@pytest.fixture
def server():
    servers = []

    def start(**kwargs):
        s = DashboardServer(('127.0.0.1', 0), **kwargs)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        servers.append(s)
        return f'http://127.0.0.1:{s.server_port}/'
    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


def open_page(browser, url, width, height):
    page = browser.new_page(viewport={'width': width, 'height': height})
    problems = []
    page.on('pageerror', lambda e: problems.append(f'pageerror {e}'))
    page.on('request', lambda r: problems.append(f'external {r.url}') if not r.url.startswith(url) else None)
    page.goto(url)
    page.wait_for_selector('#sample')
    return page, problems


def run_sample(page):
    page.click('#sample')
    # On fast machines the example completes before the progress banner is
    # observable. Completion, not a transient animation, is the contract.
    page.wait_for_selector('#view-summary:not(.hidden)', timeout=60000)
    page.wait_for_selector('#statusbar.hidden', state='attached', timeout=60000)


def screenshot_artifact(page, name):
    """Screenshots contain only the deliberately fictional showcase capture."""
    target = os.environ.get('TRACE_UI_ARTIFACT_DIR')
    if target:
        folder = Path(target)
        folder.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(folder / (name + '.png')), animations='disabled')


def box(page, selector):
    return page.locator(selector).bounding_box()


def test_journey_a_first_use_and_b_inspect_in_place_on_desktop(browser, server):
    page, problems = open_page(browser, server(), 1440, 900)
    # First opening: one obvious action, the sample is clearly labelled, auto-start is stated up front.
    assert page.is_visible('#start-title') and page.is_visible('#choose') and page.is_visible('#sample')
    assert page.is_hidden('#page-head')
    assert 'Analysis starts as soon as you choose a file' in page.inner_text('#dropzone')
    assert page.inner_text('#ctx-status') == 'Not analysed'
    run_sample(page)
    screenshot_artifact(page, 'summary-1440')
    # The answer leads: count, kinds, completeness.
    assert re.match(r'\d+ potential findings?', page.inner_text('#answer-title'))
    assert page.inner_text('#verdict-icon') in ('Scan finished', 'Check details')
    assert page.inner_text('#ctx-status') in ('Complete', 'Incomplete')
    page.click('.answer [data-go=findings]')
    page.wait_for_selector('#fi-support .msg-card')
    assert page.get_attribute('#inspector', 'data-mode') == 'pane'
    assert page.get_attribute('#inspector', 'data-open') == 'true'
    # VP scenario: select finding A, then B. The inspector is beside the list and the page never moves.
    rows = page.locator('#findings-body tr')
    assert rows.count() >= 4
    y0 = page.evaluate('scrollY')
    rows.nth(2).click()
    expect_type = rows.nth(2).locator('.row-title').inner_text()
    page.wait_for_function('t=>document.getElementById("inspect-title").textContent===t', arg=expect_type)
    assert 'selected' in rows.nth(2).get_attribute('class')
    assert page.evaluate('scrollY') == y0
    list_box, insp_box = box(page, '#view-findings .list-card'), box(page, '#inspector')
    assert insp_box['x'] >= list_box['x'] + list_box['width'] - 1, 'inspector must sit beside the list'
    assert insp_box['y'] < 120 and insp_box['height'] > 600, 'inspector must be visible without scrolling'
    screenshot_artifact(page, 'inspector-1440')
    rows.nth(4).click()
    page.wait_for_function('v=>document.getElementById("inspect-sub").textContent===v', arg=rows.nth(4).locator('.row-sub').inner_text())
    assert page.evaluate('scrollY') == y0
    # Keyboard: arrow keys move the selection and the pane follows.
    rows.nth(1).locator('.row-main').focus()
    page.keyboard.press('ArrowDown')
    page.wait_for_function('v=>document.getElementById("inspect-sub").textContent===v', arg=rows.nth(2).locator('.row-sub').inner_text())
    assert 'selected' in rows.nth(2).get_attribute('class')
    # Hide and bring back.
    page.click('#insp-close')
    assert page.get_attribute('#inspector', 'data-open') == 'false'
    rows.nth(3).click()
    assert page.get_attribute('#inspector', 'data-open') == 'true'
    assert problems == []


@pytest.mark.parametrize('width,height,mode', [(1024, 768, 'drawer'), (768, 1024, 'drawer'), (390, 844, 'sheet'), (375, 667, 'sheet')])
def test_journey_b_drawer_and_sheet_open_in_place_and_return(browser, server, width, height, mode):
    url = server()
    page, problems = open_page(browser, url, 1440, 900)
    run_sample(page)
    page.set_viewport_size({'width': width, 'height': height})
    if page.is_visible('#nav-toggle'):
        page.click('#nav-toggle')
    page.click('.nav-link[data-tab=findings]')
    page.wait_for_selector('#findings-body tr .row-main')
    assert page.get_attribute('#inspector', 'data-mode') == mode
    assert page.get_attribute('#inspector', 'data-open') == 'false', 'auto-selection must not cover the list on small screens'
    page.evaluate('window.scrollTo(0, 260)')
    y0 = page.evaluate('scrollY')
    row = page.locator('#findings-body tr').nth(3)
    row.locator('.row-main').click()
    page.wait_for_selector('#fi-support .msg-card')
    page.wait_for_timeout(350)  # let the slide-in finish before measuring
    assert page.get_attribute('#inspector', 'data-open') == 'true'
    assert page.get_attribute('#inspector', 'role') == 'dialog' and page.get_attribute('#inspector', 'aria-modal') == 'true'
    assert page.evaluate('document.getElementById("main").inert') is True
    assert page.evaluate('document.activeElement.id') == 'insp-title'
    b = box(page, '#inspector')
    assert b['x'] >= 0 and b['x'] + b['width'] <= width + 1 and b['y'] + b['height'] <= height + 1
    if mode == 'sheet':
        assert abs(b['width'] - width) <= 1
    if width in (1024, 390):
        screenshot_artifact(page, f'inspector-{width}')
    assert page.evaluate('scrollY') == y0, 'opening must not move the page'
    page.keyboard.press('Escape')
    page.wait_for_function('() => document.getElementById("inspector").dataset.open==="false"')
    assert page.evaluate('document.getElementById("main").inert') is False
    assert page.evaluate('document.activeElement.className') == 'row-main'
    assert 'selected' in row.get_attribute('class')
    assert page.evaluate('scrollY') == y0, 'closing must return to the same place'
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
    assert problems == []


def test_journey_c_technical_evidence_and_back(browser, server):
    page, problems = open_page(browser, server(), 1440, 900)
    run_sample(page)
    page.click('.nav-link[data-tab=findings]')
    page.wait_for_selector('#fi-support .msg-card')
    finding_type = page.inner_text('#inspect-title')
    page.click('#fi-support .msg-card .btn')
    page.wait_for_selector('#insp-dynamic .switch-btn')
    assert page.inner_text('#insp-kicker').startswith('HTTP')
    assert page.is_visible('#insp-back')
    assert page.locator('#insp-dynamic .switch-btn').count() >= 2
    assert 'frame_' in page.inner_text('#insp-dynamic .x-table')
    assert 'original recording' in page.inner_text('#insp-dynamic') or 'recorded data below' in page.inner_text('#insp-dynamic')
    page.locator('#insp-dynamic .switch-btn').nth(1).click()
    page.wait_for_function('() => document.getElementById("insp-title").textContent.startsWith("HTTP/")')
    page.click('#insp-back')
    page.wait_for_selector('#insp-finding:not(.hidden)')
    assert page.inner_text('#inspect-title') == finding_type
    # The same inspector serves Traffic: conversations and connections.
    page.click('.nav-link[data-tab=flows]')
    page.wait_for_selector('#conv-body tr .row-main')
    page.locator('#conv-body tr').first.click()
    page.wait_for_selector('#insp-dynamic .switch-btn')
    page.click('#seg-connections')
    page.locator('#flows-body tr').first.click()
    page.wait_for_function('() => document.getElementById("insp-kicker").textContent==="Connection"')
    # Returning to Findings restores that view's own inspector state.
    page.click('.nav-link[data-tab=findings]')
    page.wait_for_selector('#insp-finding:not(.hidden)')
    assert page.inner_text('#inspect-title') == finding_type
    assert problems == []


def test_journey_d_sensitive_source_is_inert_and_hide_wins_races(browser, server):
    url = server(retain_capture_for_inspection=True)
    page, problems = open_page(browser, url, 1440, 900)
    run_sample(page)
    page.click('.nav-link[data-tab=flows]')
    page.wait_for_selector('#conv-body tr .row-main')
    page.locator('#conv-body tr').first.click()
    page.wait_for_selector('#insp-dynamic .switch-btn')
    page.locator('#insp-dynamic .switch-btn').nth(1).click()
    page.wait_for_selector('#insp-dynamic .source-section .ack input')
    gate = {'hold': True}

    def content(route):
        if gate['hold']:
            page.wait_for_timeout(1200)
        body = {'text': HOSTILE, 'is_html': True, 'status': 'recovered', 'capture_sha256': 'a' * 64,
                'content_type': 'text/html', 'limitations': ['external_resources_not_fetched']}
        if json.loads(route.request.post_data or '{}').get('representation') == 'static':
            # A hostile tree: the client must flatten anything outside its own allowlist and set no attributes.
            body['static_representation'] = {'representation': 'inert_structure_text_v1', 'source_status': 'recovered',
                'projection_truncated': False, 'omitted_elements': {'script': 1, 'img': 1}, 'attributes_discarded': 3,
                'limitations': [], 'nodes': [{'tag': 'h1', 'children': ['Profile received']},
                                             {'tag': 'script', 'children': ['window.__pwned=5']},
                                             {'tag': 'a', 'children': [{'tag': 'img', 'children': []}, 'link text']}]}
        route.fulfill(status=200, content_type='application/json', body=json.dumps(body))
    page.route('**/content', content)
    # Reveal, then navigate away before the answer: the late answer must never be shown.
    page.check('#insp-dynamic .source-section .ack input')
    page.click('#insp-dynamic .source-section .btn-secondary')
    page.locator('#insp-dynamic .switch-btn').nth(0).click()
    page.wait_for_timeout(1600)
    assert page.locator('.src-code').count() == 0
    # Reveal for real: inert text only.
    gate['hold'] = False
    page.locator('#insp-dynamic .switch-btn').nth(1).click()
    page.wait_for_selector('#insp-dynamic .source-section .ack input')
    page.check('#insp-dynamic .source-section .ack input')
    page.click('#insp-dynamic .source-section .btn-secondary')
    page.wait_for_selector('.src-code')
    assert '<script>window.__pwned=2</script>' in page.inner_text('.src-code')
    assert page.evaluate('window.__pwned') is None
    assert page.locator('#inspector script, #inspector img, #inspector iframe, #inspector link, #inspector a').count() == 0
    page.get_by_role('button', name='Page view', exact=True).click()
    page.wait_for_selector('.page-view h1')
    assert 'Profile received' in page.inner_text('.page-view') and 'link text' in page.inner_text('.page-view')
    assert page.locator('#inspector script, #inspector img, #inspector a, #inspector iframe').count() == 0
    assert page.evaluate('[...document.querySelectorAll(".page-view *")].every(e => e.attributes.length === 0)')
    assert page.evaluate('window.__pwned') is None
    page.get_by_role('button', name='Hide source').click()
    assert page.locator('.src-code, .page-view').count() == 0
    page.wait_for_timeout(300)
    assert problems == []



def test_opt_in_single_field_reveal_is_hidden_and_cleared_on_navigation(browser, server):
    page, problems = open_page(browser, server(retain_capture_for_inspection=True), 1440, 900)
    run_sample(page)
    page.click('.nav-link[data-tab=findings]')
    page.select_option('#filter-type', 'CREDENTIAL_OR_TOKEN')
    page.wait_for_selector('#findings-body tr .row-main')
    page.locator('#findings-body tr .row-main').first.click()
    page.wait_for_selector('#fi-support .msg-card')
    page.wait_for_selector('#fi-support .iv-reveal button')
    original_preview = page.inner_text('#inspect-sub')
    assert '*' in original_preview or original_preview == '[REDACTED]'
    assert page.locator('#fi-support .iv-reveal .iv-revealed-value').is_hidden()
    page.get_by_role('button', name='Show original value').click()
    page.wait_for_function('(masked) => {const n=document.querySelector("#fi-support .iv-reveal .iv-revealed-value"); return n && n.textContent && n.textContent !== masked;}', arg=original_preview)
    assert page.inner_text('#inspect-sub') != original_preview
    page.get_by_role('button', name='Hide value').click()
    assert page.inner_text('#inspect-sub') == original_preview
    assert page.locator('#fi-support .iv-reveal .iv-revealed-value').is_hidden()
    # A new selection must never inherit the raw value from the previous item.
    page.locator('#findings-body tr .row-main').nth(1).click()
    assert page.locator('#fi-support .iv-reveal .iv-revealed-value').is_hidden()
    assert problems == []
    page.close()


def test_journey_e_slow_and_failed_evidence_never_shows_stale_details(browser, server):
    url = server()
    page, problems = open_page(browser, url, 1440, 900)
    run_sample(page)
    page.click('.nav-link[data-tab=findings]')
    page.wait_for_selector('#fi-support .msg-card')
    rows = page.locator('#findings-body tr')
    slow_message = 'flow_0001_msg_0001'

    def slow(route):
        if slow_message in route.request.url:
            page.wait_for_timeout(1500)
        route.continue_()
    page.route('**/investigation?*', slow)
    rows.nth(0).click()              # slow: flow_0001
    rows.nth(2).click()              # fast: a different message
    expected = rows.nth(2).locator('.row-loc').inner_text()
    page.wait_for_timeout(2000)
    assert expected.split('.')[-1].replace('_',' ') in page.inner_text('#fi-where').lower(), 'a slow earlier response replaced the newer selection'
    assert 'flow_0001' not in page.inner_text('#fi-where')
    page.unroute('**/investigation?*')
    # An expired job: the panel says so and keeps no stale evidence.
    page.route('**/investigation?*', lambda r: r.fulfill(status=404, content_type='application/json', body='{"error":"Job unavailable or expired"}'))
    rows.nth(5).click()
    page.wait_for_selector('#fi-support .notice-error')
    assert 'no longer available' in page.inner_text('#fi-support')
    assert page.locator('#fi-support .msg-card').count() == 0
    page.unroute('**/investigation?*')
    # Server unreachable while loading conversations: an explanation, not an endless spinner.
    page.route('**/conversations?*', lambda r: r.abort())
    page.click('.nav-link[data-tab=flows]')
    page.wait_for_function('() => document.getElementById("conv-body").textContent.includes("could not reach")')
    assert [p for p in problems if not p.startswith('pageerror')] == []



def test_summary_scope_distinguishes_supported_reconstruction_and_unreadable_content(browser, server):
    page, problems = open_page(browser, server(), 1280, 800)
    run_sample(page)
    assert page.is_visible('#scope-summary')
    assert not page.locator('#scope-summary').evaluate('(el) => el.open'), 'Advanced scope must be collapsed by default'
    page.locator('#scope-summary > summary').click()
    examined = page.inner_text('#scope-examined')
    assert 'readable web messages' in examined
    assert 'TRACE looked at' in examined
    assert 'encrypted' in page.inner_text('#scope-uninspectable').lower()
    assert 'not part of this scan' in page.inner_text('#scope-uninspectable').lower()
    # Controlled report variations exercise truthful rendering. These values
    # aren't an assertion that the showcase capture itself has missing packets.
    page.evaluate('''() => {
      state.report.summary.stream_gaps=2;
      state.report.summary.analysis_incomplete=true;
      state.report.summary.ml_coverage_status='partial';
      state.report.summary.ml_fields_eligible=10;
      state.report.summary.ml_fields_evaluated=6;
      state.report.metadata.detection_method='rules_plus_bilstm';
      renderSummary();
    }''')
    assert '2 conversations were missing' in page.inner_text('#scope-partial')
    assert '6 of 10 eligible pieces of information' in page.inner_text('#scope-partial')
    assert page.inner_text('#verdict-icon') == 'Check details'
    page.evaluate('''() => {
      state.report.summary.potential_leaks=0;
      state.report.finding_type_counts={};
      state.report.findings=[];
      renderSummary();
    }''')
    assert page.inner_text('#answer-title') == 'No potential findings in inspected content'
    assert problems == []
    page.close()

def test_accessibility_basics(browser, server):
    page, problems = open_page(browser, server(), 1440, 900)
    run_sample(page)
    page.click('.nav-link[data-tab=findings]')
    page.wait_for_selector('#fi-support .msg-card')
    unnamed = page.evaluate('''[...document.querySelectorAll('button,a[href],input,select,[role=tab],[role=separator]')]
      .filter(e=>e.offsetParent!==null)
      .filter(e=>!(e.getAttribute('aria-label')||e.textContent.trim()||(e.labels&&e.labels.length)||e.getAttribute('aria-labelledby')||e.placeholder))
      .map(e=>e.outerHTML.slice(0,80))''')
    assert unnamed == []
    assert page.locator('nav[aria-label=Main]').count() == 1 and page.locator('main#main').count() == 1
    assert page.get_attribute('#inspector', 'role') == 'complementary'
    # Every control reachable by keyboard has a visible focus style.
    page.keyboard.press('Tab')
    outline = page.evaluate('getComputedStyle(document.activeElement).outlineStyle')
    assert outline != 'none'
    assert problems == []


def _luminance(hex_colour):
    hex_colour = hex_colour.lstrip('#')
    r, g, b = (int(hex_colour[i:i + 2], 16) / 255 for i in (0, 2, 4))
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in (r, g, b)]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _contrast(a, b):
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def test_design_tokens_meet_wcag_aa_in_light_and_dark():
    css = (STATIC / 'app.css').read_text(encoding='utf-8')
    light = dict(re.findall(r'--([a-z0-9-]+):(#[0-9a-f]{6})', css.split('@media (prefers-color-scheme:dark)')[0]))
    dark_block = css.split('@media (prefers-color-scheme:dark)')[1].split('}}')[0]
    dark = {**light, **dict(re.findall(r'--([a-z0-9-]+):(#[0-9a-f]{6})', dark_block))}
    for name, t in (('light', light), ('dark', dark)):
        for fg in ('text', 'text-2', 'text-3', 'accent-text'):
            for bg in ('bg', 'surface', 'surface-2', 'sidebar'):
                assert _contrast(t[fg], t[bg]) >= 4.5, f'{name}: {fg} on {bg}'
        assert _contrast(t['accent-ink'], t['accent']) >= 4.5, f'{name}: primary button'
        for state in ('warn', 'error', 'ok'):
            assert _contrast(t[f'{state}-text'], t[f'{state}-bg']) >= 4.5, f'{name}: {state}'
        assert _contrast(t['text-3'], t['select']) >= 4.5, f'{name}: secondary text on a selected row'


def _many_findings_pcap(path, conversations=200, emails=8):
    from test_vp_qa_support import build_pcap, conversation, ok_response, post_json
    convs = []
    for i in range(conversations):
        body = {f'contact_{j}': f'person{i}x{j}@example.test' for j in range(emails)}
        convs.append(conversation(i % 200, post_json(body, path=f'/api/c{i}'), ok_response(), t0=1_760_000_000.0 + i * 400))
    return build_pcap(path, convs)


def test_large_list_stays_responsive_and_paged(browser, server, tmp_path):
    capture = _many_findings_pcap(tmp_path / 'many.pcap')
    page, problems = open_page(browser, server(), 1280, 800)
    page.set_input_files('#file', str(capture))
    page.wait_for_selector('#statusbar:not(.hidden)')
    page.wait_for_selector('#statusbar.hidden', state='attached', timeout=120000)
    page.click('.nav-link[data-tab=findings]')
    page.wait_for_selector('#findings-body tr .row-main')
    total = int(re.search(r'of ([\d,]+)', page.inner_text('#findings-page')).group(1).replace(',', ''))
    assert total >= 1500
    assert page.locator('#findings-body tr').count() == 100, 'the list renders one bounded page, never the whole report'
    metrics = page.evaluate('''async () => {
      const rows=[...document.querySelectorAll('#findings-body tr')];
      const t0=performance.now(); rows[40].querySelector('.row-main').click(); const select=performance.now()-t0;
      const t1=performance.now();
      while(!document.querySelector('#fi-support .msg-card, #fi-support .notice-error')) await new Promise(r=>setTimeout(r,10));
      const evidence=performance.now()-t1;
      const t2=performance.now(); document.getElementById('findings-next').click();
      while(!document.getElementById('findings-page').textContent.startsWith('101')) await new Promise(r=>setTimeout(r,10));
      return {select, evidence, nextPage: performance.now()-t2};
    }''')
    print('measured', json.dumps({k: round(v, 1) for k, v in metrics.items()}), 'findings', total)
    assert metrics['select'] < 100 and metrics['evidence'] < 3000 and metrics['nextPage'] < 3000
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
    assert problems == []


def test_cancel_shows_reported_steps_and_never_claims_results(browser, server):
    url = server()
    page, problems = open_page(browser, url, 1280, 800)
    state = {'cancelled': False}

    def status(route):
        if route.request.method != 'GET' or route.request.url.rstrip('/').count('/') != 5:
            return route.continue_()
        body = ({'job_id': 'x', 'status': 'cancelled', 'elapsed_seconds': 3} if state['cancelled'] else
                {'job_id': 'x', 'status': 'running', 'elapsed_seconds': 2, 'progress': {'stage': 'reading', 'packets': 4096, 'endpoint_pairs': 3}})
        route.fulfill(status=200, content_type='application/json', body=json.dumps(body))
    page.route(re.compile(r'.*/api/jobs/[0-9a-f]{32}$'), status)
    page.route(re.compile(r'.*/api/jobs/[0-9a-f]{32}/cancel$'), lambda r: (state.update(cancelled=True), r.fulfill(status=200, content_type='application/json', body='{"status":"cancelled"}')))
    page.click('#sample')
    # The first step shows immediately; the reported stage replaces it at the first status poll.
    page.wait_for_function('() => (document.querySelector("#progress-steps li.current")||{}).textContent === "Reading packets"')
    assert page.locator('#progress-steps li.done').first.inner_text() == 'Preparing the capture'
    assert '4,096 packets' in page.inner_text('#status-stage')
    assert page.inner_text('#ctx-status') == 'Analysing'
    page.click('#cancel-job')
    page.wait_for_selector('#statusbar.hidden', state='attached')
    assert 'cancelled' in page.inner_text('#errorbar').lower()
    assert page.inner_text('#ctx-status') == 'Cancelled'
    assert page.is_disabled('#export'), 'a cancelled scan must not offer a report'
    assert problems == []


def test_reload_restores_the_view_and_capture(browser, server):
    page, problems = open_page(browser, server(), 1440, 900)
    run_sample(page)
    page.click('.nav-link[data-tab=findings]')
    page.wait_for_selector('#fi-support .msg-card')
    page.reload()
    page.wait_for_selector('#view-findings:not(.hidden)', timeout=30000)
    assert page.inner_text('#ctx-capture') == 'trace-vp-showcase.pcap'
    assert page.inner_text('#crumb') == 'Findings'
    assert problems == []


def test_rapid_drawer_toggling_settles_on_the_last_choice(browser, server):
    page, problems = open_page(browser, server(), 1440, 900)
    run_sample(page)
    page.set_viewport_size({'width': 1024, 'height': 768})
    page.click('.nav-link[data-tab=findings]')
    rows = page.locator('#findings-body tr')
    for i in range(6):
        rows.nth(i).locator('.row-main').click()
        page.keyboard.press('Escape')
    rows.nth(7).locator('.row-main').click()
    page.wait_for_selector('#fi-support .msg-card, #fi-support .notice-error')
    page.wait_for_timeout(600)
    assert page.get_attribute('#inspector', 'data-open') == 'true'
    assert page.inner_text('#inspect-sub') == rows.nth(7).locator('.row-sub').inner_text()
    assert rows.nth(7).locator('.row-loc').inner_text().split('.')[-1].replace('_',' ') in page.inner_text('#fi-where').lower()
    assert problems == []
