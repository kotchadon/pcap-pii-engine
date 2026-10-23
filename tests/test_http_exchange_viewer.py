"""HTTP exchange viewer: pairing from engine evidence, inert body display and no fabricated content."""
from pathlib import Path
import json
import re
import shutil
import subprocess
import threading

import pytest

STATIC = Path(__file__).resolve().parents[1] / 'src' / 'packet_pii' / 'dashboard_static'
JS = (STATIC / 'inspector.js').read_text(encoding='utf-8')
HTML = (STATIC / 'index.html').read_text(encoding='utf-8')


def test_viewer_never_parses_links_frames_or_executes_captured_content():
    for banned in ('innerHTML', 'outerHTML', 'insertAdjacentHTML', 'eval(', 'new Function', 'srcdoc', 'iframe',
                   'DOMParser', 'createContextualFragment', 'document.write', '.href', '.src=', 'window.open'):
        assert banned not in JS, banned
    assert "c.redacted===true" in JS                       # body text is shown only when the server says it is redacted
    assert 'Nothing has been reconstructed or guessed' in JS
    assert '/inspector.js' in HTML and HTML.index('/inspector.js') < HTML.index('/app.js')
    used = set(re.findall(r"q\('([a-z0-9-]+)'\)", JS))
    ids = set(re.findall(r'id="([^"]+)"', HTML))
    assert used - ids == set()


def test_dashboard_serves_inspector_script():
    from packet_pii.dashboard import _ALLOWED
    assert _ALLOWED['/inspector.js'][0] == 'inspector.js'


NODE = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
class El{constructor(t){this.tag=t;this.children=[];this.textContent='';this.className='';this.attrs={};this.dataset={};this.classList={toggle(){},add(){},remove(){},contains(){return false}}}
 append(...x){this.children.push(...x)} appendChild(x){this.children.push(x);return x} replaceChildren(...x){this.children=x}
 setAttribute(k,v){this.attrs[k]=String(v)} addEventListener(){}}
const text=n=>n.textContent+n.children.map(text).join('');
const tags=n=>[n.tag,...n.children.flatMap(tags)];
const nodes={};for(const id of ['fx-request','fx-response','fx-packets','msg-body','msg-total','msg-page','msg-prev','msg-next','msg-scope','msg-clear-flow','mi-title','mi-sub','mx-request','mx-response','mx-packets'])nodes[id]=new El('div');
const rows={
 http_evidence:[
  {http_message_id:'f1_msg_0001',flow_id:'f1',stream_id:'f1_direction_0',http_request_id:'f1_req_0000',protocol:'http/1',pairing_status:'paired_best_effort',start_line:'GET [path-redacted] HTTP/1.1',stream_start:0,stream_end:80,header_end:80,body_start:80,field_count:1},
  {http_message_id:'f1_msg_0002',flow_id:'f1',stream_id:'f1_direction_1',http_request_id:'f1_req_0000',protocol:'http/1',pairing_status:'paired_best_effort',start_line:'HTTP/1.1 200',stream_start:0,stream_end:300,header_end:60,body_start:60,field_count:1,
   content:{redacted:true,media_type:'text/html',text:'<p>Hi j***@example.test</p>\n<script>alert(1)</script><img src="http://example.invalid/x.png">'}},
  {http_message_id:'f1_msg_0003',flow_id:'f1',stream_id:'f1_direction_1',http_request_id:null,protocol:'http/1',pairing_status:'unpaired',start_line:'HTTP/1.1 200',stream_start:300,stream_end:400,header_end:350,body_start:350,field_count:0,
   content:{redacted:false,text:'<b>unmasked secret</b>'}}],
 field_evidence:[{field_id:'f1_msg_0001_field_0',field_index:0,location:'header',source_category:'header',granularity:'exact_stream_range',transformations:[],stream_ranges:[{start:20,end:30}]},
  {field_id:'f1_msg_0002_field_0',field_index:0,location:'body',source_category:'body',granularity:'transformed_source_range',transformations:['gzip'],stream_ranges:[{start:60,end:300}]}]};
const calls=[];
const state={reportJobId:'job',token:'t',report:{capture_evidence:{identity_status:'unverified'}},pageFindings:[]};
const ctx={console,URLSearchParams,Error,Promise,Set,Array,String,Number,Math,Object,JSON,state,
 document:{getElementById:id=>nodes[id],createElement:t=>new El(t),querySelector:()=>null,querySelectorAll:()=>[],readyState:'loading',addEventListener(){}},
 fetch:async(url,opts)=>{calls.push(url);assert.equal(opts.headers['X-Dashboard-Token'],'t');const u=new URL(url,'http://x');const kind=u.pathname.split('/').pop();
  const id=u.searchParams.get('evidence_id'),sid=u.searchParams.get('stream_id');
  const items=(rows[kind]||[]).filter(r=>(!id||(r.http_message_id||r.field_id)===id)&&(!sid||r.stream_id===sid));
  return {ok:true,json:async()=>({items,total:items.length})}}};
vm.createContext(ctx);vm.runInContext(fs.readFileSync(process.argv[1]+'/inspector.js','utf8')+';this.TI=TraceInspector;',ctx);
(async()=>{
 const TI=ctx.TI;
 const data=await TI.loadExchange('f1_msg_0001');
 assert.equal(data.request.http_message_id,'f1_msg_0001');
 assert.equal(data.response.http_message_id,'f1_msg_0002');           // paired by the engine's own request id
 assert(!calls.some(u=>u.includes('stream_evidence')),'packet references withheld for an unverified capture');
 vm.runInContext("TraceInspector._state.view='traffic'",ctx);
 await TI.openMessage('f1_msg_0002',true);
 const resp=nodes['mx-response'];
 assert(text(resp).includes('<script>alert(1)</script>'),'markup is shown as text');
 assert(!tags(resp).some(t=>['script','img','iframe','a','link'].includes(t)),'no live elements from captured markup');
 assert(text(resp).includes('Scripts in the captured page do not run'));
 assert(text(nodes['mx-packets']).includes('not verified'));
 await TI.openMessage('f1_msg_0003',true);
 assert(!text(nodes['mx-response']).includes('unmasked secret'),'content not declared redacted is never displayed');
 assert(text(nodes['mx-response']).includes('HTML source is not available'));
 assert(text(nodes['mx-request']).includes('No matching request was observed'));
 const toks=TI.tokenize('<a href="x">[REDACTED]</a><!-- c -->');
 assert.deepEqual(toks.map(t=>t.cls),['tok-tag','tok-mask','tok-tag','tok-comment']);
 console.log('ok');
})().catch(e=>{console.error(e);process.exitCode=1});
'''


@pytest.mark.skipif(shutil.which('node') is None, reason='Node.js unavailable')
def test_exchange_pairing_inert_source_and_redaction_gate():
    result = subprocess.run(['node', '-e', NODE, str(STATIC)], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr


CHROME = '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'
HOSTILE = '<html><head><link rel="stylesheet" href="http://example.invalid/s.css"></head><body onload="window.__pwned=1">' \
          '<script>window.__pwned=2</script><img src="http://example.invalid/p.png" onerror="window.__pwned=3">' \
          '<a href="javascript:window.__pwned=4">x</a></body></html>'


def test_browser_hostile_html_stays_inert_and_loads_nothing():
    sync_api = pytest.importorskip('playwright.sync_api')
    exe = next((p for p in (CHROME, shutil.which('chromium'), shutil.which('google-chrome')) if p and Path(p).exists()), None)
    if exe is None:
        pytest.skip('no Chromium available')
    from packet_pii.dashboard import DashboardServer
    server = DashboardServer(('127.0.0.1', 0))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{server.server_port}/'
    try:
        with sync_api.sync_playwright() as pw:
            browser = pw.chromium.launch(executable_path=exe, args=['--no-sandbox'])
            page = browser.new_page(viewport={'width': 1300, 'height': 1000})
            outside, errors = [], []
            page.on('request', lambda r: outside.append(r.url) if not r.url.startswith(base) else None)
            page.on('pageerror', lambda e: errors.append(str(e)))

            def inject(route):
                response = route.fetch()
                data = response.json()
                for item in data.get('items', []):
                    if str(item.get('start_line', '')).startswith('HTTP/'):
                        item['content'] = {'redacted': True, 'media_type': 'text/html', 'text': HOSTILE}
                route.fulfill(response=response, body=json.dumps(data), headers={**response.headers, 'content-type': 'application/json'})
            page.route('**/http_evidence?*', inject)
            page.goto(base)
            page.wait_for_selector('#sample')
            page.click('#sample')
            page.wait_for_selector('#statusbar:not(.hidden)')
            page.wait_for_selector('#statusbar.hidden', state='attached', timeout=60000)
            page.click('[data-tab=findings]')
            page.click('#fi-tab-response')
            page.wait_for_selector('#fx-response .src-code', timeout=15000)
            assert '<script>window.__pwned=2</script>' in page.inner_text('#fx-response .src-code')
            assert page.evaluate('window.__pwned') is None
            assert page.locator('#fx-response script, #fx-response img, #fx-response link, #fx-response a, #fx-response iframe').count() == 0
            page.wait_for_timeout(300)
            assert outside == [] and errors == []
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
