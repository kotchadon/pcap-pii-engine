"""Execute selection/race/redaction behavior in Node; not a browser substitute."""
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(shutil.which('node') is None, reason='Node unavailable')
def test_investigation_selection_races_and_inert_content():
    script = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const base=process.argv[1]+'/src/packet_pii/dashboard_static/';
const html=fs.readFileSync(base+'index.html','utf8'),source=fs.readFileSync(base+'investigation.js','utf8');
class Element {
 constructor(){this.children=[];this.listeners={};this.attrs={};this._text='';this.disabled=false;this.checked=false;}
 set textContent(x){this._text=String(x);this.children=[];} get textContent(){return this._text+this.children.map(x=>x.textContent).join(' ');}
 set innerHTML(x){throw Error('Captured HTML must never be inserted');}
 setAttribute(k,v){this.attrs[k]=v;} append(...xs){this.children.push(...xs);} appendChild(x){this.append(x);return x;}
 replaceChildren(){this.children=[];this._text='';} addEventListener(k,f){this.listeners[k]=f;}
 click(){return this.listeners.click?.();}
}
const nodes=Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],new Element()]));
const pending=[];const ctx={URLSearchParams,console,document:{getElementById:id=>{assert(nodes[id],id);return nodes[id]},createElement:()=>new Element()},
 fetch:async(url,options)=>new Promise(resolve=>pending.push({url,options,resolve}))};
vm.createContext(ctx);vm.runInContext(source+'\nthis.api=TraceInvestigation;',ctx);
function respond(at,data){pending[at].resolve({ok:true,json:async()=>data});}
function page(items=[]){return {items,total:items.length,offset:0,limit:25};}
function data(id){const message={http_message_id:id,message_type:'response',protocol:'http/1',flow_id:'flow_1',session:1,
 client:{ip:'192.0.2.10',port:50123},server:{ip:'198.51.100.20',port:80},start_line:'HTTP/1.1 200',stream_id:'stream_1'};
 return {message,transaction:{transaction_id:'tx1',messages:[message]},fields:page(),findings:page(),
 source_ranges:[],capture_identity:{capture_sha256:'a'.repeat(64)},verification:{status:'recorded_source_ranges',coverage_complete:true},content_available:true};}
const finding=id=>({pii_type:'EMAIL',value:'a***@example.invalid',http_message_id:id,evidence:{field_ids:[]}});
(async()=>{
 ctx.api.setReport({job_id:'jobA'},'test-token');
 const first=ctx.api.openFinding(finding('m1')),second=ctx.api.openFinding(finding('m2'));
 assert(pending[0].url.includes('/jobA/'));assert.equal(pending[0].options.headers['X-Dashboard-Token'],'test-token');
 respond(1,data('m2'));await second;respond(0,data('m1'));await first;
 assert(nodes['conversation-status'].textContent.startsWith('m2'),'late response overwrote selection');
 nodes['content-ack'].checked=true;nodes['content-ack'].listeners.change();
 const hidden=nodes['content-reveal'].click();nodes['content-hide'].click();
 respond(2,{text:'secret hidden by user',status:'recovered',limitations:[]});await hidden;
 assert.equal(nodes['conversation-content'].textContent,'','hide failed to invalidate pending reveal');
 nodes['content-ack'].checked=true;nodes['content-ack'].listeners.change();
 const reveal=nodes['content-reveal'].click();
 assert.equal(JSON.parse(pending[3].options.body).acknowledge_sensitive_content,true);
 const attack='<script>window.pwned=true</script><img src="https://example.invalid/leak">';
 respond(3,{text:attack,is_html:true,status:'recovered',capture_sha256:'a'.repeat(64),limitations:[]});await reveal;
 assert.equal(nodes['conversation-content'].textContent,attack);
 assert.equal(nodes['conversation-content'].children.length,0,'HTML became DOM elements');
 const stale=ctx.api.openFinding(finding('m3'));ctx.api.setReport({job_id:'jobB'},'new-token');
 respond(4,data('m3'));await stale;
 assert(!nodes['conversation-status'].textContent.includes('m3'));assert.equal(nodes['conversation-content'].textContent,'');
 assert.equal(nodes['selected-finding'].children.length,0,'previous capture finding survived reset');
 const current=ctx.api.openFinding(finding('m4'));const related=data('m4');
 related.fields=page([{field_id:'unrelated',field_index:9,source_category:'header',granularity:'exact_stream_range'}]);
 related.message.reconstruction_complete=false;related.message.limitations=['http2_stream_incomplete'];
 respond(5,related);await current;
 assert(pending[5].url.includes('/jobB/'));assert.equal(pending[5].options.headers['X-Dashboard-Token'],'new-token');
 assert.match(nodes['conversation-meta'].textContent,/Incomplete \/ partial HTTP message/);
 assert.match(nodes['conversation-meta'].textContent,/http2_stream_incomplete/);
 const unrelated=nodes['conversation-fields'].children[0].click();respond(6,data('m4'));await unrelated;
 assert(!nodes['selected-finding'].textContent.includes('EMAIL'),'unrelated field retained misleading finding');
 assert.match(nodes['selected-finding'].textContent,/Choose a finding/);
 console.log('selection order, job isolation, hide/reveal races and inert text verified');
})().catch(e=>{console.error(e);process.exitCode=1});
'''
    result = subprocess.run(['node', '-e', script, str(ROOT)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr


def test_independent_reference_parser_on_generated_capture(tmp_path):
    pytest.importorskip('dpkt'); pytest.importorskip('h11')
    import importlib.util
    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
    generator = load('mentor_generator_independent', ROOT/'examples/generate_mentor_demo.py')
    reference = load('mentor_reference', ROOT/'scripts/validation/verify_mentor_demo.py')
    capture = tmp_path/'mentor.pcap'
    oracle = generator.write_demo(capture)
    first = capture.read_bytes(); generator.write_demo(capture)
    assert capture.read_bytes() == first
    from packet_pii.engine import analyze_to_report
    report = tmp_path/'report.json'; analyze_to_report(capture, report)
    result = reference.verify(capture, report)
    assert result['capture_sha256'] == oracle['sha256']
    assert result['exact_email_support_frames'] == [5, 4]
