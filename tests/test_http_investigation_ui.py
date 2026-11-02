"""Execute selection/race/redaction behavior in Node; not a browser substitute."""
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(shutil.which('node') is None, reason='Node unavailable')
def test_inspector_selection_races_job_isolation_and_inert_source():
    """Ported from investigation.js to the universal inspector (inspector.js); same guarantees, plus error states."""
    script = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const base=process.argv[1]+'/src/packet_pii/dashboard_static/';
const html=fs.readFileSync(base+'index.html','utf8'),source=fs.readFileSync(base+'inspector.js','utf8');
assert(!/innerHTML|outerHTML|insertAdjacentHTML|srcdoc|iframe|DOMParser|document\.write|eval\(/.test(source),'unsafe DOM API in inspector.js');
class CL{constructor(){this.s=new Set()}toggle(c,on){on=on===undefined?!this.s.has(c):on;on?this.s.add(c):this.s.delete(c);return on}add(c){this.s.add(c)}remove(c){this.s.delete(c)}contains(c){return this.s.has(c)}}
class Element{
 constructor(tag){this.tag=tag||'div';this.children=[];this.listeners={};this.attrs={};this._text='';this.disabled=false;this.checked=false;this.hidden=false;this.dataset={};this.classList=new CL();this.style={setProperty(){}};this.className='';}
 set textContent(x){this._text=String(x);this.children=[];} get textContent(){return this._text+this.children.map(x=>x.textContent).join(' ');}
 set innerHTML(x){throw Error('Captured HTML must never be inserted');}
 setAttribute(k,v){this.attrs[k]=String(v)} getAttribute(k){return this.attrs[k]} removeAttribute(k){delete this.attrs[k]}
 append(...xs){this.children.push(...xs.filter(Boolean))} appendChild(x){this.append(x);return x} replaceChildren(...xs){this.children=xs.filter(Boolean);this._text=''}
 addEventListener(k,f){(this.listeners[k]=this.listeners[k]||[]).push(f)} fire(k,ev={}){for(const f of this.listeners[k]||[])f({preventDefault(){},stopPropagation(){},...ev,target:this})}
 click(){this.fire('click')} focus(){} contains(){return false} closest(){return null} setPointerCapture(){} get isConnected(){return true}
 find(pred){if(pred(this))return this;for(const c of this.children){const r=c.find&&c.find(pred);if(r)return r}return null}
 all(pred,out=[]){if(pred(this))out.push(this);for(const c of this.children)c.all&&c.all(pred,out);return out}
}
const nodes=Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],new Element()]));
const pending=[];
const state={reportJobId:'jobA',token:'test-token',report:{}};
const ctx={URLSearchParams,console,Error,Promise,Set,Array,String,Number,Math,Object,JSON,Date,setTimeout,clearTimeout,state,window:{innerWidth:1440},
 document:{readyState:'complete',body:new Element(),activeElement:null,getElementById:id=>{assert(nodes[id],id);return nodes[id]},createElement:t=>new Element(t),querySelector:()=>null,addEventListener(){}},
 matchMedia:q=>({matches:q.includes('min-width'),addEventListener(){}}),localStorage:{getItem:()=>null,setItem(){}},
 fetch:(url,options)=>new Promise(resolve=>pending.push({url,options,resolve}))};
vm.createContext(ctx);vm.runInContext(source+'\nthis.api=TraceInspector;',ctx);
const api=ctx.api,dyn=nodes['insp-dynamic'];
const tick=()=>new Promise(r=>setImmediate(r));
function respond(at,data,status=200){pending[at].resolve({ok:status<400,status,json:async()=>data});}
function page(items=[]){return {items,total:items.length,offset:0,limit:25};}
function data(id,extra={}){const message={http_message_id:id,message_type:'response',protocol:'http/1',flow_id:'flow_1',session:1,
 client:{ip:'192.0.2.10',port:50123},server:{ip:'198.51.100.20',port:80},start_line:'HTTP/1.1 200',stream_id:'stream_1',stream_start:0,stream_end:10,...extra};
 return {message,transaction:{transaction_id:'tx1',messages:[message]},fields:page(),findings:page(),stream:{},
 source_ranges:[],capture_identity:{capture_sha256:'a'.repeat(64)},verification:{status:'recorded_source_ranges',coverage_complete:true},content_available:true,limitations:[]};}
(async()=>{
 api.onView('flows');
 // 1. A later selection wins even when the earlier response arrives last.
 api.openMessage('m1',{open:true});api.openMessage('m2',{open:true});
 const n=pending.length;assert(pending[n-2].url.includes('/jobA/investigation'));assert.equal(pending[n-2].options.headers['X-Dashboard-Token'],'test-token');
 respond(n-1,data('m2'));await tick();respond(n-2,data('m1',{start_line:'HTTP/1.1 500'}));await tick();
 assert.equal(nodes['insp-title'].textContent,'Reply · 200 OK','late response overwrote the newer selection');
 assert(dyn.textContent.includes('m2')&&!dyn.textContent.includes('m1'));
 // 2. Reveal, then hide before the server answers: nothing may appear.
 let ack=dyn.find(e=>e.tag==='input'),reveal=dyn.find(e=>e.tag==='button'&&e._text==='Show response source');
 ack.checked=true;ack.fire('change');assert.equal(reveal.disabled,false);
 reveal.click();const hidePending=pending.length-1;assert.equal(JSON.parse(pending[hidePending].options.body).acknowledge_sensitive_content,true);
 api.openMessage('m2',{open:true});const reload=pending.length-1;   // navigating away hides source
 respond(hidePending,{text:'secret hidden by user',is_html:false,status:'recovered',limitations:[]});await tick();
 respond(reload,data('m2'));await tick();
 assert(!dyn.textContent.includes('secret hidden by user'),'stale reveal displayed after navigation');
 // 3. Captured HTML stays inert text.
 ack=dyn.find(e=>e.tag==='input');reveal=dyn.find(e=>e.tag==='button'&&e._text==='Show response source');
 ack.checked=true;ack.fire('change');reveal.click();
 const attack='<script>window.pwned=true</script><img src="https://example.invalid/leak">';
 respond(pending.length-1,{text:attack,is_html:true,status:'recovered',capture_sha256:'a'.repeat(64),limitations:['external_resources_not_fetched']});await tick();
 assert(['<script>','window.pwned=true','</script>','https://example.invalid/leak'].every(t=>dyn.textContent.includes(t)),'source not shown as text');
 assert.equal(dyn.all(e=>['script','img','iframe','a','link','object'].includes(e.tag)).length,0,'captured markup became elements');
 assert(dyn.textContent.includes('were not fetched'));
 // 4. A new capture (job) invalidates everything in flight.
 api.openMessage('m3',{open:true});const stale=pending.length-1;
 state.reportJobId='jobB';state.token='new-token';api.onResult({job_id:'jobB'});
 respond(stale,data('m3'));await tick();
 assert(!dyn.textContent.includes('m3'),'previous capture evidence survived the reset');
 assert(!dyn.textContent.includes('<script>'),'revealed source survived the reset');
 // 5. Incomplete reconstruction is disclosed, and requests use the new job and token.
 api.openMessage('m4',{open:true});const cur=pending.length-1;
 assert(pending[cur].url.includes('/jobB/'));assert.equal(pending[cur].options.headers['X-Dashboard-Token'],'new-token');
 respond(cur,data('m4',{reconstruction_complete:false,limitations:['http2_stream_incomplete']}));await tick();
 assert.match(dyn.textContent,/Part of this message was missing/);assert.match(dyn.textContent,/http2 stream incomplete/);
 // 6. Errors replace the previous evidence instead of leaving it on screen.
 api.openMessage('m5',{open:true});respond(pending.length-1,{error:'Job unavailable or expired'},404);await tick();await tick();
 assert.match(dyn.textContent,/no longer available/);assert(!dyn.textContent.includes('m4'),'stale evidence left visible after an error');
 // 7. Retention disabled: the server's opt-in is explained, nothing is requested.
 api.openMessage('m6',{open:true});const d6=data('m6');d6.content_available=false;respond(pending.length-1,d6);await tick();
 assert.match(dyn.textContent,/--retain-capture-for-inspection/);assert(!dyn.find(e=>e.tag==='input'));
 console.log('selection order, job isolation, hide/reveal races, errors and inert text verified');
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
