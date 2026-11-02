"""Exercise browser state transitions without third-party browser dependencies."""
from pathlib import Path
import shutil
import subprocess
import unittest


class UnifiedUITest(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the UI behavior test')
    def test_model_truth_async_pagination_and_export(self):
        assets = Path(__file__).resolve().parents[1] / 'src' / 'packet_pii' / 'dashboard_static'
        script = r'''
const fs=require('fs'), vm=require('vm'), assert=require('assert');
class Element {
 constructor(){this.textContent='';this.value='';this.children=[];this.events={};this.disabled=false;this.checked=false;this.dataset={};this.style={};this.classList={toggle(){},add(){},remove(){}};}
 addEventListener(name,fn){this.events[name]=fn} appendChild(x){this.children.push(x);return x} append(...xs){this.children.push(...xs)} replaceChildren(){this.children=[]} setAttribute(){} click(){this.clicked=true}
}
const elements={}, html=fs.readFileSync(process.argv[1]+'/index.html','utf8');
for(const id of html.matchAll(/id="([^"]+)"/g))elements[id[1]]=new Element();
elements['analysis-profile'].value='standard';
const radios=['rules','hybrid'].map(value=>Object.assign(new Element(),{value}));
const created=[], requests=[], storage=new Map();
const report={metadata:{detection_method:'rules_plus_bilstm',ml_model_version:'test-v2'},summary:{ml_invoked:true,ml_fields_evaluated:2,ml_findings:0,rules_findings:0,ml_predictions_by_label:{PERSON_NAME:0,USERNAME:0}},finding_type_counts:{EMAIL:180,USERNAME:70},findings:Array.from({length:100},()=>({pii_type:'EMAIL',value:'masked'})),flows:[],limitations:[],pagination:{findings_total:250,flows_total:0,page_size:100}};
const context={console,URL,URLSearchParams,Blob,performance,crypto:{randomUUID:()=> 'stable-attempt-uuid'},setInterval:()=>1,clearInterval(){},setTimeout:()=>1,clearTimeout(){},localStorage:{setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k),getItem:k=>storage.get(k)},document:{getElementById:id=>{assert(elements[id],id);return elements[id]},createElement:()=>{const e=new Element();created.push(e);return e},querySelectorAll:sel=>sel.includes('scan-mode')?radios:[],querySelector:sel=>radios.find(e=>sel.includes('value="'+e.value+'"'))},fetch:async(url,opts={})=>{requests.push({url,opts});let data;if(url==='/api/session')data={token:'token',max_upload_bytes:536870912,model_available:true,model_version:'test-v2',jobs_supported:true,profiles:{standard:{max_capture_bytes:134217728},large:{max_capture_bytes:536870912}}};else if(url==='/api/benchmark')data={available:true,model_version:'source-v1',dataset:{name:'Synthetic research',fields:42},precision:.8,recall:.7,f1:.75};else if(url==='/api/jobs/showcase')data={job_id:'job-1',status:'queued'};else if(url==='/api/jobs/job-1')data={job_id:'job-1',status:'completed',filename:'demo.pcap',report};else if(url.includes('/findings?'))data={items:[{pii_type:'USERNAME',value:'masked'}],total:1,offset:0,limit:100};else throw Error('Unexpected '+url);return {ok:true,status:200,json:async()=>data}}};
vm.createContext(context);vm.runInContext(fs.readFileSync(process.argv[1]+'/app.js','utf8'),context);
(async()=>{
 await new Promise(setImmediate);
 assert.strictEqual(vm.runInContext('state.scanMode',context),'rules');
 assert.strictEqual(radios[1].checked,false);
 assert.strictEqual(elements['live-model-loaded'].textContent,'LOADED');
 assert.strictEqual(elements['max-file'].textContent,'128 MiB');
 assert(elements['benchmark-note'].textContent.includes('do not describe that checkpoint'),JSON.stringify({note:elements['benchmark-note'].textContent,error:elements.errorbar.textContent,requests}));
 await vm.runInContext("post('/api/showcase',null)",context);
 assert.strictEqual(elements['live-model-state'].textContent,'YES');
 assert.strictEqual(elements['live-ml-findings'].textContent,'0');
 assert.strictEqual(elements['findings-page'].textContent,'1–100 of 250');
 assert.strictEqual(elements['findings-next'].disabled,false);
 assert.strictEqual(elements['breakdown-scope'].textContent,'All findings in this recording');
 assert.strictEqual(elements.breakdown.children[0].children[2].textContent,180);
 assert.strictEqual(requests.filter(r=>r.opts.method==='POST').length,1);
 const sent=requests.find(r=>r.url==='/api/jobs/showcase');
 assert.strictEqual(sent.opts.headers['X-Detection-Mode'],'rules');
 assert.strictEqual(sent.opts.headers['X-Request-ID'],'stable-attempt-uuid');
 assert.strictEqual(storage.get('trace-last-job'),'job-1');
 elements.search.value='test';elements['filter-type'].value='USERNAME';
 await vm.runInContext('filterFindings()',context);
 assert(requests.some(r=>r.url.includes('q=test&type=USERNAME')));
 assert.strictEqual(elements['findings-page'].textContent,'1–1 of 1');
 elements.export.events.click();
 assert(created.some(e=>e.href==='/api/jobs/job-1/report'&&e.clicked));
 vm.runInContext('setLiveEvidence({summary:{ml_invoked:false,ml_findings:0,ml_fields_evaluated:0,rules_findings:3}})',context);
 assert.strictEqual(elements['live-model-state'].textContent,'NO');
 assert.strictEqual(elements['live-model-loaded'].textContent,'LOADED');

 // Terminal failure must not present earlier successful telemetry as this scan.
 context.fetch=async()=>({ok:true,json:async()=>({job_id:'failed-job',status:'failed',error:'Memory limit exceeded',elapsed_seconds:73})});
 vm.runInContext("state.jobId='failed-job'",context);
 await vm.runInContext('pollJob()',context);
 assert.strictEqual(elements['live-model-state'].textContent,'UNKNOWN');
 assert.strictEqual(elements['live-ml-findings'].textContent,'—');
 assert.strictEqual(elements['live-fields-evaluated'].textContent,'—');
 assert(elements['live-inference-status'].textContent.includes('incomplete'));
 assert(elements['previous-results'].textContent.includes('previous completed capture: demo.pcap'));
 assert.strictEqual(elements['status-elapsed'].textContent,'01:13');
 // A stale local ID is recoverable from the server, without posting the upload again.
 const recovery=[];
 context.fetch=async(url,opts={})=>{recovery.push({url,opts});if(url==='/api/jobs/stale')return {ok:false,status:404,json:async()=>({error:'expired'})};if(url==='/api/session')return {ok:true,json:async()=>({token:'token',active_job_id:'active-job'})};return {ok:true,json:async()=>({job_id:'active-job',status:'running',elapsed_seconds:84,progress:{stage:'analysing',packets:8192,endpoint_pairs:32,fields_extracted:152}})}};
 vm.runInContext("state.jobId='stale'",context);
 await vm.runInContext('pollJob()',context);
 assert.strictEqual(vm.runInContext('state.jobId',context),'active-job');
 assert.strictEqual(elements['status-elapsed'].textContent,'01:24');
 assert(elements['status-stage'].textContent.includes('8,192 packets'));
 assert(elements['status-stage'].textContent.includes('152 fields extracted'));
 assert(recovery.every(r=>r.opts.method!=='POST'));
 // A lost POST response recovers its accepted job using a session GET, never a second POST.
 let posts=0;
 context.fetch=async(url,opts={})=>{if(opts.method==='POST'){posts++;throw Error('Connection lost after upload')}if(url==='/api/session')return {ok:true,json:async()=>({token:'token',active_job_id:'accepted-job'})};return {ok:true,json:async()=>({job_id:'accepted-job',status:'cancelled',elapsed_seconds:2})}};
 vm.runInContext('state.busy=false',context);
 await vm.runInContext("post('/api/showcase',null)",context);
 assert.strictEqual(posts,1);
 assert.strictEqual(vm.runInContext('state.jobId',context),'accepted-job');
 assert.strictEqual(elements['live-ml-findings'].textContent,'—');
 assert(elements['live-inference-status'].textContent.includes('cancelled'));
 // Refresh prefers the latest server job over stale browser storage.
 const refreshed={...context,localStorage:{getItem:()=> 'stale-browser-job',setItem(){},removeItem(){}},fetch:async(url)=>({ok:true,json:async()=>url==='/api/session'?{token:'token',max_upload_bytes:134217728,jobs_supported:true,active_job_id:'latest-server-job'}:url==='/api/benchmark'?{available:false}:{job_id:'latest-server-job',status:'cancelled',elapsed_seconds:1}})};
 vm.createContext(refreshed);vm.runInContext(fs.readFileSync(process.argv[1]+'/app.js','utf8'),refreshed);
 await new Promise(setImmediate);
 assert.strictEqual(vm.runInContext('state.jobId',refreshed),'latest-server-job');
 console.log('UI behavior checks passed');
})().catch(e=>{console.error(e);process.exitCode=1});
'''
        result = subprocess.run(['node', '-e', script, str(assets)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
