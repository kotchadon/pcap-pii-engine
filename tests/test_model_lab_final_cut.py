"""TRACE Model Laboratory integration regressions.

PR #19's original static and JS tests referenced DOM elements that PR #20's
real manifest-aware Model Laboratory deliberately replaced. Verify the actual
merged interface and its fail-closed behaviour instead of old element names.
"""
from pathlib import Path
import shutil
import subprocess

import pytest

ASSETS = Path(__file__).resolve().parents[1] / "src" / "packet_pii" / "dashboard_static"


def test_final_cut_html_has_coverage_and_separate_ground_truth():
    html = (ASSETS / "index.html").read_text(encoding="utf-8")
    js = (ASSETS / "app.js").read_text(encoding="utf-8")
    lab = (ASSETS / "lab.js").read_text(encoding="utf-8")
    css = (ASSETS / "app.css").read_text(encoding="utf-8")
    for field in (
        'id="coverage-panel"', 'id="coverage-headline"', 'id="coverage-fill"',
        'id="coverage-grid"', 'id="coverage-banner"', 'id="gt-results"',
        'id="gt-unavailable"', 'id="gt-body"', 'id="gt-file"',
        'id="gt-demo"', 'id="ml-profile"', 'id="limitations-panel"',
    ):
        assert field in html
    assert "function renderCoverage(summary,meta,ctx)" in lab
    assert "function renderEvaluation(result,jobId)" in lab
    assert "function clearEvaluation(note)" in lab
    assert "TraceLab.onResult(payload)" in js
    assert "TraceLab.onAttempt(status,message)" in js
    assert "function renderGroundTruth" not in js  # migrated to the verified evaluation flow
    assert ".coverage-panel" in css and ".gt-results" in css
    assert 'Published synthetic benchmark' in html
    assert 'File-specific accuracy unavailable: no verified ground-truth annotations provided.' in html


def test_browser_coverage_and_verified_groundtruth_contract():
    if shutil.which("node") is None:
        pytest.skip("Node.js not available for DOM behavior regression")
    js_test = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const root=process.argv[1],html=fs.readFileSync(root+'/index.html','utf8');
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(x=>x[1]);
class Element{
 constructor(){
  this.textContent='';this.value='';this.dataset={};this.style={width:''};
  this.children=[];this.disabled=false;this.checked=false;this.events={};
  const active=new Set(['hidden']);
  this.classList={
   add:x=>active.add(x),remove:x=>active.delete(x),contains:x=>active.has(x),
   toggle:(x,on)=>{if(on===true)active.add(x);else if(on===false)active.delete(x);else if(active.has(x))active.delete(x);else active.add(x)}
  };
 }
 addEventListener(k,fn){this.events[k]=fn}
 appendChild(el){this.children.push(el);return el}
 append(...items){this.children.push(...items)}
 replaceChildren(){this.children=[]}
 setAttribute(name,value){this[name]=value}
 click(){}
}
const nodes=Object.fromEntries(ids.map(id=>[id,new Element()]));
const ctx={console,URL,URLSearchParams,setTimeout,clearTimeout,
 state:{token:'session-test',scanMode:'hybrid'},
 document:{getElementById:id=>{assert(nodes[id],id);return nodes[id]},createElement:()=>new Element(),
  querySelectorAll:()=>[]},
 fetch:async()=>({ok:true,json:async()=>ctx.answer})};
vm.createContext(ctx);vm.runInContext(fs.readFileSync(root+'/lab.js','utf8'),ctx);
const call=(script)=>vm.runInContext(script,ctx);
const report={
 metadata:{ml_requested:true,ml_work_limits:{profile:'standard',max_fields:10000,max_characters:2000000}},
 summary:{ml_coverage_status:'partial',ml_invoked:true,fields_extracted:107484,ml_fields_eligible:88192,
  ml_fields_evaluated:10000,ml_fields_skipped:78192,ml_fields_excluded_by_policy:19292,
  ml_fields_empty:0,ml_batches:40,ml_processing_time_seconds:4.525,
  ml_fields_skipped_by_reason:{field_budget:78192}}
};
ctx.payload={report,evaluation_requested:false};
call('TraceLab.onResult(payload)');
assert(nodes['coverage-headline'].textContent.includes('10,000 of 88,192'));
assert(nodes['coverage-headline'].textContent.includes('11.3%'));
assert(nodes['coverage-banner'].textContent.includes('Results are incomplete'));
assert.strictEqual(nodes['coverage-panel'].dataset.state,'partial');
assert.strictEqual(nodes['coverage-fill'].style.width,'11.3%');
assert(nodes['gt-results'].classList.contains('hidden'));
assert(nodes['gt-unavailable'].textContent.includes('File-specific accuracy unavailable'));
call("TraceLab.onAttempt('failed','Synthetic failure')");
assert.strictEqual(nodes['coverage-panel'].dataset.state,'failed');
assert(nodes['gt-results'].classList.contains('hidden'));
assert.strictEqual(nodes['coverage-fill'].style.width,'0.0%');
ctx.rulesOnly={report:{summary:{ml_coverage_status:'not_requested',ml_fields_eligible:0,ml_fields_evaluated:0,ml_fields_skipped:0},metadata:{}},evaluation_requested:false};
call('TraceLab.onResult(rulesOnly)');
assert.strictEqual(nodes['coverage-panel'].dataset.state,'not_requested');
assert(!nodes['coverage-headline'].textContent.includes('100%'));
const micro={tp:8,fp:2,fn:1,precision:0.8,recall:8/9,f1:16/19};
ctx.answer={
 status:'complete',capture:{verified_against_manifest:true},
 manifest:{verified:true,kind:'controlled_synthetic_fixture',label_source:'constructed_by_generator',sha256:'a'.repeat(64)},
 alignment:{aligned:12,manifest_fields:12,unaligned:{},unannotated_fields_in_listed_messages:0},
 systems:{model_only:{micro,scored_fields:12,per_label:{PERSON_NAME:{tp:8,fp:2,fn:1,precision:0.8,recall:8/9,f1:16/19}},
   unscored_fields:{},error_breakdown:{false_positive:{},false_negative:{}},negative_fields:{with_false_positive:2,scored:3}}},
 model_version:'test-v2',generated_at:'2026-10-18T00:00:00Z'
};
ctx.verified={report,evaluation_requested:true,job_id:'job-fixture'};
call('TraceLab.onResult(verified)');
(async()=>{
 await new Promise(setImmediate);
 assert(!nodes['gt-results'].classList.contains('hidden'));
 assert(nodes['gt-unavailable'].classList.contains('hidden'));
 assert(nodes['gt-status'].textContent.includes('Verified manifest'));
 assert.strictEqual(nodes['gt-body'].children.length,1);
 const cells=nodes['gt-body'].children[0].children;
 assert(cells.some(c=>c.textContent==='0.800'));
 assert(cells.some(c=>c.textContent==='0.842'));
 call("TraceLab.onAttempt('cancelled','User cancelled')");
 assert(nodes['gt-results'].classList.contains('hidden'));
 assert.strictEqual(nodes['coverage-panel'].dataset.state,'cancelled');
 console.log('New Model Laboratory coverage and verified-evaluation DOM checks passed');
})().catch(e=>{console.error(e);process.exitCode=1});
'''
    result = subprocess.run(["node", "-e", js_test, str(ASSETS)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
