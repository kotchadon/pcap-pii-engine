"""TRACE Model Laboratory: honest coverage and fail-closed verified metrics.

The JavaScript behavior check runs under Node when available; static asset
assertions run everywhere, including minimal Python-only GitHub CI.
"""
from pathlib import Path
import shutil
import subprocess

ASSETS = Path(__file__).resolve().parents[1] / "src" / "packet_pii" / "dashboard_static"


def test_final_cut_html_has_coverage_and_separate_ground_truth():
    html = (ASSETS / "index.html").read_text()
    js = (ASSETS / "app.js").read_text()
    css = (ASSETS / "app.css").read_text()
    for item in (
        'id="coverage-progress"', 'id="coverage-percent"',
        'id="coverage-evaluated"', 'id="coverage-skipped"',
        'id="groundtruth-precision"', 'id="groundtruth-recall"',
        'id="groundtruth-f1"', 'id="groundtruth-status"',
        'id="overview-open-lab"', 'id="limitations-title"',
    ):
        assert item in html
    assert "function renderCoverage(report)" in js
    assert "function renderGroundTruth(e,report)" in js
    assert "evaluation.status" not in html
    assert "coverage-bar" in css
    assert ".groundtruth-metrics.hidden" in css
    assert 'View published synthetic benchmark — not this file’s accuracy' in html


def test_browser_coverage_and_verified_groundtruth_contract():
    if shutil.which("node") is None:
        import pytest
        pytest.skip("Node.js not available for DOM behavior regression")
    js_test = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
class Element {
 constructor(){this.textContent='';this.value='';this.children=[];this.events={};this.style={};this.attributes={};this.disabled=false;this.checked=false;this.dataset={};
  const classes=new Set();this.classList={add:x=>classes.add(x),remove:x=>classes.delete(x),toggle:(x,on)=>{if(on===true)classes.add(x);else if(on===false)classes.delete(x);else if(classes.has(x))classes.delete(x);else classes.add(x)},contains:x=>classes.has(x)};
 }
 setAttribute(k,v){this.attributes[k]=v}addEventListener(k,f){this.events[k]=f}appendChild(e){this.children.push(e);return e}append(...xs){this.children.push(...xs)}
 replaceChildren(){this.children=[]}click(){this.clicked=true}
}
const assets=process.argv[1],html=fs.readFileSync(assets+'/index.html','utf8'),elements={};
for(const match of html.matchAll(/id="([^"]+)"/g))elements[match[1]]=new Element();
elements['analysis-profile'].value='standard';
const radios=['rules','hybrid'].map(value=>Object.assign(new Element(),{value}));
const ctx={console,performance,URL,URLSearchParams,Blob,
 crypto:{randomUUID:()=> 'test-uuid'},setInterval:()=>1,clearInterval(){},setTimeout:()=>1,clearTimeout(){},
 localStorage:{getItem(){return null},setItem(){},removeItem(){}},
 document:{getElementById:id=>{assert(elements[id],id);return elements[id]},createElement:()=>new Element(),querySelectorAll:sel=>sel.includes('scan-mode')?radios:[],querySelector:sel=>radios.find(r=>sel.includes('value="'+r.value+'"'))},
 fetch:async url=>({ok:true,json:async()=>url==='/api/session'?{token:'secret',model_available:true,model_version:'test-v2',max_upload_bytes:134217728,profiles:{standard:{max_capture_bytes:134217728}}}:{available:false}})
};
vm.createContext(ctx);vm.runInContext(fs.readFileSync(assets+'/app.js','utf8'),ctx);
(async()=>{
 await new Promise(setImmediate);
 ctx.current={metadata:{ml_requested:true,ml_model_version:'test-v2',detection_method:'rules_plus_bilstm',ml_work_limits:{max_fields:10000}},
   summary:{ml_invoked:true,ml_fields_eligible:88192,ml_fields_evaluated:10000,ml_fields_skipped:78192,ml_fields_excluded_by_policy:19292,ml_incomplete:true,ml_findings:939,rules_findings:11182,ml_predictions_by_label:{PERSON_NAME:626,USERNAME:313}},findings:[],flows:[]};
 vm.runInContext('setLiveEvidence(current)',ctx);
 assert.strictEqual(elements['coverage-percent'].textContent,'11.3%');
 assert(elements['coverage-description'].textContent.includes('78,192 skipped'));
 assert(elements['coverage-description'].textContent.includes('10,000-field'));
 assert.strictEqual(elements['coverage-progress'].attributes['aria-valuenow'],'11');
 assert.strictEqual(elements['coverage-chip'].textContent,'INCOMPLETE');
 assert.strictEqual(elements['coverage-excluded'].textContent,'19,292');
 assert.strictEqual(elements['coverage-evaluated'].textContent,'10,000');
 assert.strictEqual(elements['coverage-eligible'].textContent,'88,192');
 assert.strictEqual(elements['live-ml-findings'].textContent,'939');
 // No fabricated metric: even numerically plausible reported "accuracy" is ignored.
 ctx.untrusted={status:'verified',counts:{tp:100,fp:0,fn:0},precision:1,recall:1,f1:1};
 vm.runInContext('renderGroundTruth(untrusted,current)',ctx);
 assert.strictEqual(elements['groundtruth-precision'].textContent,'—');
 assert(elements['groundtruth-metrics'].classList.contains('hidden'));
 const shaA='a'.repeat(64),shaB='b'.repeat(64);
 ctx.current.metadata.capture_sha256=shaA;
 ctx.verifiedFixture={status:'verified',manifest_verified:true,schema_version:'ground-truth-v1',capture_sha256:shaA,
  manifest_sha256:shaB,model_version:'test-v2',negative_fields_reviewed:true,scope:'evaluated_subset',fields_in_scope:10000,counts:{tp:8,fp:4,fn:1}};
 vm.runInContext('renderGroundTruth(verifiedFixture,current)',ctx);
 assert.strictEqual(elements['groundtruth-precision'].textContent,'66.7%');
 assert.strictEqual(elements['groundtruth-recall'].textContent,'88.9%');
 assert.strictEqual(elements['groundtruth-f1'].textContent,'76.2%');
 assert.strictEqual(elements['groundtruth-status'].textContent,'VERIFIED SUBSET');
 assert(elements['groundtruth-explanation'].textContent.includes('NOT full-file accuracy'));
 assert(!elements['groundtruth-metrics'].classList.contains('hidden'));
 // A malicious "complete" label on a partial scan fails closed.
 ctx.verifiedFixture.scope='all_eligible_fields';ctx.verifiedFixture.coverage_complete=true;
 vm.runInContext('renderGroundTruth(verifiedFixture,current)',ctx);
 assert.strictEqual(elements['groundtruth-precision'].textContent,'—');
 assert(elements['groundtruth-metrics'].classList.contains('hidden'));
 // Complete processing, validated manifest can legitimately show complete-scope metrics.
 ctx.current.summary.ml_incomplete=false;ctx.current.summary.ml_fields_skipped=0;ctx.current.summary.ml_fields_evaluated=88192;
 vm.runInContext('renderGroundTruth(verifiedFixture,current)',ctx);
 assert.strictEqual(elements['groundtruth-status'].textContent,'VERIFIED COMPLETE');
 // Wrong model must fail closed.
 ctx.verifiedFixture.model_version='other-checkpoint';
 vm.runInContext('renderGroundTruth(verifiedFixture,current)',ctx);
 assert.strictEqual(elements['groundtruth-precision'].textContent,'—');
 // Pending/failure cannot inherit previous evaluated values.
 vm.runInContext("markLatestScan('failed','A later attempt failed')",ctx);
 assert.strictEqual(elements['groundtruth-precision'].textContent,'—');
 assert.strictEqual(elements['coverage-percent'].textContent,'—');
 // Rules-only is never shown as "100% AI coverage".
 ctx.ruleScan={metadata:{ml_requested:false},summary:{ml_invoked:false,ml_fields_eligible:0,ml_fields_evaluated:0,ml_fields_skipped:0,ml_fields_excluded_by_policy:0}};
 vm.runInContext('renderCoverage(ruleScan)',ctx);
 assert.strictEqual(elements['coverage-percent'].textContent,'—');
 // Internally inconsistent summary also withholds any calculated coverage.
 ctx.current.summary.ml_fields_skipped=100;ctx.current.summary.ml_fields_evaluated=88192;
 vm.runInContext('renderCoverage(current)',ctx);
 assert.strictEqual(elements['coverage-chip'].textContent,'UNVERIFIED');
 console.log('Model Laboratory verified-only accuracy and coverage checks passed');
})().catch(e=>{console.error(e);process.exitCode=1});
'''
    result = subprocess.run(["node", "-e", js_test, str(ASSETS)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
