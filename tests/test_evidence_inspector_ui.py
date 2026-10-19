"""Frontend evidence contract checks for the stacked network-evidence UI."""
from pathlib import Path
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1] / 'src' / 'packet_pii' / 'dashboard_static'


def test_inspector_has_only_privacy_safe_reference_slots():
    html = (ROOT / 'index.html').read_text()
    js = (ROOT / 'app.js').read_text()
    for key in ('evidence-provenance', 'evidence-status', 'evidence-http',
                'evidence-fields', 'evidence-frames'):
        assert f'id="{key}"' in html
    assert 'Raw detection span' in js
    assert 'Capture identity is not verified' in js or 'Original capture identity is not verified' in js
    assert "state.report?.finding_type_counts" in js
    for category in ('APPLE_ADVERTISING_ID', 'ANDROID_ADVERTISING_ID',
                     'ADVERTISING_ID', 'AGE', 'GENDER', 'SEX', 'DEVICE_ID',
                     'USER_ACCOUNT_ID'):
        assert category in js
    block = js.split('/* Evidence v1.0:', 1)[1].split('function renderSummary()', 1)[0]
    assert not re.search(r'\binnerHTML\b|\beval\(', block)
    assert "/api/jobs/" in block
    assert 'raw_detection_span' not in html.lower()  # no invented raw-byte component
    assert 'This viewer displays redacted metadata' in html


@pytest.mark.skipif(shutil.which('node') is None, reason='Node.js unavailable')
def test_lookup_preserves_capture_identity_and_bounded_source_ranges():
    js = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync(process.argv[1]+'/app.js','utf8');
const from=source.indexOf('/* Evidence v1.0:'),to=source.indexOf('function renderSummary()',from);
assert(from>=0&&to>from);
class Element{
 constructor(){this.textContent='';this.children=[];}
 replaceChildren(){this.children=[];}
 append(...items){this.children.push(...items);}
}
const nodes=Object.fromEntries(['evidence-status','evidence-http','evidence-fields','evidence-frames']
 .map(id=>[id,new Element()]));
const sha='c'.repeat(64);
const state={reportJobId:'job-fixture',token:'test-token',report:{
 capture_evidence:{capture_sha256:sha,identity_status:'verified_read'}}};
const calls=[];
const data={
 http_evidence:{items:[{http_message_id:'flow_1_msg_1',protocol:'http/1.1',
   pairing_status:'paired_best_effort',stream_id:'flow_1_direction_0',
   start_line:'POST [redacted] HTTP/1.1',stream_start:0,stream_end:99}],total:1},
 field_evidence:{items:[{field_id:'flow_1_msg_1_field_2',source_category:'json_body',
   granularity:'exact_stream_range',transformations:[],stream_id:'flow_1_direction_0',
   stream_ranges:[{start:10,end:14}]}],total:1},
 stream_evidence:{items:[{row_type:'source_range',stream_id:'flow_1_direction_0',
   frame_id:'frame_4',stream_start:0,stream_end:99,file_start:200,file_end:299}],total:1}};
const ctx={state,URL,URLSearchParams,console,Error,Number,
 document:{getElementById:id=>{assert(nodes[id]);return nodes[id]},createElement:()=>new Element()},
 num:x=>Number(x).toLocaleString('en-AU'),
 setText:(id,v)=>{nodes[id].textContent=String(v)},
 $:id=>nodes[id],
 fetch:async(url,opts)=>{calls.push(url);assert.equal(opts.headers['X-Dashboard-Token'],'test-token');
   const parsed=new URL(url,'http://localhost');const kind=parsed.pathname.split('/').pop();
   assert(parsed.searchParams.get('limit')==='100');return {ok:true,json:async()=>data[kind]};}
};
vm.createContext(ctx);vm.runInContext(source.slice(from,to),ctx);
ctx.finding={pii_type:'PERSON_NAME',evidence:{http_message_id:'flow_1_msg_1',
 field_ids:['flow_1_msg_1_field_2'],decoded_text_span:{start:0,end:4}}};
(async()=>{
 await vm.runInContext('loadFindingEvidence(finding)',ctx);
 assert.equal(calls.length,3);
 assert(nodes['evidence-status'].textContent.includes('Capture identity verified'));
 const rendered=JSON.stringify(nodes);
 assert(rendered.includes('frame_4'));
 assert(rendered.includes('210'));
 assert(rendered.includes('214'));
 assert(rendered.includes('not a PCAP byte offset'));
 assert(!rendered.includes('SecretBodyName'));
 ctx.state.report.capture_evidence.identity_status='unverified';
 await vm.runInContext('loadFindingEvidence(finding)',ctx);
 assert.equal(calls.length,3,'unverified capture must not query evidence API');
 assert(nodes['evidence-status'].textContent.includes('not verified'));
 console.log('Evidence inspector hash gate and source range UI passed');
})().catch(e=>{console.error(e);process.exitCode=1});
'''
    check = subprocess.run(['node', '--check', str(ROOT / 'app.js')],
                           capture_output=True, text=True, timeout=20)
    assert check.returncode == 0, check.stderr
    result = subprocess.run(['node', '-e', js, str(ROOT)], capture_output=True,
                            text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
