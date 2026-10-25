'use strict';
/* TRACE dashboard: session, scan lifecycle, summary, paged findings and connections.
   The universal inspector lives in inspector.js and the Model laboratory in lab.js.
   Everything from the server or a capture is written with textContent. */
const state={token:null,maxBytes:0,report:null,file:null,tab:'overview',scanMode:'rules',modelAvailable:false,modelVersion:null,busy:false,jobsSupported:false,profiles:{},profile:"standard",serverMaxBytes:0,jobId:null,reportJobId:null,reportFilename:null,pollTimer:null,pageSize:100,findingsOffset:0,flowsOffset:0,findingsTotal:0,flowsTotal:0,findingsRequest:0,flowsRequest:0,selectedFinding:null,selectedFlowId:null,pageFindings:[],restoreTab:null};
const $=id=>document.getElementById(id);
const labels={
 overview:['New analysis','New analysis','Choose a packet capture to inspect.'],
 summary:['Summary','Summary','What TRACE found in this capture and how complete the examination was.'],
 findings:['Findings','Findings','Potential personal information found in HTTP traffic. Values are masked.'],
 flows:['Traffic','Traffic','The HTTP conversations and TCP connections TRACE rebuilt from the capture.'],
 model:['Model laboratory','Model laboratory','How the optional contextual model behaved, kept separate from synthetic and offline research results.'],
 how:['How TRACE works','How TRACE works','What TRACE does, the terms it uses and the limits of its results.']};
const RESULT_TABS=['summary','findings','flows','model'];
const hasInspector=()=>typeof TraceInspector!=='undefined';
const UPPER=new Set(['ip','id','pii','url','uuid']);
function typeLabel(t){const words=String(t||'Unknown').replaceAll('_',' ').toLowerCase().split(' ').map(w=>UPPER.has(w)?w.toUpperCase():w);const out=words.join(' ');return out.charAt(0).toUpperCase()+out.slice(1);}
const num=n=>Number(n||0).toLocaleString('en-AU');
function setText(id,value){$(id).textContent=String(value)}
function store(key,value){try{if(value==null)localStorage.removeItem(key);else localStorage.setItem(key,value)}catch{}}
function recall(key){try{return localStorage.getItem(key)}catch{return null}}

// ---------------------------------------------------------------- capture status and progress
const CAPTURE_STATE={none:'Not analysed',running:'Analysing',complete:'Complete',incomplete:'Incomplete',failed:'Failed',cancelled:'Cancelled',unknown:'Status unknown'};
function setCaptureStatus(kind,name,meta){
 const pill=$('ctx-status');pill.textContent=CAPTURE_STATE[kind]||kind;pill.dataset.state=kind;
 if(name!=null)setText('ctx-capture',name);
 if(meta!=null)setText('ctx-meta',meta);
}
// Steps the engine reports, in the order it reports them. Nothing here estimates time.
const STEPS=[['prepare','Preparing the capture',['uploading','queued','running']],['reading','Reading packets',['reading']],
 ['reconstructing','Rebuilding conversations',['reconstructing']],['analysing','Checking extracted fields',['analysing']],
 ['model','Running the contextual model',['ml_inference']],['report','Preparing findings and evidence',['writing_report','complete']]];
let lastStep=0;
function renderSteps(stage){
 const steps=STEPS.filter(s=>s[0]!=='model'||state.scanMode==='hybrid'||stage==='ml_inference');
 const found=steps.findIndex(s=>s[2].includes(stage));
 if(found>=0)lastStep=found;else if(stage==='uploading')lastStep=0;
 const root=$('progress-steps');root.replaceChildren();
 steps.forEach((s,i)=>{const li=document.createElement('li');li.className=i<lastStep?'done':i===lastStep?'current':'todo';li.textContent=s[1];if(i===lastStep)li.setAttribute('aria-current','step');root.appendChild(li)});
}
let timerHandle=null;
function loading(on,message='Analysing capture...'){state.busy=on;$('statusbar').classList.toggle('hidden',!on);setText('status',message);for(const id of ['sample','choose','analysis-profile'])$(id).disabled=on;$('cancel-job').classList.toggle('hidden',!on||!state.jobId);for(const x of document.querySelectorAll('input[name="scan-mode"]'))x.disabled=on||(x.value==='hybrid'&&!state.modelAvailable);if(timerHandle){clearInterval(timerHandle);timerHandle=null;}if(on){lastStep=0;renderSteps('uploading');const started=performance.now();const tick=()=>{if(state.jobId)return;const seconds=Math.floor((performance.now()-started)/1000);setText('status-elapsed',String(Math.floor(seconds/60)).padStart(2,'0')+':'+String(seconds%60).padStart(2,'0'));};tick();timerHandle=setInterval(tick,1000);setText('status-stage','Processing on this computer.');}}
function error(msg){setText('errorbar',msg);$('errorbar').classList.remove('hidden')}
function clearError(){$('errorbar').classList.add('hidden')}

// ---------------------------------------------------------------- navigation
function setNav(open){$('sidebar').classList.toggle('open',open);$('nav-scrim').classList.toggle('hidden',!open);$('nav-toggle').setAttribute('aria-expanded',String(open));if(open&&hasInspector()&&TraceInspector._state.open)TraceInspector.close(false);}
function switchTab(name){
 if(!labels[name])return;
 state.tab=name;
 for(const nav of document.querySelectorAll('.nav-link')){const on=nav.dataset.tab===name;nav.classList.toggle('active',on);if(on)nav.setAttribute('aria-current','page');else nav.removeAttribute('aria-current');}
 setNav(false);
 for(const sec of document.querySelectorAll('.view'))sec.classList.toggle('hidden',sec.id!==`view-${name}`);
 $('page-head').classList.toggle('hidden',name==='overview');
 setText('crumb',labels[name][0]);setText('page-title',labels[name][1]);setText('page-description',labels[name][2]);
 if(state.report&&RESULT_TABS.includes(name))store('trace-tab',name);
 if(hasInspector())TraceInspector.onView(name);
}
for(const nav of document.querySelectorAll('.nav-link'))nav.addEventListener('click',()=>switchTab(nav.dataset.tab));
for(const go of document.querySelectorAll('[data-go]'))go.addEventListener('click',()=>switchTab(go.dataset.go));
$('nav-toggle').addEventListener('click',()=>setNav(!$('sidebar').classList.contains('open')));$('nav-scrim').addEventListener('click',()=>setNav(false));
function cell(row,text,cls=''){const td=document.createElement('td');td.textContent=String(text);if(cls)td.className=cls;row.appendChild(td);return td}
function span(text,cls){const s=document.createElement('span');s.textContent=String(text);if(cls)s.className=cls;return s}
function types(findings){const counts=new Map();for(const f of findings){const key=String(f.pii_type||'UNKNOWN');counts.set(key,(counts.get(key)||0)+1)}return [...counts].sort((a,b)=>b[1]-a[1]);}

// ---------------------------------------------------------------- live model evidence (Model laboratory, section 1)
function setLiveEvidence(report){
 const sum=report?.summary||{}, invoked=sum.ml_invoked===true;
 const examined=sum.ml_fields_evaluated, contextual=sum.ml_findings;
 const title=sum.ml_inference_failed?'The contextual model failed or did not finish':!invoked?'The contextual model was not used in this scan':contextual>0?'The contextual model suggested '+num(contextual)+' candidate spans':'The contextual model ran and suggested no spans';
 const message=!invoked?'Only the rules ran. To use the model, choose “Rules + contextual model” before the next scan. Loading a model does not run it.':sum.ml_inference_failed?'Review the limitations before interpreting these partial results. A failed inference is not a clean result.':'The model examined '+(examined==null?'an unreported number of':num(examined))+' extracted HTTP fields. Predictions and rule findings are measured separately; zero predictions is not proof of safety.';
 setText('obs-title',title);setText('obs-text',message);
 setText('live-model-state',invoked?'YES':'NO');
 setText('live-fields-evaluated',examined==null?'—':num(examined));
 setText('live-ml-findings',contextual==null?'—':num(contextual));
 setText('live-rule-findings',sum.rules_findings==null?'—':num(sum.rules_findings));
 setText('live-inference-status',sum.ml_inference_failed?'Failed / partial':sum.ml_incomplete?'Incomplete':invoked?'Invoked':'Not invoked');
 const root=$('live-telemetry');root.replaceChildren();
 const metrics=[['Extracted fields',sum.fields_extracted],['Eligible for ML',sum.ml_fields_eligible],['Excluded by policy',sum.ml_fields_excluded_by_policy],['Skipped fields',sum.ml_fields_skipped],['Empty fields',sum.ml_fields_empty],['PERSON_NAME predictions',sum.ml_predictions_by_label?.PERSON_NAME],['USERNAME predictions',sum.ml_predictions_by_label?.USERNAME],['ML processing time',sum.ml_processing_time_seconds==null?null:Number(sum.ml_processing_time_seconds).toFixed(3)+' s']];
 for(const [label,value] of metrics){const group=document.createElement('div'),dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=value==null?'—':typeof value==='number'?num(value):value;group.append(dt,dd);root.appendChild(group)}
 setText('live-disclosure','No live-file precision/recall/F1 is available: this capture has no independently verified labels. Model scores are uncalibrated; offline benchmarks apply only to the stated source model and research dataset.');
}
async function loadBenchmark(){
 try{const response=await fetch('/api/benchmark',{headers:{'X-Dashboard-Token':state.token}});if(!response.ok)throw Error();const b=await response.json();if(!b.available||!b.model_version)throw Error();
 const pct=value=>typeof value==='number'?((value<=1?value*100:value).toFixed(1)+'%'):'—';
 setText('benchmark-title','Offline benchmark · '+b.model_version);setText('benchmark-version',b.model_version);
 setText('benchmark-source',(b.dataset?.name||'Research dataset')+' · '+(b.dataset?.fields==null?'field count unavailable':num(b.dataset.fields)+' fields'));
 for(const key of ['precision','recall','f1'])setText('benchmark-'+key,pct(b[key]));
 setText('benchmark-ci',Array.isArray(b.bootstrap_ci)?'Bootstrap interval: '+b.bootstrap_ci.map(pct).join('–'):'Confidence interval unavailable');
 const mismatch=state.modelVersion&&b.model_version!==state.modelVersion?' The loaded checkpoint is '+state.modelVersion+'; these metrics do not describe that checkpoint.':'';
 setText('benchmark-note',(b.scope||'Offline research evaluation.')+' Metrics apply only to source model '+b.model_version+'.'+mismatch+' They are not this capture’s accuracy. Model scores are uncalibrated.');
 if(typeof TraceLab!=='undefined')TraceLab.onBenchmark(b);
 }catch{setText('benchmark-source','Verified benchmark unavailable');}
}

// ---------------------------------------------------------------- one finding, in plain language
function explainDetection(f){
 const loc=String(f.location||'unknown field');
 if(f.detector==='bilstm'){
  const range=Number.isInteger(f.span_start)&&Number.isInteger(f.span_end)
   ?'characters ['+f.span_start+', '+f.span_end+')':'a text span';
  return 'The loaded contextual BiLSTM model predicted '+String(f.pii_type||'an entity')+' at '+range+' in '+loc+'. This was inferred from the extracted text and field context, not a fixed regex. The model is not explainable from this record alone: this is a prediction, not proof of a person or leak. Raw score '+(Number(f.confidence)||0).toFixed(3)+' is NOT calibrated accuracy.';
 }
 const kind=String(f.pii_type||'');
 if(kind==='EMAIL')return 'The rules detector found an email-shaped text pattern inside '+loc+'. This is a regex-like structural match, not a judgement about whether transmission was authorised.';
 if(kind==='PHONE')return 'The rules detector found a phone-number-shaped value with a plausible digit count inside '+loc+'. Some non-phone numbers may also match.';
 if(kind==='IP_ADDRESS')return 'The rules detector recognised an IPv4-shaped pattern and checked it as a valid IPv4 address inside '+loc+'.';
 if(kind==='CREDIT_CARD')return 'The rules detector found a payment-card-shaped number that passed a Luhn checksum in '+loc+'. It is not evidence that the card belongs to a real account.';
 if(kind==='CREDENTIAL_OR_TOKEN')return 'The rules detector identified a credential-bearing field or authorisation header ('+loc+'). This relies on the field context; masked output avoids disclosing the underlying value.';
 if(kind==='USERNAME')return 'The rules detector classified '+loc+' as a username field based on its name. The entire field value is a candidate username.';
 if(kind==='PERSON_NAME_CANDIDATE')return 'The rules detector classified '+loc+' using a structured name-related key. This is a PERSON_NAME_CANDIDATE, not a validated identity or an AI prediction.';
 if(['APPLE_ADVERTISING_ID','ANDROID_ADVERTISING_ID','ADVERTISING_ID'].includes(kind))return 'A deterministic rule matched a UUID-shaped advertising identifier with supporting field context at '+loc+'. Apple/Android attribution requires explicit platform evidence. A valid format does not establish a genuine assigned device identifier.';
 if(kind==='AGE')return 'A deterministic rule matched an explicitly labelled age field and its permitted value format at '+loc+'. TRACE did not infer a person’s age.';
 if(kind==='GENDER'||kind==='SEX')return 'A deterministic rule classified an explicitly transmitted '+(kind==='SEX'?'sex':'gender')+' field using documented context and value checks at '+loc+'. TRACE did not infer demographic characteristics.';
 if(kind==='DEVICE_ID'||kind==='USER_ACCOUNT_ID')return 'A deterministic rule found an identifier-shaped value under a narrowly defined '+(kind==='DEVICE_ID'?'device':'user/account')+' field at '+loc+'. This does not verify a real person or device.';
 return 'The rule detector emitted a candidate '+kind+' finding at '+loc+'. Examine its location and source; rule scores are heuristics, not calibrated probabilities.';
}
function findingKey(f){return [f?.http_message_id||f?.evidence?.http_message_id,f?.location,f?.pii_type,f?.value,f?.detector,f?.span_start,f?.span_end].join('|')}
function endpoint(ip,port){return ip?String(ip)+(port!=null?':'+port:''):'an unknown endpoint'}
function whereText(f){
 const kind=f.http_message_type==='response'?'HTTP response':f.http_message_type==='request'?'HTTP request':'HTTP message';
 return 'In the field '+String(f.location||'(unknown)')+' of an '+kind+' sent from '+endpoint(f.source_ip,f.source_port)+' to '+endpoint(f.destination_ip,f.destination_port)+'.';
}
function detectorText(f){
 const score=typeof f.confidence==='number'?f.confidence.toFixed(f.detector==='bilstm'?3:2):'unreported';
 return f.detector==='bilstm'?'Contextual model prediction · raw score '+score+' (uncalibrated)':'Rule match · heuristic score '+score;
}
function markFindingRows(){
 const key=state.selectedFinding?findingKey(state.selectedFinding):null;
 for(const row of $('findings-body').children){const on=!!row.finding&&findingKey(row.finding)===key;row.classList.toggle('selected',on);if(row.main)row.main.setAttribute('aria-current',String(on));}
}
function inspectFinding(f,opts={}){
 if(!opts.restore||state.tab==='findings'){state.selectedFinding=f;markFindingRows();}
 setText('inspect-title',typeLabel(f.pii_type||'PII'));
 setText('inspect-sub',f.value||'[masked]');
 setText('fi-detector',detectorText(f));
 setText('fi-where',whereText(f));
 setText('inspect-reason',explainDetection(f));
 setText('inspect-location',String(f.location||'—'));
 setText('inspect-message',String(f.http_message_id||'—')+' · '+String(f.http_message_type||'HTTP')+(f.http_start_line?' · '+String(f.http_start_line):''));
 setText('inspect-endpoints',String(f.source_ip||'—')+':'+String(f.source_port??'—')+' → '+String(f.destination_ip||'—')+':'+String(f.destination_port??'—'));
 setText('inspect-method',f.detector==='bilstm'?'BiLSTM · uncalibrated raw model score':'Rules · heuristic score');
 if(typeof TraceLab!=='undefined')TraceLab.inspect(f);
 // Packet-to-field references load only when that section is open; the inspector's evidence section covers the common case.
 if($('provenance-details').open)void loadFindingEvidence(f);else clearFindingEvidence('Open this section to check verified packet references.');
 if(hasInspector())TraceInspector.openFinding(f,{open:opts.open===true,push:opts.push===true,restore:opts.restore===true});
}

/* Evidence v1.0: read-only authenticated joins. Never fetch raw capture bytes. */
let evidenceEpoch=0;
function clearFindingEvidence(message){
 setText('evidence-status',message);
 for(const id of ['evidence-http','evidence-fields','evidence-frames'])$(id).replaceChildren();
}
function evidenceFact(id,title,body){
 const wrapper=document.createElement('div'),key=document.createElement('strong'),value=document.createElement('span');
 wrapper.className='evidence-fact';key.textContent=String(title);value.textContent=String(body);
 wrapper.append(key,value);$(id).appendChild(wrapper);
}
async function evidencePage(job,kind,key,value,offset=0){
 if(typeof value!=='string'||!value||value.length>160)throw Error('Invalid evidence reference');
 const params=new URLSearchParams({offset:String(offset),limit:'100'});
 params.set(key,value);
 const response=await fetch('/api/jobs/'+encodeURIComponent(job)+'/'+kind+'?'+params,
   {headers:{'X-Dashboard-Token':state.token}});
 if(!response.ok)throw Error('Evidence reference unavailable ('+response.status+')');
 const data=await response.json();
 if(!Array.isArray(data.items)||!Number.isInteger(data.total))throw Error('Invalid evidence response');
 return data;
}
function evidenceIntervalText(start,end){
 return Number.isInteger(start)&&Number.isInteger(end)&&end>=start?'['+num(start)+', '+num(end)+')':'unavailable';
}
async function loadFindingEvidence(finding){
 const epoch=++evidenceEpoch,job=state.reportJobId,report=state.report||{};
 clearFindingEvidence('Checking independently verified source references…');
 const evidence=finding?.evidence;
 if(!job||!evidence||!evidence.http_message_id){
  clearFindingEvidence('Packet-level evidence is unavailable for this result. Legacy logical field and network-flow details remain above.');
  return;
 }
 const identity=report.capture_evidence||{};
 if(identity.identity_status!=='verified_read'||!/^[0-9a-f]{64}$/i.test(identity.capture_sha256||'')){
  clearFindingEvidence('Original capture identity is not verified; packet-byte references are withheld.');
  return;
 }
 const valid=()=>epoch===evidenceEpoch&&state.reportJobId===job&&state.report?.capture_evidence?.capture_sha256===identity.capture_sha256;
 const fieldIds=Array.isArray(evidence.field_ids)?evidence.field_ids.filter(x=>typeof x==='string'&&x.length<=160).slice(0,8):[];
 try{
  const pages=await Promise.all([evidencePage(job,'http_evidence','evidence_id',evidence.http_message_id),
   ...fieldIds.map(id=>evidencePage(job,'field_evidence','evidence_id',id))]);
  if(!valid())return;
  const http=pages[0].items.find(x=>x.http_message_id===evidence.http_message_id);
  if(!http)throw Error('HTTP evidence identity not found');
  const fields=pages.slice(1).flatMap((x,i)=>x.items.filter(y=>y.field_id===fieldIds[i]));
  evidenceFact('evidence-http','Capture SHA-256',identity.capture_sha256);
  evidenceFact('evidence-http','HTTP message',http.http_message_id+' · '+String(http.protocol||'unknown').toUpperCase());
  evidenceFact('evidence-http','Request/response pairing',http.pairing_status||'unavailable');
  evidenceFact('evidence-http','Start line (redacted)',http.start_line||'unavailable');
  evidenceFact('evidence-http','TCP stream',http.stream_id||'unavailable');
  evidenceFact('evidence-http','Observed stream range',evidenceIntervalText(http.stream_start,http.stream_end));
  if(http.protocol==='h2')evidenceFact('evidence-http','HTTP/2 stream ID',http.http2_stream_id??'unavailable');
  if(!fields.length)evidenceFact('evidence-fields','Mapping limitation','No uniquely resolvable field reference; HTTP message-level evidence only.');
  for(const field of fields){
   evidenceFact('evidence-fields',field.field_id,
    'Source: '+(field.source_category||'unknown')+
    ' · granularity: '+(field.granularity||'unavailable')+
    ' · transforms: '+(field.transformations?.join(', ')||'none')+
    ' · source intervals: '+(field.stream_ranges?.length||0));
  }
  if(evidence.decoded_text_span)evidenceFact('evidence-fields','BiLSTM decoded character span',
   evidenceIntervalText(evidence.decoded_text_span.start,evidence.decoded_text_span.end)+' (not a PCAP byte offset)');
  evidenceFact('evidence-fields','Raw detection span','Unavailable — TRACE does not claim exact raw match offsets.');
  const sourcePages=new Map();
  for(const streamId of [...new Set(fields.map(x=>x.stream_id).filter(Boolean))].slice(0,2)){
   sourcePages.set(streamId,await evidencePage(job,'stream_evidence','stream_id',streamId));
   if(!valid())return;
  }
  const sources=new Map();let partial=fieldIds.length<(evidence.field_ids?.length||0);
  for(const field of fields){
   const pg=sourcePages.get(field.stream_id);
   if(!pg)continue;
   if(pg.total>pg.items.length)partial=true;
   for(const needed of field.stream_ranges||[]){
    if(!Number.isInteger(needed.start)||!Number.isInteger(needed.end))continue;
    for(const src of pg.items){
     if(src.row_type!=='source_range'||!src.frame_id)continue;
     const start=Math.max(needed.start,src.stream_start),end=Math.min(needed.end,src.stream_end);
     if(!(start<end))continue;
     const exact=field.granularity==='exact_stream_range'&&Array.isArray(field.transformations)&&field.transformations.length===0;
     let reference=src.frame_id+' · stream '+evidenceIntervalText(start,end);
     if(Number.isInteger(src.file_start))reference+=' · supporting file bytes '+
      evidenceIntervalText(src.file_start+start-src.stream_start,src.file_start+end-src.stream_start);
     reference+=' · '+(exact?'source field bytes':'transformed source only');
     sources.set(reference,true);
    }
   }
  }
  const refs=[...sources.keys()];
  for(const item of refs.slice(0,12))evidenceFact('evidence-frames','Observed source interval',item);
  if(!refs.length)evidenceFact('evidence-frames','No resolved frame ranges',
   'Source ranges may be unavailable, transformed, or beyond the bounded lookup page. Do not infer packet numbers.');
  if(refs.length>12)partial=true;
  if(valid())setText('evidence-status',partial?
   'Capture identity verified. Showing a bounded subset of field/source references; evidence is partial.':
   'Capture identity verified. Showing metadata and supporting source references (no raw data).');
 }catch(e){if(valid()){
  clearFindingEvidence('Evidence lookup failed or is unsupported by this scan: '+(e instanceof Error?e.message:'unavailable'));
 }}
}

function renderSummary(){
 const r=state.report;const s=r.summary||{},f=r.findings||[];
 setText('metric-findings',num(s.potential_leaks));setText('metric-rules',num(s.rules_findings));setText('metric-ml',num(s.ml_findings));
 setText('analysis-mode',r.metadata?.detection_method==='rules_plus_bilstm'?'Rules + contextual model':'Rules only');
 setText('model-stamp',r.metadata?.ml_model_version?r.metadata.ml_model_version:'Not used');
 setText('metric-flows',num(s.flows_processed));setText('metric-messages',num(s.http_messages));setText('metric-packets',num(s.packets_captured));setText('metric-gaps',num(s.stream_gaps));setText('metric-transactions',num(s.http_transactions));setText('metric-time',`${Number(s.processing_time_seconds||0).toFixed(3)} s`);
 setText('analysis-meta',`${num(s.packets_captured)} packets · ${num(s.http_messages)} HTTP messages · ${num(s.total_data_bytes)} frame bytes`);
 setText('capture-name',state.file||'Capture loaded');
 setText('nav-count-findings',num(s.potential_leaks));$('nav-count-findings').classList.remove('hidden');
 setText('breakdown-scope',r.finding_type_counts?'All findings in this capture':state.reportJobId?'First report page only · full totals above':'Current capture');
 const items=r.finding_type_counts?Object.entries(r.finding_type_counts).filter(x=>Number(x[1])>0).sort((a,b)=>b[1]-a[1]):types(f);
 const total=Number(s.potential_leaks)||0;
 setText('answer-title',total?num(total)+' potential '+(total===1?'finding':'findings'):'No personal information detected');
 setText('answer-text',total
  ?'Involving '+num(items.length)+' '+(items.length===1?'type':'types')+' of information across '+num(s.http_messages)+' HTTP messages. Values are masked. Each finding is a candidate to review, not confirmed personal information.'
  :'TRACE checked '+num(s.http_messages)+' HTTP messages and found nothing at the current thresholds. That does not show the capture is free of personal information, especially if some traffic was encrypted or incomplete.');
 // Completeness: every signal that limits the result is stated, never hidden behind a green tick.
 const reasons=[];
 if(Number(s.stream_gaps)>0)reasons.push('Some packets were missing ('+num(s.stream_gaps)+' gaps in the captured streams), so parts of some conversations may be incomplete.');
 if(s.ml_coverage_status==='partial')reasons.push('The contextual model read only part of the eligible fields.');
 if(s.ml_inference_failed)reasons.push('The contextual model failed or did not finish.');
 if(s.analysis_incomplete&&!reasons.length)reasons.push('A capture problem or processing limit stopped TRACE reading some traffic.');
 const bad=!!s.analysis_incomplete||reasons.length>0;
 setText('verdict-icon',bad?'Incomplete':'Complete');$('verdict-icon').classList.toggle('warning',bad);$('verdict-icon').dataset.state=bad?'warn':'ok';
 setText('verdict-title',bad?'Some traffic could not be fully analysed':'No capture or reconstruction problems reported');
 setText('verdict-text',bad?reasons.join(' ')+' Missing findings are not evidence of absence.':'TRACE did not report capture damage or gaps. This does not prove that every protocol or sensitive value was decoded; encrypted traffic is never read.');
 const root=$('breakdown');root.replaceChildren();
 if(!items.length){const p=document.createElement('p');p.className='empty-inline';p.textContent='No findings were reported at the current thresholds.';root.appendChild(p)}
 else{const max=items[0][1];for(const [label,count] of items.slice(0,8)){const line=document.createElement('button');line.type='button';line.className='bar-row';line.setAttribute('aria-label',typeLabel(label)+': '+count+' findings. Show them.');const name=document.createElement('span');name.className='bar-label';name.textContent=typeLabel(label);const track=document.createElement('span');track.className='bar-track';const fill=document.createElement('span');fill.className='bar-fill';fill.style.width=`${Math.max(3,(count/max)*100)}%`;track.appendChild(fill);const n=document.createElement('b');n.className='bar-count';n.textContent=count;line.append(name,track,n);line.addEventListener('click',()=>showType(label));root.appendChild(line)}}
 setCaptureStatus(bad?'incomplete':'complete',state.file||'Capture',num(total)+' '+(total===1?'finding':'findings')+' · '+(r.metadata?.detection_method==='rules_plus_bilstm'?'rules + model':'rules only'));
}
function showType(label){$('search').value='';$('filter-type').value=label;switchTab('findings');void filterFindings();}
function updatePagination(kind,total,offset,count){setText(kind+'-page',count?num(offset+1)+'–'+num(offset+count)+' of '+num(total):'0 of '+num(total));$(kind+'-prev').disabled=offset===0;$(kind+'-next').disabled=offset+count>=total;}
function renderFindings(){const rows=state.report?.findings||[];const names=Object.keys(state.report?.finding_type_counts||{}).filter(k=>Number(state.report.finding_type_counts[k])>0);if(!names.length)names.push(...types(rows).map(a=>a[0]));names.sort();const select=$('filter-type'),selected=select.value;select.replaceChildren();for(const label of ['',...names]){const opt=document.createElement('option');opt.value=label;opt.textContent=label?typeLabel(label):'All types';select.appendChild(opt)}select.value=names.includes(selected)?selected:'';paintFindings(rows.slice(0,state.pageSize),state.reportJobId?state.findingsTotal:rows.length,state.findingsOffset);}
function emptyRow(root,text,cols){const tr=document.createElement('tr');cell(tr,text,'table-empty').colSpan=cols;root.appendChild(tr)}
function paintFindings(rows,total,offset){
 state.pageFindings=rows;const root=$('findings-body');root.replaceChildren();
 const filtered=!!($('search').value||$('filter-type').value);
 if(!rows.length)emptyRow(root,filtered?'No findings match this search or filter.':'No findings in this capture at the current thresholds.',3);
 for(const f of rows){
  const tr=document.createElement('tr');tr.finding=f;
  const first=cell(tr,'');const main=document.createElement('button');main.type='button';main.className='row-main';
  main.append(span(typeLabel(f.pii_type),'row-title'),span(f.value||'[masked]','row-sub mono'));
  main.setAttribute('aria-label',typeLabel(f.pii_type)+', '+(f.value||'masked value')+', in '+String(f.location||'an unknown field')+'. Inspect.');
  main.addEventListener('click',ev=>{if(ev&&ev.stopPropagation)ev.stopPropagation();inspectFinding(f,{open:true})});
  first.appendChild(main);tr.main=main;tr.select=open=>inspectFinding(f,{open});
  const where=cell(tr,'');where.append(span(f.location||'—','row-loc'),span([f.http_message_type?'HTTP '+f.http_message_type:'',f.flow_id||''].filter(Boolean).join(' · '),'cell-sub'));
  const det=cell(tr,'');const tag=span(f.detector==='bilstm'?'Contextual model':'Rules',f.detector==='bilstm'?'det-model':'det-rule');
  const score=span(typeof f.confidence==='number'?f.confidence.toFixed(2):'—','cell-sub');score.title=f.detector==='bilstm'?'Uncalibrated raw model score':'Heuristic rule score';det.append(tag,score);
  tr.addEventListener('click',()=>inspectFinding(f,{open:true}));root.appendChild(tr);
 }
 markFindingRows();
 setText('findings-total',num(total)+' findings'+(filtered?' matching':''));setText('findings-shown','Showing '+num(rows.length)+' on this page');updatePagination('findings',total,offset,rows.length);
}
async function filterFindings(){state.findingsOffset=0;await loadPage('findings',0);}
function paintFlows(flows,total,offset){
 const root=$('flows-body');root.replaceChildren();setText('flows-total',num(total));
 if(!flows.length)emptyRow(root,'No TCP connections were found in this capture.',4);
 for(const f of flows){
  const tr=document.createElement('tr'),ends=f.endpoints||[];tr.flow=f;
  if(f.flow_id&&f.flow_id===state.selectedFlowId)tr.classList.add('selected');
  const first=cell(tr,'');const main=document.createElement('button');main.type='button';main.className='row-main';
  const a=ends[0]?.ip?ends[0].ip+':'+ends[0].port:'—',b=ends[1]?.ip?ends[1].ip+':'+ends[1].port:'—';
  main.append(span(a+' ↔ '+b,'row-title mono'),span(String(f.flow_id||''),'row-sub'));
  main.setAttribute('aria-label','Connection between '+a+' and '+b+'. Inspect.');
  const select=open=>{state.selectedFlowId=f.flow_id;for(const row of root.children){row.classList.toggle('selected',row===tr);if(row.main)row.main.setAttribute('aria-current',String(row===tr))}if(hasInspector())TraceInspector.openConnection(f,{open})};
  main.addEventListener('click',ev=>{if(ev&&ev.stopPropagation)ev.stopPropagation();select(true)});first.appendChild(main);tr.main=main;tr.select=select;
  cell(tr,num(f.packets),'num');cell(tr,num(f.http_messages),'num');const gaps=cell(tr,num(f.stream_gaps),'num'+(Number(f.stream_gaps)>0?' num-warn':''));if(Number(f.stream_gaps)>0)gaps.title='Some packets were missing in this connection';
  tr.addEventListener('click',()=>select(true));root.appendChild(tr);
 }
 updatePagination('flows',total,offset,flows.length);
}
function renderFlows(){const rows=state.report?.flows||[];paintFlows(rows.slice(0,state.pageSize),state.reportJobId?state.flowsTotal:rows.length,state.flowsOffset);}
async function loadPage(kind,offset){if(!state.report)return;const request=++state[kind+'Request'];const needle=$('search').value.trim(),category=$('filter-type').value;try{let rows,total;if(state.reportJobId){const params=new URLSearchParams({offset:String(offset),limit:String(state.pageSize)});if(kind==='findings'){if(needle)params.set('q',needle);if(category)params.set('type',category)}const response=await fetch('/api/jobs/'+encodeURIComponent(state.reportJobId)+'/'+kind+'?'+params,{headers:{'X-Dashboard-Token':state.token}});if(!response.ok)throw Error(response.status===404?'This analysis has expired. Run it again to keep investigating.':'Could not load '+kind+' page');const data=await response.json();rows=data.items;total=data.total;}else{let all=state.report[kind]||[];if(kind==='findings')all=all.filter(x=>(!category||x.pii_type===category)&&(!needle||[x.pii_type,x.location,x.value].some(v=>String(v||'').toLowerCase().includes(needle.toLowerCase()))));total=all.length;rows=all.slice(offset,offset+state.pageSize)}if(request!==state[kind+'Request'])return;state[kind+'Offset']=offset;state[kind+'Total']=total;(kind==='findings'?paintFindings:paintFlows)(rows,total,offset);}catch(e){if(request===state[kind+'Request'])error(e.message)}}
function setModel(invoked,version){setText('mode',invoked?'Rules + model':'Rules only');setText('model-active',invoked?'Model used in the last scan':'Model not used in the last scan');setText('live-model-loaded',state.modelAvailable?'LOADED':'NOT LOADED');setText('live-model-version',state.modelVersion||'—');setText('model-live-text',invoked?'Model '+(version||'version unreported')+' ran in this scan. Its predictions, coverage and offline benchmark results are reported separately below.':state.modelAvailable?'The BiLSTM model is loaded. Choose “Rules + contextual model” on New analysis to use it in the next scan.':'The contextual model is not loaded. Start the dashboard with --ml-checkpoint to enable it.')}

// ---------------------------------------------------------------- results
function render(payload){
 evidenceEpoch++;
 state.report=payload.report;state.file=payload.filename;state.reportFilename=payload.filename;$('previous-results').classList.add('hidden');state.reportJobId=payload.job_id||null;state.findingsOffset=state.flowsOffset=0;state.findingsTotal=(payload.pagination||payload.report.pagination)?.findings_total??payload.report.findings?.length??0;state.flowsTotal=(payload.pagination||payload.report.pagination)?.flows_total??payload.report.flows?.length??0;state.pageSize=(payload.pagination||payload.report.pagination)?.page_size||100;state.findingsRequest++;state.flowsRequest++;$('search').value='';$('filter-type').value='';
 state.selectedFinding=null;state.selectedFlowId=null;
 setText('selected-name',payload.filename||'capture.pcap');
 setText('selected-meta',((Number(payload.capture_bytes)||0)/1048576).toFixed(2)+' MiB · analysed');
 $('file-preview').classList.remove('hidden');
 setModel(payload.report.summary?.ml_invoked===true,payload.report.metadata?.ml_model_version);
 setLiveEvidence(payload.report,!!payload.model_enabled);
 if(hasInspector())TraceInspector.onResult(payload);
 renderSummary();renderFindings();renderFlows();
 const first=(payload.report.findings||[]).find(f=>f.detector==='bilstm')||(payload.report.findings||[])[0];
 if(first)inspectFinding(first,{open:false});else{setText('inspect-title','No findings to inspect');setText('inspect-sub','—');setText('inspect-reason','No finding has been selected for this capture.');for(const id of ['inspect-location','inspect-message','inspect-endpoints','inspect-method'])setText(id,'—');clearFindingEvidence('No findings to inspect.');}
 const limits=$('report-limitations');limits.replaceChildren();const limitations=payload.report.limitations||[];for(const item of (Array.isArray(limitations)?limitations:[limitations]).slice(0,20)){const li=document.createElement('li');li.textContent=typeof item==='string'?item:JSON.stringify(item);limits.appendChild(li)}$('limitations-panel').classList.toggle('hidden',!limits.children.length);
 $('export').disabled=false;
 const tab=state.restoreTab&&RESULT_TABS.includes(state.restoreTab)?state.restoreTab:'summary';state.restoreTab=null;switchTab(tab);
 if(typeof TraceLab!=='undefined')TraceLab.onResult(payload);
}
function rememberJob(id){try{if(id)localStorage.setItem('trace-last-job',id);else localStorage.removeItem('trace-last-job')}catch{}}
function profileChanged(){state.profile=$('analysis-profile').value;const limit=Number(state.profiles[state.profile]?.max_capture_bytes)||state.serverMaxBytes;state.maxBytes=Math.min(state.serverMaxBytes,limit);setText('max-file',Math.round(state.maxBytes/1048576)+' MiB');setText('profile-caption','Files up to '+Math.round(state.maxBytes/1048576)+' MiB. If a limit is reached, TRACE marks the analysis as incomplete.');}
function markLatestScan(status,message){
 if(typeof TraceLab!=='undefined')TraceLab.onAttempt(status,message);
 setLiveEvidence({summary:{}});
 const title=status==='running'?'Analysis in progress':status==='unknown'?'Status of the latest analysis is unavailable':'The latest analysis was '+status+' and is incomplete';
 setText('obs-title',title);setText('obs-text',message);setText('model-active','Latest scan: '+status);setText('model-live-text',message);
 setText('live-model-state','UNKNOWN');setText('live-inference-status',status==='running'?'Pending':status==='unknown'?'Unavailable':status+' / incomplete');
 setText('live-disclosure','No completed telemetry is available for this attempt. Unavailable counters are shown as —, not zero. No live-file precision, recall or F1 is measured.');
 const kind=status==='running'?'running':status==='cancelled'||status==='canceled'?'cancelled':status==='failed'?'failed':'unknown';
 setCaptureStatus(kind,state.file||'Capture',status==='running'?'Analysis in progress.':state.report?'Earlier results are still shown.':'No results from this attempt.');
 if(state.report&&status!=='running'){setText('previous-results','Summary, Findings, Traffic and export still show the previous completed capture: '+(state.reportFilename||'unnamed capture')+'. The Model laboratory describes the latest attempt ('+status+').');$('previous-results').classList.remove('hidden');setText('capture-name','Previous result · '+(state.reportFilename||'capture'));}
}
function showJobProgress(data){
 const p=data.progress||{},parts=[typeof p==='string'?p:(p.stage||'Processing').replaceAll('_',' ')];
 const counters=[['bytes_received','bytes received'],['capture_bytes','capture bytes'],['packets','packets'],['packets_captured','packets'],['endpoint_pairs','endpoint pairs'],['sessions','sessions'],['flows_processed','flows'],['http_messages','HTTP messages'],['fields_extracted','fields extracted'],['potential_leaks','findings'],['ml_fields_evaluated','fields evaluated by ML'],['ml_fields_evaluated_so_far','fields evaluated by ML so far']];
 for(const [key,label] of counters)if(typeof p[key]==='number')parts.push(num(p[key])+' '+label);
 setText('status-stage',parts.join(' · '));
 if(typeof p==='object'&&p.stage)renderSteps(p.stage);
 const elapsed=data.elapsed_seconds??p.elapsed_seconds;
 if(typeof elapsed==='number'&&Number.isFinite(elapsed)){const seconds=Math.max(0,Math.floor(elapsed));setText('status-elapsed',String(Math.floor(seconds/60)).padStart(2,'0')+':'+String(seconds%60).padStart(2,'0'));}
}
async function recoverServerJob(excludedId){
 const response=await fetch('/api/session');if(!response.ok)return false;const session=await response.json();if(session.token)state.token=session.token;
 const active=session.active_job_id;if(!active||active===excludedId)return false;
 state.jobId=active;rememberJob(active);loading(true,'Recovering server analysis status…');await pollJob();return true;
}
async function pollJob(){const id=state.jobId;if(!id)return;clearTimeout(state.pollTimer);try{const response=await fetch('/api/jobs/'+encodeURIComponent(id),{headers:{'X-Dashboard-Token':state.token}});const data=await response.json();if(id!==state.jobId)return;if(!response.ok){if(response.status===404){rememberJob(null);state.jobId=null;if(await recoverServerJob(id))return;$('job-recovery').classList.add('hidden');loading(false);markLatestScan('unknown','The saved job is no longer available. Start a new scan.');error('The saved job is no longer available. Start a new scan.');return}throw Error(data.error||'Job status unavailable');}$('job-recovery').classList.add('hidden');showJobProgress(data);if(data.status==='completed'){render(data);loading(false);return}if(['failed','cancelled','canceled'].includes(data.status)){loading(false);markLatestScan(data.status,data.error||'This attempt did not complete. Inference and finding counts are unavailable.');error(data.status==='failed'?(data.error||'Analysis failed'):'Analysis cancelled. No results were produced for this attempt.');return}setText('status','Analysing '+(state.file||'capture')+'…');state.pollTimer=setTimeout(pollJob,1000);}catch(e){loading(false);markLatestScan('unknown','Status polling stopped. Resume status to recover the latest server result.');error(e.message);$('job-recovery').classList.remove('hidden');}}
async function post(url,body){if(state.busy)return;clearError();$('job-recovery').classList.add('hidden');const previousId=state.jobId;state.jobId=null;if(url==='/api/showcase')state.file='Sample capture';markLatestScan('running','The latest scan has not returned completed inference telemetry.');loading(true,url==='/api/showcase'?'Generating the sample capture and analysing it…':url==='/api/demo'?'Analysing the legacy synthetic fixture…':'Uploading and analysing '+(state.file||'capture')+'…');const requestId=crypto.randomUUID();let queued=false,responseReceived=false;try{const target=state.jobsSupported?(url==='/api/analyze'?'/api/jobs':url==='/api/showcase'?'/api/jobs/showcase':'/api/jobs/demo'):url;const response=await fetch(target,{method:'POST',headers:{'X-Dashboard-Token':state.token,'X-Detection-Mode':state.scanMode,'X-Analysis-Profile':state.profile,'X-Request-ID':requestId,...(typeof TraceLab!=='undefined'?TraceLab.scanHeaders():{}),...(url==='/api/analyze'?{'Content-Type':'application/octet-stream','X-Capture-Name':encodeURIComponent(state.file)}:{})},body});const data=await response.json();responseReceived=true;if(!response.ok)throw Error(data.error||'Analysis failed');if(state.jobsSupported){if(!data.job_id)throw Error('Server returned no job identifier');state.jobId=data.job_id;rememberJob(data.job_id);queued=true;$('cancel-job').classList.remove('hidden');await pollJob();}else{rememberJob(null);render(data)}}catch(e){if(state.jobsSupported&&!responseReceived){try{queued=await recoverServerJob(previousId);if(queued)return}catch{}}markLatestScan(responseReceived?'failed':'unknown',e instanceof Error?e.message:'Analysis failed');error(e instanceof Error?e.message:'Analysis failed');if(!responseReceived&&state.jobsSupported)$('job-recovery').classList.remove('hidden');}finally{if(!queued)loading(false)}}
function ingest(file){if(!file||state.busy)return;if(!/\.(pcap|pcapng)$/i.test(file.name)){error('“'+file.name+'” is not a packet capture. Choose a .pcap or .pcapng file.');return}if(file.size>state.maxBytes){error(`This file is larger than the ${Math.round(state.maxBytes/(1024*1024))} MiB limit for the selected profile. Open “Large capture settings” to choose a bigger profile.`);return}state.file=file.name;setText('selected-name',file.name);setText('selected-meta',(file.size/1048576).toFixed(2)+' MiB · '+(file.name.toLowerCase().endsWith('.pcapng')?'PCAPNG':'PCAP'));$('file-preview').classList.remove('hidden');post('/api/analyze',file)}

// ---------------------------------------------------------------- controls
$('choose').addEventListener('click',ev=>{ev.stopPropagation();$('file').click()});$('file').addEventListener('change',ev=>{const picked=ev.target.files?.[0];ev.target.value='';ingest(picked)});$('sample').addEventListener('click',ev=>{ev.stopPropagation();post('/api/showcase',null)});let searchTimer;$('search').addEventListener('input',()=>{clearTimeout(searchTimer);searchTimer=setTimeout(filterFindings,250)});$('filter-type').addEventListener('change',filterFindings);
$('dropzone').addEventListener('click',ev=>{if(state.busy||(ev.target.closest&&ev.target.closest('button')))return;$('file').click()});for(const e of ['dragenter','dragover'])$('dropzone').addEventListener(e,ev=>{ev.preventDefault();$('dropzone').classList.add('drag')});for(const e of ['dragleave','drop'])$('dropzone').addEventListener(e,ev=>{ev.preventDefault();$('dropzone').classList.remove('drag');if(e==='drop')ingest(ev.dataTransfer?.files?.[0])});
for(const input of document.querySelectorAll('input[name="scan-mode"]'))input.addEventListener('change',()=>{if(!input.checked||state.busy)return;state.scanMode=input.value;setText('scan-caption',input.value==='hybrid'?'The next scan runs the rules and the BiLSTM V2 model. Model scores are uncalibrated.':'The next scan runs the rules only. The model is not used.');setText('mode',input.value==='hybrid'?'Rules + model selected':'Rules only');});
$('provenance-details').addEventListener('toggle',()=>{if($('provenance-details').open&&state.selectedFinding)void loadFindingEvidence(state.selectedFinding)});
$('export').addEventListener('click',()=>{if(!state.report)return;if(state.reportJobId){const a=document.createElement('a');a.href='/api/jobs/'+encodeURIComponent(state.reportJobId)+'/report';a.download='trace-privacy-report.json';a.click();return;}const blob=new Blob([JSON.stringify(state.report,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='trace-privacy-report.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),3000)});
if(typeof document.addEventListener==='function')document.addEventListener('keydown',ev=>{
 const t=ev.target,typing=t&&(t.tagName==='INPUT'||t.tagName==='SELECT'||t.tagName==='TEXTAREA');
 if(ev.key==='/'&&!typing&&state.tab==='findings'){ev.preventDefault();$('search').focus();}
});
(async()=>{try{const result=await fetch('/api/session');if(!result.ok)throw Error('Session unavailable');const data=await result.json();state.token=data.token;state.serverMaxBytes=Number(data.max_upload_bytes)||0;state.maxBytes=state.serverMaxBytes;state.jobsSupported=data.jobs_supported===true;state.profiles=data.profiles||{};profileChanged();setText('max-file',`${Math.round(state.maxBytes/(1024*1024))} MiB`);state.modelAvailable=!!(data.model_available??data.model_enabled);state.modelVersion=data.model_version||null;const ai=document.querySelector('input[name="scan-mode"][value="hybrid"]');ai.disabled=!state.modelAvailable;setText('ai-ready',state.modelAvailable?'Ready':'Not loaded');$('ai-ready').className='chip '+(state.modelAvailable?'chip-ok':'');state.scanMode='rules';ai.checked=false;document.querySelector('input[name="scan-mode"][value="rules"]').checked=true;setText('scan-caption',state.modelAvailable?'Model '+data.model_version+' is loaded. Rules stay selected until you choose the model.':'The contextual model is not loaded, so only rules are available. Start TRACE with --ml-checkpoint to enable it.');setModel(false,null);setText('mode','Rules only');if(hasInspector())TraceInspector.init(data);if(typeof TraceLab!=='undefined')TraceLab.init(data);loadBenchmark();if(state.jobsSupported){let last;try{last=localStorage.getItem('trace-last-job')}catch{}const resume=data.active_job_id||last;if(resume){state.restoreTab=recall('trace-tab');state.jobId=resume;rememberJob(resume);markLatestScan('running','Recovering the latest server analysis. Completed inference telemetry is pending.');loading(true,'Resuming analysis status…');pollJob()}}}catch(e){setCaptureStatus('unknown',null,'The local server is not responding.');error('Cannot connect to the local analysis server. Restart the dashboard.')}})();

$('analysis-profile').addEventListener('change',profileChanged);
for(const kind of ['findings','flows'])for(const direction of ['prev','next'])$(kind+'-'+direction).addEventListener('click',()=>loadPage(kind,Math.max(0,state[kind+'Offset']+(direction==='next'?state.pageSize:-state.pageSize))));
$('resume-job').addEventListener('click',async()=>{clearError();loading(true,'Resuming analysis status…');if(state.jobId){await pollJob();return}try{if(await recoverServerJob(null))return;loading(false);error('No recoverable server job is available. Start a new scan.')}catch(e){loading(false);error(e.message)}});
$('cancel-job').addEventListener('click',async()=>{if(!state.jobId)return;$('cancel-job').disabled=true;setText('status','Cancelling…');try{const response=await fetch('/api/jobs/'+encodeURIComponent(state.jobId)+'/cancel',{method:'POST',headers:{'X-Dashboard-Token':state.token}});if(!response.ok)throw Error('Could not cancel analysis');await pollJob()}catch(e){error(e.message)}finally{$('cancel-job').disabled=false}});
