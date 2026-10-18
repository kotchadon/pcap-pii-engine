'use strict';
/* Model Laboratory: ML coverage accounting, ground-truth evaluation and inspector detail.
   Renders only server-reported numbers with textContent; it never computes or invents accuracy. */
const TraceLab=(()=>{
 const q=id=>document.getElementById(id);
 const set=(id,text)=>{const node=q(id);if(node)node.textContent=String(text)};
 const nf=n=>Number(n||0).toLocaleString('en-AU');
 const fmt=v=>v==null?'n/a':Number(v).toFixed(3);
 const ratio=(a,b)=>b>0?(100*a/b):null;
 const SKIP_LABEL={field_budget:'field budget reached',character_budget:'character budget reached',time_budget:'inference time budget reached',field_too_large:'single field too large',location_too_long:'field name too long',invalid_field:'invalid field'};
 const KIND_LABEL={controlled_synthetic_fixture:'Controlled synthetic fixture',hand_designed_demonstration:'Hand-designed demonstration — not an independent benchmark',human_annotated_capture:'Human-annotated capture'};
 const CHIP={complete:'COMPLETE',partial:'PARTIAL',no_eligible_fields:'NO ELIGIBLE FIELDS',not_requested:'NOT REQUESTED',unavailable:'UNAVAILABLE',failed:'FAILED',running:'RUNNING',cancelled:'CANCELLED',unknown:'UNKNOWN',none:'NO SCAN YET'};
 const st={mlProfile:'standard',manifestId:null,manifest:null,coverage:'none',evalJob:null,evalResult:null};

 function item(list,text){const li=document.createElement('li');li.textContent=text;list.appendChild(li)}
 function row(tr,text,cls){const td=document.createElement('td');td.textContent=String(text);if(cls)td.className=cls;tr.appendChild(td)}
 function token(){return typeof state!=='undefined'?state.token:null}
 function fail(message){if(typeof error==='function')error(message)}

 // ---------------------------------------------------------------- scan configuration
 function scanHeaders(){
  const headers={};
  if(typeof state!=='undefined'&&state.scanMode==='hybrid')headers['X-ML-Coverage']=st.mlProfile;
  if(st.manifestId)headers['X-Ground-Truth-Manifest']=st.manifestId;
  return headers;
 }
 function syncProfileRow(){
  const hybrid=typeof state!=='undefined'&&state.scanMode==='hybrid';
  q('ml-profile-row').classList.toggle('hidden',!hybrid);
 }

 // ---------------------------------------------------------------- live capture analysis
 function setBanner(text,kind){const b=q('coverage-banner');if(!text){b.classList.add('hidden');b.textContent='';return}b.textContent=text;b.dataset.kind=kind||'warning';b.classList.remove('hidden')}
 function grid(entries){
  const root=q('coverage-grid');root.replaceChildren();
  for(const [label,value] of entries){const g=document.createElement('div'),dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=value==null?'—':typeof value==='number'?nf(value):String(value);g.append(dt,dd);root.appendChild(g)}
 }
 function paint(stateName,headline,detail,fill,entries,banner){
  st.coverage=stateName;
  const chip=q('coverage-chip');chip.textContent=CHIP[stateName]||stateName.toUpperCase();chip.dataset.state=stateName;q('coverage-panel').dataset.state=stateName;
  set('coverage-headline',headline);set('coverage-detail',detail);
  q('coverage-fill').style.width=Math.max(0,Math.min(100,fill||0)).toFixed(1)+'%';
  grid(entries||[]);setBanner(banner&&banner.text,banner&&banner.kind);
 }
 function renderCoverage(summary,meta,ctx){
  const status=summary.ml_coverage_status||(summary.ml_invoked?'complete':'not_requested');
  const eligible=summary.ml_fields_eligible,evaluated=summary.ml_fields_evaluated,skipped=summary.ml_fields_skipped;
  const limits=meta.ml_work_limits||{};
  const pct=ratio(evaluated,eligible);
  const reasons=Object.entries(summary.ml_fields_skipped_by_reason||{}).map(([k,v])=>nf(v)+' '+(SKIP_LABEL[k]||k)).join(' · ');
  const entries=[['Extracted fields',summary.fields_extracted],['Eligible for ML',eligible],['Evaluated by ML',evaluated],['Skipped',skipped],
   ['Coverage',pct==null?'—':pct.toFixed(1)+'%'],['Excluded by policy',summary.ml_fields_excluded_by_policy],['Empty fields',summary.ml_fields_empty],
   ['Model batches',summary.ml_batches],['Model time',summary.ml_processing_time_seconds==null?null:Number(summary.ml_processing_time_seconds).toFixed(2)+' s'],
   ['ML coverage profile',limits.profile||ctx.profile||'—'],['Field / character budget',limits.max_fields?nf(limits.max_fields)+' / '+nf(limits.max_characters):'—'],['Skip reasons',reasons||'none']];
  if(status==='partial'){
   const text='ML coverage limit reached. Analysed '+nf(evaluated)+' of '+nf(eligible)+' eligible fields ('+(pct==null?'—':pct.toFixed(1))+'%). Results are incomplete.';
   paint('partial',text,'The model never saw the other '+nf(skipped)+' eligible fields, so findings from them are missing. Absence of a model finding is not evidence of absence. Select a larger ML coverage profile (now: '+(limits.profile||'standard')+') and scan again to cover more fields.',pct||0,entries,{text:text,kind:'warning'});
  }else if(status==='complete'){
   paint('complete','Analysed '+nf(evaluated)+' of '+nf(eligible)+' eligible fields (100%).','Every eligible extracted field was examined by the model. This describes coverage only, not the correctness of the predictions.',100,entries,null);
  }else if(status==='no_eligible_fields'){
   paint('no_eligible_fields','The model was requested but no extracted field was eligible for it.','Headers, credential-named fields, empty fields and unreadable text are excluded by policy. Zero model findings here is not a clean result.',0,entries,null);
  }else{
   paint('not_requested','Contextual inference was not requested for this scan.','Only the deterministic rules ran. Select AI-assisted hybrid to request the model.',0,entries,null);
  }
 }
 function onAttempt(status,message){
  const known={running:'running',failed:'failed',cancelled:'cancelled',canceled:'cancelled',unknown:'unknown'}[status]||'unknown';
  const headline={running:'Scan in progress — coverage is not known yet.',failed:'Scan failed — no complete result was published.',cancelled:'Scan cancelled — no result was published.',unknown:'Scan status unavailable.'}[known];
  paint(known,headline,message||'',0,[],known==='failed'?{text:'Contextual inference or the scan failed. Nothing from this attempt is reported as complete.',kind:'error'}:null);
  clearEvaluation(known==='running'&&st.manifestId?'A scan with the selected manifest is running; the evaluation will appear when it completes.':null);
 }

 // ---------------------------------------------------------------- ground truth
 function clearEvaluation(note){
  st.evalResult=null;q('gt-results').classList.add('hidden');
  const u=q('gt-unavailable');u.classList.remove('hidden');
  set('gt-unavailable',note||(st.manifestId?'A manifest is selected. Run a scan of the matching capture to evaluate it.':'File-specific accuracy unavailable: no verified ground-truth annotations provided.'));
 }
 function manifestInfo(m){
  if(!m){set('gt-manifest-info','No manifest selected. The manifest is applied to the next scan of the matching capture.');q('gt-clear').classList.add('hidden');return}
  set('gt-manifest-info',m.name+' · '+(KIND_LABEL[m.kind]||m.kind)+' · '+nf(m.fields)+' fields, '+nf(m.gold_spans)+' gold spans · SHA-256 '+String(m.sha256).slice(0,12)+'…');
  q('gt-clear').classList.remove('hidden');
 }
 async function uploadManifest(body,url){
  try{
   const response=await fetch(url||'/api/manifests',{method:'POST',headers:{'X-Dashboard-Token':token(),'Content-Type':'application/json'},body});
   const data=await response.json();
   if(!response.ok)throw Error(data.error||'Manifest rejected');
   st.manifestId=data.manifest_id;st.manifest=data.manifest;manifestInfo(data.manifest);clearEvaluation();
  }catch(e){fail(e instanceof Error?e.message:'Manifest rejected')}
 }
 function systemRow(body,name,system){
  const tr=document.createElement('tr'),m=system.micro;
  row(tr,name,'type-pill');row(tr,nf(system.scored_fields));row(tr,nf(m.tp));row(tr,nf(m.fp));row(tr,nf(m.fn));
  for(const key of ['precision','recall','f1']){const td=document.createElement('td');td.textContent=fmt(m[key]);if(m[key]==null)td.title=(m.undefined||[]).join('; ')||'undefined';td.className='val-redacted';tr.appendChild(td)}
  body.appendChild(tr);
 }
 function renderEvaluation(result,jobId){
  st.evalResult=result;st.evalJob=jobId;
  const banner=q('gt-status');
  if(result.status==='rejected'){
   q('gt-results').classList.add('hidden');q('gt-unavailable').classList.remove('hidden');
   set('gt-unavailable','File-specific accuracy unavailable: '+(result.reason||'the manifest could not be verified against this capture')+'.');return;
  }
  q('gt-unavailable').classList.add('hidden');q('gt-results').classList.remove('hidden');
  const a=result.alignment||{},unscored=Object.entries((result.systems.model_only||result.systems.rules_only).unscored_fields||{}).map(([k,v])=>nf(v)+' '+k.replace('skipped:','skipped — ').replaceAll('_',' ')).join(', ');
  if(result.status==='complete'){
   banner.dataset.kind='info';
   banner.textContent='Verified manifest · all '+nf(a.manifest_fields)+' annotated fields were aligned and scored. These metrics describe THIS capture and these annotations only.';
  }else{
   banner.dataset.kind='warning';
   banner.textContent='PARTIAL evaluation: '+nf(a.aligned)+' of '+nf(a.manifest_fields)+' annotated fields aligned'+(unscored?'; not scored by the model: '+unscored:'')+(a.unannotated_fields_in_listed_messages?'; '+nf(a.unannotated_fields_in_listed_messages)+' extracted fields were not annotated':'')+'. These are NOT full-file metrics.';
  }
  const body=q('gt-body');body.replaceChildren();
  const names={rules_only:'Rules only',model_only:'Model only (BiLSTM)',rules_plus_model:'Rules + model'};
  for(const [key,system] of Object.entries(result.systems))systemRow(body,names[key]||key,system);
  const labels=q('gt-labels'),errors=q('gt-errors'),alignment=q('gt-alignment');labels.replaceChildren();errors.replaceChildren();alignment.replaceChildren();
  const focus=result.systems.model_only||result.systems.rules_only;
  for(const [label,v] of Object.entries(focus.per_label))item(labels,label.replaceAll('_',' ')+': P '+fmt(v.precision)+' · R '+fmt(v.recall)+' · F1 '+fmt(v.f1)+' (TP '+v.tp+', FP '+v.fp+', FN '+v.fn+')');
  const eb=focus.error_breakdown||{};
  for(const kind of ['false_positive','false_negative'])for(const [type,count] of Object.entries(eb[kind]||{}))item(errors,kind.replace('_',' ')+' · '+type.replaceAll('_',' ')+': '+nf(count));
  if(!errors.children.length)item(errors,'No errors recorded.');
  const neg=focus.negative_fields||{};item(errors,'Negative fields with a false positive: '+nf(neg.with_false_positive)+' of '+nf(neg.scored));
  item(alignment,'Aligned '+nf(a.aligned)+' of '+nf(a.manifest_fields)+' annotated fields');
  for(const [k,v] of Object.entries(a.unaligned||{}))item(alignment,k.replaceAll('_',' ')+': '+nf(v));
  item(alignment,'Capture SHA-256 verified against the manifest');
  const m=result.manifest||{};
  set('gt-provenance',(KIND_LABEL[m.kind]||m.kind||'')+' · labels: '+String(m.label_source||'').replaceAll('_',' ')+' · manifest '+String(m.sha256||'').slice(0,12)+'… · model '+(result.model_version||'none')+' · '+(result.generated_at||''));
 }
 async function fetchEvaluation(jobId){
  try{
   const response=await fetch('/api/jobs/'+encodeURIComponent(jobId)+'/evaluation',{headers:{'X-Dashboard-Token':token()}});
   if(!response.ok)throw Error('Evaluation unavailable');
   renderEvaluation(await response.json(),jobId);
  }catch(e){clearEvaluation('File-specific accuracy unavailable: the evaluation could not be loaded.')}
 }

 // ---------------------------------------------------------------- hooks used by app.js
 function onResult(payload){
  const report=payload.report||{};
  renderCoverage(report.summary||{},report.metadata||{},{profile:payload.ml_profile});
  if(payload.evaluation_requested&&payload.job_id)fetchEvaluation(payload.job_id);else clearEvaluation(st.manifestId?'The last scan did not use the selected manifest. Run a scan of the matching capture to evaluate it.':null);
 }
 function onBenchmark(b){
  const pct=v=>typeof v==='number'?(v*100).toFixed(1)+'%':'—';
  const parts=(b.comparators||[]).map(c=>c.label+' — precision '+pct(c.precision)+', recall '+pct(c.recall)+', F1 '+pct(c.f1)+'. '+(c.note||''));
  set('benchmark-comparators',parts.length?parts.join('  ·  '):'Comparator rows unavailable.');
  if(b.target&&typeof b.target.f1==='number'){
   const node=q('benchmark-note');
   node.textContent=node.textContent+' Engineering target F1 '+pct(b.target.f1)+' on an independent set: '+(b.target.met?'met.':'not met.')+' '+(b.target.note||'');
  }
 }
 function inspect(f){
  const model=f.detector==='bilstm';
  set('inspect-span',model&&Number.isInteger(f.span_start)&&Number.isInteger(f.span_end)?'characters ['+f.span_start+', '+f.span_end+') of the field':'whole field value (rule match)');
  set('inspect-model',model?String(f.model_version||'version unreported')+' · field #'+(Number.isInteger(f.field_index)?f.field_index:'—'):'not applicable (rule)');
  set('inspect-quality',Array.isArray(f.input_quality)&&f.input_quality.length?f.input_quality.join(', ').replaceAll('_',' '):model?'none reported':'not applicable (rule)');
  set('inspect-coverage',model?(CHIP[st.coverage]||st.coverage):'not applicable (rule)');
 }
 function init(session){
  const select=q('ml-profile');
  select.disabled=!session.model_available;
  select.addEventListener('change',()=>{st.mlProfile=select.value});
  for(const input of document.querySelectorAll('input[name="scan-mode"]'))input.addEventListener('change',syncProfileRow);
  q('gt-file').addEventListener('change',async ev=>{
   const file=ev.target.files&&ev.target.files[0];ev.target.value='';
   if(!file)return;
   if(file.size>16*1048576){fail('Manifest is larger than 16 MiB');return}
   await uploadManifest(file);
  });
  q('gt-demo').addEventListener('click',()=>uploadManifest(null,'/api/manifests/showcase'));
  q('gt-clear').addEventListener('click',()=>{st.manifestId=null;st.manifest=null;manifestInfo(null);clearEvaluation()});
  q('gt-download').addEventListener('click',()=>{if(!st.evalJob)return;const a=document.createElement('a');a.href='/api/jobs/'+encodeURIComponent(st.evalJob)+'/evaluation?download=1';a.download='trace-evaluation.json';a.click()});
  syncProfileRow();
 }
 return {init,scanHeaders,onResult,onAttempt,onBenchmark,inspect,syncProfileRow,_state:st};
})();
