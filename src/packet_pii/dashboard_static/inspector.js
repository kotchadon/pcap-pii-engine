'use strict';
/* Universal inspector.

   One component inspects findings, HTTP conversations and connections:
   - a persistent pane on wide windows, a modal drawer on laptops and tablets, a sheet on phones;
   - a navigation stack per view, so opening the message behind a finding and pressing Back
     never loses the list position or the selection;
   - every request is tagged with a sequence number and the report epoch, so a late response
     can never paint evidence for an item the user has moved away from.

   Data comes only from the authenticated, read-only job APIs: /investigation and /conversations
   (indexed, value-free metadata) and the opt-in POST /content (unmasked source, gated by server
   retention and an explicit acknowledgement). Captured text is always written with textContent:
   nothing from a capture is parsed as markup, linked, framed or fetched, and revealed source is
   never stored. */
const TraceInspector=(()=>{
 const $i=id=>document.getElementById(id);
 const nf=n=>Number(n||0).toLocaleString('en-AU');
 const PAGE=25,TIMEOUT_MS=20000,MAX_SOURCE_CHARS=512*1024,MAX_LINES=5000,MIN_W=340,MAX_W=720;
 const INSPECTABLE=['findings','flows'];
 const st={epoch:0,seq:0,stacks:{findings:[],flows:[]},view:'overview',open:false,collapsed:false,mode:'pane',
  returnFocus:null,filled:null,contentSeq:0,sourceHost:null,width:420,seg:'conversations',inited:false,
  conv:{offset:0,total:0,loaded:false,seq:0,selected:null}};
 const stack=()=>st.stacks[INSPECTABLE.includes(st.view)?st.view:'findings'];

 // ------------------------------------------------------------------ small helpers
 function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!=null)n.textContent=String(text);return n}
 function button(label,cls,onClick){const b=el('button',cls||'btn btn-secondary btn-sm',label);b.type='button';if(onClick)b.addEventListener('click',onClick);return b}
 function token(){return typeof state!=='undefined'?state.token:null}
 function job(){return typeof state!=='undefined'?state.reportJobId:null}
 const typeName=t=>typeof typeLabel==='function'?typeLabel(t):String(t||'Unknown');
 const interval=(a,b)=>Number.isInteger(a)&&Number.isInteger(b)&&b>=a?'['+nf(a)+', '+nf(b)+')':'unavailable';
 const endpoint=ep=>ep&&ep.ip?ep.ip+':'+ep.port:'unknown';
 const kindOf=m=>m.message_type==='request'?'HTTP request':m.interim_response?'Interim HTTP response':'HTTP response';
 const messageOf=f=>f&&(f.evidence&&f.evidence.http_message_id||f.http_message_id)||null;
 const BASIS={directional_fifo_best_effort:'Matched to its partner by message order (best effort)',http2_stream_id:'Matched to its partner by HTTP/2 stream ID'};
 const GRANULARITY={exact_stream_range:'Exact bytes',transformed_source_range:'Decoded',message_level_only:'Message only',unavailable:'Not mapped'};
 const LIMITS={recorded_offsets_are_not_independently_reverified_capture_bytes:'Byte positions come from the analysis record; they were not re-read from the capture file.',
  detector_character_offsets_are_not_raw_byte_offsets:'Positions inside decoded text are not byte positions in the capture.',
  source_range_page_limit:'Only the first page of packet ranges is shown.',
  source_text_only_not_a_rendered_webpage:'This is the text of the response, not a rendered web page.',
  external_resources_not_fetched:'Images, scripts and other resources it refers to were not fetched.',
  text_decoding_may_replace_invalid_characters:'Characters that could not be decoded may have been replaced.',
  decoded_content_truncated_at_64_kib:'Only the first 64 KiB of the decoded body is shown.'};
 const humanLimit=x=>LIMITS[x]||String(x).replaceAll('_',' ');

 class RequestError extends Error{constructor(message,status){super(message);this.status=status}}
 function explain(e){
  const s=e&&e.status;
  if(s===403)return 'Your session has ended. Reload TRACE to continue.';
  if(s===404)return 'This analysis is no longer available. It may have expired. Run the analysis again to keep investigating.';
  if(s===400)return e.message&&e.message.startsWith('Content unavailable')?e.message:'Evidence for this item is not available.';
  if(s===-1)return 'The local server took too long to answer.';
  if(s===-2)return 'TRACE could not reach the local analysis server.';
  if(s===0)return 'Evidence is available for analyses run in this session.';
  return 'Evidence could not be loaded'+(s?' ('+s+')':'')+'.';
 }
 async function request(path,options={}){
  const id=job();if(!id)throw new RequestError('No completed analysis',0);
  const ctrl=typeof AbortController!=='undefined'?new AbortController():null;
  const timer=ctrl?setTimeout(()=>ctrl.abort(),TIMEOUT_MS):null;
  try{
   const r=await fetch('/api/jobs/'+encodeURIComponent(id)+'/'+path,{...options,...(ctrl?{signal:ctrl.signal}:{}),headers:{'X-Dashboard-Token':token(),...(options.headers||{})}});
   if(!r.ok){let msg='';try{msg=(await r.json()).error||''}catch{}throw new RequestError(msg,r.status)}
   return await r.json();
  }catch(e){
   if(e instanceof RequestError)throw e;
   if(e&&e.name==='AbortError')throw new RequestError('timeout',-1);
   throw new RequestError('network',-2);
  }finally{if(timer)clearTimeout(timer)}
 }
 function note(text,kind){const p=el('p','note-line'+(kind?' note-'+kind:''),text);return p}
 function loadingBox(text){const d=el('div','iv-loading');d.append(el('span','spinner'),el('span',null,text||'Loading evidence…'));d.setAttribute('role','status');return d}
 function errorBox(e,retry){
  const d=el('div','notice notice-error');d.setAttribute('role','alert');
  const t=el('div');t.append(el('strong',null,'Couldn’t load this'),el('p',null,explain(e)));d.append(t);
  if(retry&&e&&e.status!==404&&e.status!==0)d.append(button('Try again','btn btn-secondary btn-sm',retry));
  return d;
 }
 function facts(pairs){
  const dl=el('dl','facts');
  for(const [k,v,cls] of pairs){if(v==null||v==='')continue;const g=el('div');g.append(el('dt',null,k),el('dd',cls||null,v));dl.append(g)}
  return dl;
 }
 function section(title,...children){const s=el('section','iv-section');s.append(el('h3',null,title),...children.filter(Boolean));return s}
 function announce(text){const n=$i('insp-live');if(n)n.textContent=text}
 const alive=(seq,epoch)=>seq===st.seq&&epoch===st.epoch;

 // ------------------------------------------------------------------ presentation: pane, drawer or sheet
 const media=q=>typeof matchMedia==='function'&&matchMedia(q).matches;
 function computeMode(){return media('(min-width: 1180px)')?'pane':media('(max-width: 639px)')?'sheet':'drawer'}
 function applyLayout(){
  const insp=$i('inspector'),ws=$i('workspace');
  st.mode=computeMode();insp.dataset.mode=st.mode;
  const visible=INSPECTABLE.includes(st.view);
  const shown=st.mode==='pane'?visible&&!st.collapsed:visible&&st.open;
  const modal=shown&&st.mode!=='pane';
  insp.dataset.open=String(shown);
  ws.dataset.pane=st.mode==='pane'&&shown?'open':'closed';
  if(modal){insp.setAttribute('role','dialog');insp.setAttribute('aria-modal','true')}
  else{insp.removeAttribute('aria-modal');if(st.mode==='pane')insp.setAttribute('role','complementary');else insp.removeAttribute('role')}
  for(const node of [$i('sidebar'),document.querySelector('.topbar'),$i('main')])if(node)node.inert=modal;
  $i('insp-scrim').classList.toggle('hidden',!modal);
  $i('insp-close').setAttribute('aria-label',st.mode==='pane'?'Hide inspector':'Close inspector');
  $i('insp-resize').hidden=st.mode!=='pane';
 }
 function selectedRowButton(){
  const body=$i(st.view==='flows'?(st.seg==='connections'?'flows-body':'conv-body'):'findings-body');
  if(!body)return null;for(const row of body.children)if(row.classList.contains('selected')&&row.main)return row.main;return null;
 }
 function openPanel(){
  st.collapsed=false;
  if(st.mode==='pane'){applyLayout();return}
  if(!st.open){const a=document.activeElement;st.returnFocus=a&&a!==document.body?a:selectedRowButton()}
  st.open=true;applyLayout();
  const title=$i('insp-title');if(title&&title.focus)title.focus({preventScroll:true});
 }
 function close(restore=true){
  const wasOpen=st.open;st.open=false;if(st.mode==='pane')st.collapsed=true;
  clearSource();applyLayout();
  if(restore){const t=(wasOpen&&st.returnFocus&&st.returnFocus.isConnected)?st.returnFocus:selectedRowButton();if(t&&t.focus)t.focus({preventScroll:true})}
  st.returnFocus=null;
 }

 // ------------------------------------------------------------------ navigation stack
 function setHeader(kicker,title){$i('insp-kicker').textContent=kicker;$i('insp-title').textContent=title}
 function showOnly(id){for(const x of ['insp-empty','insp-finding','insp-dynamic'])$i(x).classList.toggle('hidden',x!==id)}
 function show(){
  st.seq++;clearSource();
  const s=stack(),top=s[s.length-1];
  $i('insp-back').hidden=s.length<2;
  $i('insp-body').scrollTop=0;
  if(!top){setHeader('Inspector','Nothing selected');showOnly('insp-empty');return}
  if(top.kind==='finding'){
   if(st.filled!==top.f&&typeof inspectFinding==='function'){inspectFinding(top.f,{restore:true});return}
   renderFinding(top);
  }else if(top.kind==='message')renderMessage(top);
  else if(top.kind==='connection')renderConnection(top);
  announce('Inspector: '+$i('insp-kicker').textContent+', '+$i('insp-title').textContent);
 }
 function push(entry){stack().push(entry);show();const t=$i('insp-title');if(t&&t.focus)t.focus({preventScroll:true})}
 function replaceTop(entry){const s=stack();s[s.length-1]=entry;show()}
 function back(){const s=stack();if(s.length<2)return;s.pop();show();const t=$i('insp-title');if(t&&t.focus)t.focus({preventScroll:true})}
 function setRoot(entry){const s=stack();s.length=0;s.push(entry);show()}

 // ------------------------------------------------------------------ finding view (static template filled by app.js)
 function openFinding(f,opts={}){
  st.filled=f;
  if(opts.restore){if(!stack().length)stack().push({kind:'finding',f});else{const s=stack();if(s[s.length-1].kind!=='finding')s.push({kind:'finding',f});else s[s.length-1]={kind:'finding',f}}show();return}
  const entry={kind:'finding',f};
  if(opts.push)push(entry);else setRoot(entry);
  if(opts.open)openPanel();else applyLayout();
 }
 function evidenceStatement(data){
  const f=data.selected_field,v=data.verification||{};
  const scope=!f?'The packets below support the whole message. Select a field to see the packets for that field alone.'
   :f.granularity==='exact_stream_range'?'The packets contain the whole field exactly as captured. TRACE does not mark the byte position of the detected value inside it.'
   :f.granularity==='transformed_source_range'?'The field was decoded (for example from JSON or URL encoding), so the packets support the field but cannot show the value byte for byte.'
   :'This field could not be mapped precisely. The packets support the message as a whole.';
  const coverage=v.coverage_complete?'Recorded packet ranges cover the whole selection.':'Part of the selection has no recorded packet range, so this evidence is incomplete.';
  return [scope,coverage,!!v.coverage_complete];
 }
 function packetChips(sources,limit){
  const ul=el('ul','chips');
  for(const s of sources.slice(0,limit)){const li=el('li','chip chip-mono',s.frame_id+' · file bytes '+interval(s.file_start,s.file_end));ul.append(li)}
  return ul;
 }
 async function renderFinding(entry){
  const f=entry.f;setHeader('Inspector','Finding');showOnly('insp-finding');
  const host=$i('fi-support');host.replaceChildren();
  const mid=messageOf(f);
  if(!mid||!job()){host.append(note(!job()?'Evidence details are available for analyses run in this session.':'This finding is not linked to an HTTP message, so no message evidence is available.'));return}
  const ids=(f.evidence&&Array.isArray(f.evidence.field_ids))?f.evidence.field_ids:[];
  const fieldId=ids.length===1?ids[0]:'';
  host.append(loadingBox('Loading the message and packets behind this finding…'));
  const seq=st.seq,epoch=st.epoch;
  try{
   const data=await request('investigation?'+new URLSearchParams({message_id:mid,field_id:fieldId,limit:String(PAGE)}));
   if(!alive(seq,epoch))return;
   const m=data.message;host.replaceChildren();
   const roleText=m.message_type==='request'?'sent by the client '+endpoint(m.client)+' to the server '+endpoint(m.server):'sent by the server '+endpoint(m.server)+' to the client '+endpoint(m.client);
   $i('fi-where').textContent='In the field '+String(f.location||'(unknown)')+' of an '+kindOf(m)+' '+roleText+'.';
   const card=el('div','msg-card');
   const head=el('div','msg-card-head');head.append(el('span','msg-kind',kindOf(m)),el('code','msg-line',m.start_line||'Start line unavailable'));
   card.append(head);
   if(m.reconstruction_complete===false)card.append(note('Some of this message is missing, so it may be incomplete.','warn'));
   card.append(button('Open this '+(m.message_type==='request'?'request':'response'),'btn btn-primary btn-sm',()=>push({kind:'message',id:mid,fieldId,from:f})));
   host.append(card);
   const [scope,coverage,complete]=evidenceStatement(data);
   host.append(el('p','prose',scope),note(coverage,complete?'ok':'warn'));
   if(ids.length>1)host.append(note('This rule matched '+ids.length+' fields with the same name, so the evidence covers the whole message.'));
   if(data.source_ranges&&data.source_ranges.length){host.append(el('p','iv-label','Supported by '+nf(data.source_ranges.length)+' packet range'+(data.source_ranges.length===1?'':'s')+(data.source_ranges_truncated?' (more not shown)':'')),packetChips(data.source_ranges,6))}
   else host.append(note('No recorded packet range is available for this selection. TRACE does not infer one.','warn'));
  }catch(e){if(alive(seq,epoch)){host.replaceChildren(errorBox(e,()=>show()))}}
 }

 // ------------------------------------------------------------------ message view
 async function renderMessage(entry){
  showOnly('insp-dynamic');const root=$i('insp-dynamic');root.replaceChildren(loadingBox('Loading the HTTP message…'));
  setHeader('HTTP message','Loading…');
  const seq=st.seq,epoch=st.epoch;
  try{
   const data=await request('investigation?'+new URLSearchParams({message_id:entry.id,field_id:entry.fieldId||'',field_offset:String(entry.fieldOffset||0),finding_offset:String(entry.findingOffset||0),limit:String(PAGE)}));
   if(!alive(seq,epoch))return;
   paintMessage(root,entry,data);
   announce('Inspector: '+$i('insp-kicker').textContent+', '+$i('insp-title').textContent);
  }catch(e){if(alive(seq,epoch)){setHeader('HTTP message','Unavailable');root.replaceChildren(errorBox(e,()=>show()))}}
 }
 function paintMessage(root,entry,data){
  const m=data.message;root.replaceChildren();
  setHeader(kindOf(m),m.start_line||m.http_message_id);
  // Request / response switcher: the same conversation, without leaving the inspector.
  const others=(data.transaction&&data.transaction.messages)||[];
  if(others.length>1){
   const sw=el('div','switcher');sw.setAttribute('role','group');sw.setAttribute('aria-label','Messages in this conversation');
   for(const o of others){const label=(o.message_type==='request'?'Request':o.interim_response?'Interim':'Response')+(o.method?' · '+o.method:o.status?' · '+o.status:'');
    const b=button(label,'switch-btn',()=>{if(o.http_message_id!==m.http_message_id)replaceTop({kind:'message',id:o.http_message_id,fieldId:'',from:entry.from})});
    b.setAttribute('aria-pressed',String(o.http_message_id===m.http_message_id));sw.append(b)}
   root.append(sw);
  }else root.append(note(m.message_type==='request'?'No response was observed for this request. TRACE does not create one.':'No request was observed for this response.'));
  if(data.transaction&&data.transaction.messages_truncated)root.append(note('This conversation has more messages than can be listed here.','warn'));
  if(m.reconstruction_complete===false)root.append(note('Some of this message is missing, so it may be incomplete.','warn'));
  root.append(section('Exchange',facts([
   ['Between','Client '+endpoint(m.client)+' → server '+endpoint(m.server),'mono-soft'],
   ['This message',m.message_type==='request'?'Sent by the client':'Sent by the server'],
   ['Captured at',Number.isFinite(m.timestamp)?new Date(m.timestamp*1000).toLocaleString():null],
   ['Partner',m.pairing_status==='unpaired'?'No matching message observed':BASIS[m.association_basis]||m.pairing_status],
   ['Protocol',m.protocol==='h2'?'HTTP/2':'HTTP/1.x']])));
  // Findings in this message
  const fp=data.findings||{items:[],total:0,offset:0};
  const flist=el('ul','finding-list');
  for(const f of fp.items){const li=el('li'),b=el('button','finding-btn');b.type='button';
   b.append(el('span','fb-type',typeName(f.pii_type)),el('span','fb-value mono',f.value||'[masked]'),el('span','fb-det',f.detector==='bilstm'?'Model':'Rule'));
   b.setAttribute('aria-label','Inspect '+typeName(f.pii_type)+' '+(f.value||'masked')+' in '+String(f.location||'field'));
   b.addEventListener('click',()=>{if(typeof inspectFinding==='function')inspectFinding(f,{open:true,push:true})});li.append(b);flist.append(li)}
  root.append(section('Personal information in this message',fp.items.length?flist:note('No findings in this message'+(entry.fieldId?' for the selected field.':'.')),pager(fp,o=>replaceTop({...entry,findingOffset:o}))));
  // Fields
  const fields=[...((data.fields&&data.fields.items)||[])];
  if(data.selected_field&&!fields.some(x=>x.field_id===data.selected_field.field_id))fields.unshift(data.selected_field);
  const fl=el('ul','field-list');
  for(const x of fields){const li=el('li'),b=el('button','field-btn');b.type='button';
   b.append(el('span','fd-index mono','#'+x.field_index),el('span','fd-loc',x.location||x.source_category||'field'),el('span','fd-map',GRANULARITY[x.granularity]||x.granularity||''));
   b.setAttribute('aria-pressed',String(x.field_id===entry.fieldId));
   b.addEventListener('click',()=>replaceTop({...entry,fieldId:x.field_id===entry.fieldId?'':x.field_id,findingOffset:0}));li.append(b);fl.append(li)}
  root.append(section('Fields',el('p','hint','Values stay hidden. Select a field to see the packets that carried it.'),fields.length?fl:note('No fields were extracted from this message.'),pager(data.fields||{items:[],total:0,offset:0},o=>replaceTop({...entry,fieldOffset:o}))));
  // Packets
  const [scope,coverage,complete]=evidenceStatement(data);
  const sel=data.selected_field;
  root.append(section(sel?'Packets for field #'+sel.field_index:'Packets for this message',el('p','prose',scope),note(coverage,complete?'ok':'warn'),packetTable(data.source_ranges||[]),data.source_ranges_truncated?note('Only the first page of packet ranges is shown.','warn'):null));
  if(m.message_type==='response')root.append(sourceSection(m,data));
  // Technical details
  const more=el('details','iv-more');more.append(el('summary',null,'Technical details'));
  const s=data.stream||{};
  more.append(facts([['Message ID',m.http_message_id,'mono'],['Connection',m.flow_id+(m.session!=null?' · session '+m.session:''),'mono'],['Stream',m.stream_id,'mono'],
   ['Stream bytes',interval(m.stream_start,m.stream_end),'mono'],
   ['Headers present',Array.isArray(m.header_names)?(m.header_names.join(', ')||'none recognised')+(m.unknown_header_count?' + '+m.unknown_header_count+' other':'')+' · values withheld':null],
   ['Connection flags seen','start '+(s.syn_observed?'yes':'no')+' · close '+(s.fin_observed?'yes':'no')+' · reset '+(s.rst_observed?'yes':'no')],
   ['Stream diagnostics',(s.diagnostics||[]).map(humanLimit).join('; ')||'None reported'],
   ['Connection diagnostics',data.flow&&Array.isArray(data.flow.http_diagnostics)&&data.flow.http_diagnostics.length?data.flow.http_diagnostics.slice(0,20).map(d=>typeof d==='string'?d:d.reason||'unspecified').join('; '):null],
   ['Message limitations',(m.limitations||[]).map(humanLimit).join('; ')||null],
   ['Capture SHA-256',data.capture_identity&&data.capture_identity.capture_sha256,'mono'],
   ['Evidence status',(data.verification&&data.verification.status||'').replaceAll('_',' ')]]));
  const lims=el('ul','plain-list');for(const x of data.limitations||[])lims.append(el('li',null,humanLimit(x)));more.append(lims);
  root.append(more);
 }
 function pager(page,go){
  if(!page||page.total<=page.items.length)return null;
  const d=el('div','mini-pager');const a=page.offset||0;
  const prev=button('Previous','btn btn-ghost btn-sm',()=>go(Math.max(0,a-PAGE)));prev.disabled=a===0;
  const next=button('Next','btn btn-ghost btn-sm',()=>go(a+PAGE));next.disabled=a+page.items.length>=page.total;
  d.append(prev,el('span',null,nf(a+1)+'–'+nf(a+page.items.length)+' of '+nf(page.total)),next);return d;
 }
 function packetTable(sources){
  if(!sources.length)return note('No recorded packet range is available. TRACE does not infer packet numbers.','warn');
  const wrap=el('div','x-scroll'),t=el('table','x-table'),head=el('thead'),hr=el('tr');
  for(const h of ['Packet','File bytes','Stream bytes'])hr.append(el('th',null,h));head.append(hr);
  const body=el('tbody');
  for(const s of sources){
   const tr=el('tr'),td=el('td'),b=el('button','link-btn mono',s.frame_id);b.type='button';b.setAttribute('aria-expanded','false');
   const detail=el('tr','x-detail hidden'),dtd=el('td');dtd.colSpan=3;const p=s.packet||{};
   dtd.append(facts([['Within frame',interval(s.frame_start,s.frame_end),'mono'],['TCP sequence',interval(s.tcp_seq_start,s.tcp_seq_end),'mono'],['Captured / on wire',(p.captured_length??'?')+' / '+(p.wire_length??'?')+' bytes'],['Record offset',p.record_offset!=null?nf(p.record_offset):null],['TCP flags',p.tcp_datagram&&p.tcp_datagram.flags!=null?String(p.tcp_datagram.flags):null]]));
   detail.append(dtd);
   b.addEventListener('click',()=>{const open=detail.classList.contains('hidden');detail.classList.toggle('hidden',!open);b.setAttribute('aria-expanded',String(open))});
   td.append(b);tr.append(td,el('td','mono',interval(s.file_start,s.file_end)),el('td','mono',interval(s.stream_start,s.stream_end)));body.append(tr,detail);
  }
  t.append(head,body);wrap.append(t);return wrap;
 }

 // ------------------------------------------------------------------ opt-in response source (inert text)
 function clearSource(){st.contentSeq++;if(st.sourceHost){st.sourceHost.replaceChildren();st.sourceHost=null}}
 function sourceSection(m,data){
  const sec=el('section','iv-section source-section');sec.append(el('h3',null,'Original response'));
  if(!data.content_available){sec.append(note('Viewing the original response is turned off. To allow it, start TRACE with --retain-capture-for-inspection; the capture is then kept until this analysis expires.'));return sec}
  if(m.protocol==='h2'){sec.append(note('Viewing the original text is not supported for HTTP/2 responses yet.'));return sec}
  sec.append(el('p','prose','The original response can contain unmasked personal information. It is shown as plain text: nothing in it runs, loads or links anywhere. TRACE re-checks the capture’s fingerprint first.'));
  const id='ack-'+String(m.http_message_id).replace(/[^A-Za-z0-9_-]/g,'');
  const label=el('label','ack'),box=el('input');box.type='checkbox';box.id=id;
  label.append(box,el('span',null,'I am authorised to view this response and understand it may contain sensitive values.'));
  const reveal=button('Show response source','btn btn-secondary btn-sm');reveal.disabled=true;
  const status=el('p','hint');status.setAttribute('role','status');status.textContent='The source is hidden.';
  const host=el('div','source-host');
  box.addEventListener('change',()=>{reveal.disabled=!box.checked});
  reveal.addEventListener('click',async()=>{
   if(!box.checked)return;
   clearSource();st.sourceHost=host;const mine=++st.contentSeq,seq=st.seq,epoch=st.epoch;
   reveal.disabled=true;status.textContent='Checking the capture and recovering the response…';
   try{
    const result=await request('content',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message_id:m.http_message_id,acknowledge_sensitive_content:true})});
    if(mine!==st.contentSeq||!alive(seq,epoch))return;
    const hide=button('Hide source','btn btn-ghost btn-sm',()=>{clearSource();box.checked=false;reveal.disabled=true;status.textContent='The source is hidden.'});
    const view=el('div','source-view');view.append(sourceViewer(result.text,result.is_html,result.content_type));
    const parts=[];
    if(result.is_html){
     // Two views of the same authorised response: literal source, or the server's inert structure/text projection.
     const sw=el('div','switcher');sw.setAttribute('role','group');sw.setAttribute('aria-label','How to show this response');
     const src=button('Source','switch-btn'),pg=button('Page view','switch-btn');src.setAttribute('aria-pressed','true');pg.setAttribute('aria-pressed','false');
     let projection=null;
     src.addEventListener('click',()=>{if(mine!==st.contentSeq)return;src.setAttribute('aria-pressed','true');pg.setAttribute('aria-pressed','false');view.replaceChildren(sourceViewer(result.text,true,result.content_type))});
     pg.addEventListener('click',async()=>{
      if(mine!==st.contentSeq)return;src.setAttribute('aria-pressed','false');pg.setAttribute('aria-pressed','true');
      if(projection){view.replaceChildren(pageView(projection));return}
      view.replaceChildren(loadingBox('Building an inert view of the page text…'));
      try{
       const r=await request('content',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message_id:m.http_message_id,acknowledge_sensitive_content:true,representation:'static'})});
       if(mine!==st.contentSeq||!alive(seq,epoch))return;
       projection=r.static_representation;
       if(pg.getAttribute('aria-pressed')==='true')view.replaceChildren(pageView(projection));
      }catch(e){if(mine===st.contentSeq&&alive(seq,epoch))view.replaceChildren(note(explain(e),'warn'))}
     });
     sw.append(src,pg);parts.push(sw);
    }
    host.replaceChildren(...parts,view,hide);
    status.textContent=(result.is_html?'HTML source':'Response text')+(result.status==='partial'?' · partial':'')+' · capture fingerprint re-checked (SHA-256 '+String(result.capture_sha256||'').slice(0,12)+'…). '+(result.limitations||[]).map(humanLimit).join(' ');
   }catch(e){if(mine===st.contentSeq&&alive(seq,epoch)){status.textContent=explain(e);reveal.disabled=!box.checked}}
  });
  sec.append(label,reveal,status,host);return sec;
 }
 function tokenize(line){
  const out=[],re=/<!--.*?(?:-->|$)|<\/?[A-Za-z!?][^>]*>?|[^<]+|</g;let m;
  while((m=re.exec(line))){const t=m[0];out.push({text:t,cls:t.startsWith('<!--')?'tok-comment':t[0]==='<'&&t.length>1?'tok-tag':null})}
  return out;
 }
 // Inert page view: the server's allowlisted {tag,children} tree. Elements are created without attributes,
 // so nothing can run, load, link or navigate. Unknown tags are flattened to their text.
 const PAGE_TAGS=new Set(('p div section article header footer main aside blockquote h1 h2 h3 h4 h5 h6 ul ol li pre code em strong b i u s br hr '+
  'table thead tbody tfoot tr th td caption dl dt dd span address figure figcaption').split(' '));
 const PAGE_LIMITS={projection_node_or_depth_limit:'Only part of the page could be shown.',lossy_structure_and_text_not_original_browser_layout:'This shows the page’s text and basic structure, not its original appearance.',
  all_attributes_css_scripts_and_resource_references_omitted:'Scripts, styles, links, images and all other resources are left out.',malformed_html_uses_python_parser_not_browser_dom_rules:'Malformed HTML may be arranged differently from a browser.'};
 function pageView(projection){
  const wrap=el('div','page-wrap');
  if(!projection||projection.representation!=='inert_structure_text_v1'||!Array.isArray(projection.nodes)){wrap.append(note('This version of the page view is not supported.','warn'));return wrap}
  const doc=el('div','page-view');doc.setAttribute('role','document');doc.setAttribute('aria-label','Inert view of the captured page text');
  let count=0;
  const build=(node,parent,depth)=>{
   if(count>=4096||depth>64)return;count++;
   if(typeof node==='string'){parent.append(typeof document.createTextNode==='function'?document.createTextNode(node):el('span',null,node));return}
   if(!node||typeof node!=='object'||!Array.isArray(node.children))return;
   const target=PAGE_TAGS.has(node.tag)?document.createElement(node.tag):parent;
   for(const c of node.children)build(c,target,depth+1);
   if(target!==parent)parent.append(target);
  };
  for(const n of projection.nodes)build(n,doc,0);
  const omitted=Object.entries(projection.omitted_elements||{}).map(([k,v])=>nf(v)+' '+k).join(', ');
  const head=el('div','src-toolbar');head.append(el('span','chip chip-accent','Page view'),el('span','chip chip-warn','Unmasked'),el('span',null,'Text and structure only'));
  wrap.append(head,doc);
  if(projection.source_status!=='recovered'||projection.projection_truncated)wrap.append(note('The response or its page view is incomplete.','warn'));
  wrap.append(note('Left out: '+(omitted||'nothing')+'; '+nf(projection.attributes_discarded)+' attributes discarded. No resources were fetched. '+(projection.limitations||[]).map(x=>PAGE_LIMITS[x]||humanLimit(x)).join(' ')));
  return wrap;
 }
 function sourceViewer(text,isHtml,mediaType){
  const box=el('div','src-viewer'),bar=el('div','src-toolbar');
  let body=String(text||''),cut=false;
  if(body.length>MAX_SOURCE_CHARS){body=body.slice(0,MAX_SOURCE_CHARS);cut=true}
  const lines=body.split(/\r\n|\r|\n/);if(lines.length>MAX_LINES){lines.length=MAX_LINES;cut=true}
  bar.append(el('span','chip chip-accent',isHtml?'HTML source':'Response text'),el('span','chip chip-warn','Unmasked'),el('span',null,(mediaType?String(mediaType).slice(0,60)+' · ':'')+nf(lines.length)+' lines'+(cut?' · truncated':'')));
  const pre=el('pre','src-code'),code=el('code');pre.tabIndex=0;pre.setAttribute('aria-label',isHtml?'HTML source shown as plain text':'Response text');
  for(const line of lines){const ln=el('span','src-line');for(const t of tokenize(line))ln.append(el('span',t.cls,t.text));code.append(ln)}
  pre.append(code);
  const wrap=button('Wrap lines','btn btn-ghost btn-sm',()=>{const on=!pre.classList.contains('wrap');pre.classList.toggle('wrap',on);wrap.setAttribute('aria-pressed',String(on))});wrap.setAttribute('aria-pressed','false');
  bar.append(wrap);box.append(bar,pre);
  if(cut)box.append(note('Only part of the text is shown.','warn'));
  return box;
 }

 // ------------------------------------------------------------------ connection view
 function renderConnection(entry){
  const f=entry.flow,ends=f.endpoints||[];const a=endpoint(ends[0]),b=endpoint(ends[1]);
  setHeader('Connection',a+' ↔ '+b);showOnly('insp-dynamic');const root=$i('insp-dynamic');root.replaceChildren();
  if(Number(f.stream_gaps)>0)root.append(note('Some packets were missing in this connection, so its conversations may be incomplete.','warn'));
  root.append(section('Summary',facts([['Endpoints',a+' ↔ '+b,'mono-soft'],['Packets',nf(f.packets)],['HTTP messages',nf(f.http_messages)],['Conversations',nf(f.http_transactions)],
   ['Requests without a response',f.unpaired_requests!=null?nf(f.unpaired_requests):null],['Responses without a request',f.unpaired_responses!=null?nf(f.unpaired_responses):null],
   ['Gaps in the captured data',nf(f.stream_gaps)],['Unfinished HTTP messages',f.unterminated_http_messages!=null?nf(f.unterminated_http_messages):null]])),
   el('p','hint','Which endpoint acted as client or server is shown in each conversation under Conversations.'));
  if(Array.isArray(f.http_diagnostics)&&f.http_diagnostics.length){const ul=el('ul','plain-list');for(const d of f.http_diagnostics.slice(0,20))ul.append(el('li',null,typeof d==='string'?d.replaceAll('_',' '):String(d.reason||'unspecified').replaceAll('_',' ')));root.append(section('Reconstruction notes',ul))}
  const more=el('details','iv-more');more.append(el('summary',null,'Technical details'),facts([['Connection ID',f.flow_id,'mono']]));root.append(more);
 }
 function openConnection(flow,opts={}){setRoot({kind:'connection',flow});if(opts.open)openPanel();else applyLayout()}
 function openMessage(id,opts={}){const entry={kind:'message',id,fieldId:opts.fieldId||''};if(opts.push)push(entry);else setRoot(entry);if(opts.open)openPanel();else applyLayout()}

 // ------------------------------------------------------------------ conversations list (Traffic)
 function convEmpty(text){const body=$i('conv-body');body.replaceChildren();const tr=el('tr'),td=el('td','table-empty',text);td.colSpan=3;tr.append(td);body.append(tr)}
 async function loadConversations(offset){
  if(!job()){convEmpty('Conversations are available for analyses run in this session.');return}
  const seq=++st.conv.seq,epoch=st.epoch;st.conv.loaded=true;
  convEmpty('Loading conversations…');
  try{
   const data=await request('conversations?'+new URLSearchParams({offset:String(offset),limit:String(PAGE)}));
   if(seq!==st.conv.seq||epoch!==st.epoch)return;
   st.conv.offset=data.offset;st.conv.total=data.total;paintConversations(data);
  }catch(e){if(seq===st.conv.seq&&epoch===st.epoch){st.conv.loaded=false;convEmpty(explain(e))}}
 }
 function paintConversations(data){
  const body=$i('conv-body');body.replaceChildren();
  $i('conv-total').textContent=nf(data.total);
  if(!data.items.length)convEmpty('No HTTP conversations were rebuilt from this capture. Encrypted and unsupported traffic is not decoded.');
  for(const tx of data.items){
   const msgs=tx.messages||[],req=msgs.find(m=>m.message_type==='request'),resps=msgs.filter(m=>m.message_type==='response');
   const final=resps.filter(m=>!m.interim_response).pop()||resps[resps.length-1];const target=req||final||msgs[0];if(!target)continue;
   const tr=el('tr');tr.dataset.tx=tx.transaction_id;if(tx.transaction_id===st.conv.selected)tr.classList.add('selected');
   const first=el('td'),main=el('button','row-main');main.type='button';
   main.append(el('span','row-title mono',req?req.start_line:'No request observed'),el('span','row-sub',tx.flow_id||''));
   main.setAttribute('aria-label',(req?req.start_line:'Response without an observed request')+', '+(final?'response '+final.status:'no response observed')+'. Inspect.');
   first.append(main);tr.main=main;
   const resp=el('td');resp.append(el('span',final?'status-code'+(final.status>=400?' status-err':''):'muted',final?String(final.status):'No response'));
   if(resps.length>1)resp.append(el('span','cell-sub',nf(resps.length)+' responses'));
   const ep=target.client&&target.server?endpoint(target.client)+' → '+endpoint(target.server):'—';
   tr.append(first,resp,el('td','mono-soft',ep));
   const select=open=>{st.conv.selected=tx.transaction_id;for(const row of body.children){row.classList.toggle('selected',row===tr);if(row.main)row.main.setAttribute('aria-current',String(row===tr))}openMessage(target.http_message_id,{open})};
   tr.select=select;main.addEventListener('click',ev=>{ev.stopPropagation();select(true)});tr.addEventListener('click',()=>select(true));
   body.append(tr);
  }
  const a=data.offset||0;$i('conv-page').textContent=data.items.length?nf(a+1)+'–'+nf(a+data.items.length)+' of '+nf(data.total):'0 of '+nf(data.total);
  $i('conv-prev').disabled=a===0;$i('conv-next').disabled=a+data.items.length>=data.total;
 }
 function setSegment(name,focus){
  st.seg=name==='connections'?'connections':'conversations';
  for(const [tab,panel,key] of [['seg-conversations','panel-conversations','conversations'],['seg-connections','panel-connections','connections']]){
   const on=st.seg===key,t=$i(tab);t.setAttribute('aria-selected',String(on));t.tabIndex=on?0:-1;$i(panel).hidden=!on;if(on&&focus)t.focus();
  }
  try{localStorage.setItem('trace-traffic-segment',st.seg)}catch{}
  if(st.seg==='conversations'&&!st.conv.loaded&&st.view==='flows')loadConversations(0);
 }

 // ------------------------------------------------------------------ keyboard: move through any list
 function bindRowKeys(body){
  body.addEventListener('keydown',ev=>{
   const step={ArrowDown:1,j:1,ArrowUp:-1,k:-1}[ev.key];
   if(step==null&&ev.key!=='Home'&&ev.key!=='End')return;
   const btn=ev.target.closest&&ev.target.closest('.row-main');if(!btn)return;
   const rows=[...body.children].filter(r=>r.main);const i=rows.findIndex(r=>r.main===btn);
   const n=ev.key==='Home'?0:ev.key==='End'?rows.length-1:i+step;if(n<0||n>=rows.length)return;
   ev.preventDefault();const row=rows[n];row.main.focus();if(row.scrollIntoView)row.scrollIntoView({block:'nearest'});
   if(st.mode==='pane'&&row.select)row.select(false);   // the pane follows the selection; the drawer waits for Enter
  });
 }

 // ------------------------------------------------------------------ resizing the pane
 function setWidth(w,save){
  const max=Math.min(MAX_W,Math.max(MIN_W,(window.innerWidth||1440)-560));
  st.width=Math.round(Math.min(max,Math.max(MIN_W,w)));
  $i('workspace').style.setProperty('--insp-w',st.width+'px');$i('insp-resize').setAttribute('aria-valuenow',String(st.width));
  if(save)try{localStorage.setItem('trace-inspector-width',String(st.width))}catch{}
 }
 function bindResize(){
  const h=$i('insp-resize');let dragging=false;
  h.addEventListener('pointerdown',ev=>{dragging=true;h.setPointerCapture(ev.pointerId);document.body.classList.add('resizing')});
  h.addEventListener('pointermove',ev=>{if(dragging)setWidth(window.innerWidth-ev.clientX,false)});
  const end=()=>{if(!dragging)return;dragging=false;document.body.classList.remove('resizing');setWidth(st.width,true)};
  h.addEventListener('pointerup',end);h.addEventListener('pointercancel',end);
  h.addEventListener('keydown',ev=>{if(ev.key==='ArrowLeft'){ev.preventDefault();setWidth(st.width+16,true)}else if(ev.key==='ArrowRight'){ev.preventDefault();setWidth(st.width-16,true)}});
 }

 // ------------------------------------------------------------------ hooks used by app.js
 function onView(name){
  const prev=st.view;st.view=name;
  if(!INSPECTABLE.includes(name)){st.open=false;clearSource();applyLayout();return}   // revealed source never lingers out of view
  if(prev!==name){st.open=false;show()}
  applyLayout();
  if(name==='flows'&&st.seg==='conversations'&&!st.conv.loaded)loadConversations(0);
 }
 function onResult(){
  st.epoch++;st.seq++;st.stacks={findings:[],flows:[]};st.filled=null;st.open=false;clearSource();
  st.conv={offset:0,total:0,loaded:false,seq:st.conv.seq+1,selected:null};
  $i('conv-total').textContent='';convEmpty('Open Traffic to load conversations.');$i('conv-page').textContent='—';$i('conv-prev').disabled=true;$i('conv-next').disabled=true;
  show();applyLayout();
  if(st.view==='flows'&&st.seg==='conversations')loadConversations(0);
 }
 function init(){
  if(st.inited)return;st.inited=true;
  $i('insp-back').addEventListener('click',back);
  $i('insp-close').addEventListener('click',()=>close(true));
  $i('insp-scrim').addEventListener('click',()=>close(true));
  $i('conv-prev').addEventListener('click',()=>loadConversations(Math.max(0,st.conv.offset-PAGE)));
  $i('conv-next').addEventListener('click',()=>loadConversations(st.conv.offset+PAGE));
  const tabs=[$i('seg-conversations'),$i('seg-connections')];
  tabs[0].addEventListener('click',()=>setSegment('conversations'));tabs[1].addEventListener('click',()=>setSegment('connections'));
  for(const t of tabs)t.addEventListener('keydown',ev=>{if(ev.key==='ArrowRight'||ev.key==='ArrowLeft'){ev.preventDefault();setSegment(st.seg==='conversations'?'connections':'conversations',true)}});
  for(const id of ['findings-body','conv-body','flows-body'])bindRowKeys($i(id));
  bindResize();
  document.addEventListener('keydown',ev=>{
   if(ev.key!=='Escape')return;
   if(st.open&&st.mode!=='pane'){ev.preventDefault();close(true);return}
   if(st.mode==='pane'&&$i('inspector').contains(document.activeElement)){const t=selectedRowButton();if(t){ev.preventDefault();t.focus()}}
  });
  if(typeof matchMedia==='function')for(const q of ['(min-width: 1180px)','(max-width: 639px)'])matchMedia(q).addEventListener('change',()=>{if(computeMode()==='pane')st.open=false;applyLayout()});
  let saved=null,seg=null;try{saved=Number(localStorage.getItem('trace-inspector-width'));seg=localStorage.getItem('trace-traffic-segment')}catch{}
  setWidth(saved||420,false);setSegment(seg||'conversations');
  applyLayout();
 }
 if(typeof document!=='undefined'&&typeof document.addEventListener==='function'){
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
 }
 return {init,openFinding,openMessage,openConnection,onView,onResult,close,back,tokenize,sourceViewer,pageView,_state:st};
})();
