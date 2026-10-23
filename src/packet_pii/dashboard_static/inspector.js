'use strict';
/* Evidence inspector tabs, HTTP exchange viewer and HTTP message list.

   Data comes only from the authenticated, read-only job evidence pages
   (http_evidence, field_evidence, stream_evidence). Captured content is untrusted:
   everything is written with textContent. Nothing from a capture is parsed as
   markup, turned into a link, framed or fetched.

   Body content contract (not yet provided by the engine): an http_evidence row may
   carry `content: {redacted: true, text: string, media_type?, truncated?, original_bytes?}`.
   The viewer shows it only when the server states `redacted === true`. Without it, the
   viewer says the body is unavailable; it never reconstructs or guesses content. */
const TraceInspector=(()=>{
 const q=id=>document.getElementById(id);
 const nf=n=>Number(n||0).toLocaleString('en-AU');
 const PAGE=100,MAX_FIELDS=32,MAX_STREAM_PAGES=5,MAX_SOURCE_CHARS=512*1024,MAX_LINES=5000,MAX_FRAMES=40;
 const st={view:'overview',finding:null,findingMessage:null,findingLoaded:null,fEpoch:0,mEpoch:0,listEpoch:0,
  msgOffset:0,msgTotal:0,msgFlow:null,openMessage:null};

 const GRANULARITY={exact_stream_range:'Exact',transformed_source_range:'Decoded',
  message_level_only:'Message only',unavailable:'Not mapped'};
 const PAIRING={paired_best_effort:'Matched by message order (best effort)',paired_by_http2_stream_id:'Matched by HTTP/2 stream ID',unpaired:'No matching message observed'};

 function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!=null)n.textContent=String(text);return n}
 function job(){return typeof state!=='undefined'?state.reportJobId:null}
 function token(){return typeof state!=='undefined'?state.token:null}
 function verified(){
  const c=typeof state!=='undefined'&&state.report?state.report.capture_evidence:null;
  return !!c&&c.identity_status==='verified_read'&&/^[0-9a-f]{64}$/i.test(c.capture_sha256||'');
 }
 const range=(a,b)=>Number.isInteger(a)&&Number.isInteger(b)&&b>=a?'['+nf(a)+', '+nf(b)+')':'unavailable';
 const isResponse=m=>/^HTTP\//.test(String(m&&m.start_line||''));
 const statusOf=m=>{const x=/^HTTP\/\S+\s+(\d{3})/.exec(String(m.start_line||''));return x?Number(x[1]):null};
 const protocolLabel=p=>p==='h2'?'HTTP/2':String(p||'HTTP').toUpperCase().replace('HTTP/1','HTTP/1.x').replace('HTTP/1.x.','HTTP/1.');
 const messageOf=f=>f&&(f.evidence&&f.evidence.http_message_id||f.http_message_id)||null;

 // ------------------------------------------------------------- data access (bounded, read-only)
 async function page(kind,params){
  const id=job();if(!id)throw Error('No analysis job');
  const p=new URLSearchParams({offset:String(params.offset||0),limit:String(PAGE)});
  for(const key of ['evidence_id','stream_id'])if(params[key]!=null){
   if(typeof params[key]!=='string'||!params[key]||params[key].length>160)throw Error('Invalid evidence reference');
   p.set(key,params[key]);
  }
  const response=await fetch('/api/jobs/'+encodeURIComponent(id)+'/'+kind+'?'+p,{headers:{'X-Dashboard-Token':token()}});
  if(!response.ok)throw Error('Evidence unavailable ('+response.status+')');
  const data=await response.json();
  if(!data||!Array.isArray(data.items)||!Number.isInteger(data.total))throw Error('Invalid evidence response');
  return data;
 }
 function siblingStream(m){
  const x=/^(.*)_direction_([01])$/.exec(String(m.stream_id||''));
  return x&&x[1]===m.flow_id?x[1]+'_direction_'+(x[2]==='0'?'1':'0'):null;
 }
 function counterpart(m,rows){
  if(!m.http_request_id)return null;
  const wanted=!isResponse(m);
  const c=rows.filter(x=>x.http_message_id!==m.http_message_id&&x.flow_id===m.flow_id&&x.http_request_id===m.http_request_id&&isResponse(x)===wanted);
  if(!wanted)return c[0]||null;
  return c.find(x=>(statusOf(x)||0)>=200)||c[0]||null;     // a final response wins over 1xx interim responses
 }
 function messageRanges(m){
  if(Array.isArray(m.stream_ranges)&&m.stream_ranges.length)return m.stream_ranges.filter(r=>Number.isInteger(r.start)&&Number.isInteger(r.end)&&r.end>r.start);
  return Number.isInteger(m.stream_start)&&Number.isInteger(m.stream_end)&&m.stream_end>m.stream_start?[{start:m.stream_start,end:m.stream_end}]:[];
 }
 async function fieldsFor(m){
  const total=Number.isInteger(m.field_count)&&m.field_count>0?m.field_count:0,n=Math.min(total,MAX_FIELDS);
  const ids=Array.from({length:n},(_,i)=>m.http_message_id+'_field_'+i);
  const pages=await Promise.all(ids.map(id=>page('field_evidence',{evidence_id:id}).catch(()=>null)));
  const rows=pages.map((p,i)=>p&&p.items.find(x=>x.field_id===ids[i])).filter(Boolean);
  return {rows,total,shown:rows.length,failed:n-rows.length};
 }
 async function sourcesFor(m){
  const ranges=messageRanges(m),out={meta:null,frames:[],partial:false};
  if(!ranges.length||!m.stream_id)return out;
  const end=Math.max(...ranges.map(r=>r.end)),seen=new Set();
  let offset=0;
  for(let i=0;i<MAX_STREAM_PAGES;i++){
   const pg=await page('stream_evidence',{stream_id:m.stream_id,offset});
   for(const r of pg.items){
    if(r.stream_id!==m.stream_id)continue;
    if(r.row_type==='stream'){out.meta=r;continue}
    if(r.row_type!=='source_range'||!r.frame_id||!Number.isInteger(r.stream_start)||!Number.isInteger(r.stream_end))continue;
    for(const need of ranges){
     const a=Math.max(need.start,r.stream_start),b=Math.min(need.end,r.stream_end);
     if(!(a<b))continue;
     const key=r.frame_id+':'+a+':'+b;if(seen.has(key))continue;seen.add(key);
     out.frames.push({frame:r.frame_id,a,b,fa:Number.isInteger(r.file_start)?r.file_start+a-r.stream_start:null,
      fb:Number.isInteger(r.file_start)?r.file_start+b-r.stream_start:null});
    }
   }
   offset+=pg.items.length;
   const last=pg.items[pg.items.length-1];
   if(!pg.items.length||offset>=pg.total||(last&&Number.isInteger(last.stream_end)&&last.stream_end>=end))break;
   if(i===MAX_STREAM_PAGES-1)out.partial=true;
  }
  if(out.frames.length>MAX_FRAMES){out.frames.length=MAX_FRAMES;out.partial=true}
  return out;
 }
 async function loadExchange(messageId){
  const first=await page('http_evidence',{evidence_id:messageId});
  const m=first.items.find(x=>x.http_message_id===messageId);
  if(!m)throw Error('This HTTP message is not in the current analysis');
  const notes=[];
  let rows=[m];
  const streams=[m.stream_id,siblingStream(m)].filter(Boolean);
  if(m.http_request_id){
   const pages=await Promise.all(streams.map(s=>page('http_evidence',{stream_id:s})));
   rows=pages.flatMap(p=>p.items);
   if(pages.some(p=>p.total>p.items.length))notes.push('Only the first '+nf(PAGE)+' messages in each direction of this flow were searched for the matching message.');
  }
  const other=counterpart(m,rows);
  if(m.http_request_id&&m.pairing_status!=='unpaired'&&!other)notes.push('The engine paired this message, but its counterpart was not found within the bounded lookup.');
  const request=isResponse(m)?other:m,response=isResponse(m)?m:other;
  const ok=verified();
  const [reqFields,respFields,reqSrc,respSrc]=await Promise.all([
   request?fieldsFor(request):null,response?fieldsFor(response):null,
   ok&&request?sourcesFor(request).catch(()=>null):null,ok&&response?sourcesFor(response).catch(()=>null):null]);
  return {selected:m,request,response,reqFields,respFields,reqSrc,respSrc,notes,verified:ok,flow:m.flow_id};
 }

 // ------------------------------------------------------------- rendering helpers
 function note(text,warn){return el('p','x-note'+(warn?' x-note-warn':''),text)}
 function facts(pairs){
  const dl=el('dl','x-facts');
  for(const [k,v,mono] of pairs){if(v==null||v==='')continue;dl.append(el('dt',null,k),el('dd',mono?'mono':null,v))}
  return dl;
 }
 function section(title,...children){const s=el('section','x-section');s.append(el('h3',null,title),...children.filter(Boolean));return s}
 function pageFindings(){return typeof state!=='undefined'&&Array.isArray(state.pageFindings)?state.pageFindings:[]}
 function routeText(kind,src,data){
  const d=src&&src.meta&&Array.isArray(src.meta.direction)&&src.meta.direction.length===4?src.meta.direction:null;
  if(d)return [kind==='request'?'Client':'Server',d[0]+':'+d[1],kind==='request'?'Server':'Client',d[2]+':'+d[3]];
  const f=st.finding;
  if(f&&messageOf(f)===(kind==='request'?data.request:data.response)?.http_message_id&&f.source_ip)
   return [kind==='request'?'Client':'Server',f.source_ip+':'+f.source_port,kind==='request'?'Server':'Client',f.destination_ip+':'+f.destination_port];
  return null;
 }
 function route(kind,src,data){
  const r=routeText(kind,src,data);if(!r)return null;
  const p=el('p','x-route');
  p.append(el('span',null,r[0]),el('span','mono',r[1]),el('span','x-route-arrow','→'),el('span',null,r[2]),el('span','mono',r[3]));
  p.setAttribute('aria-label',r[0]+' '+r[1]+' to '+r[2]+' '+r[3]);
  return p;
 }
 function bodyFacts(m,fields){
  const rows=fields?fields.rows:[];
  const bodyRows=rows.filter(x=>['body','json_body','form','multipart'].includes(x.source_category));
  const transforms=[...new Set(bodyRows.flatMap(x=>Array.isArray(x.transformations)?x.transformations:[]))];
  let size=null;
  if(m.protocol!=='h2'&&Number.isInteger(m.body_start)&&Number.isInteger(m.stream_end))size=m.stream_end-m.body_start;
  const kinds=[...new Set(bodyRows.map(x=>({body:'text',json_body:'JSON',form:'form data',multipart:'multipart form'})[x.source_category]))];
  return {size,transforms,kinds,
   pairs:[['Body size',size==null?(m.protocol==='h2'?'Carried in HTTP/2 DATA frames':'unavailable'):size===0?'No body':nf(size)+' bytes in the stream'],
    ['Body framing',m.body_framing?String(m.body_framing).replaceAll('_',' '):null],
    ['Body location',size?range(m.body_start,m.stream_end)+' in '+m.stream_id:null,true],
    ['Read as',kinds.length?kinds.join(', '):(size?'Not extracted as text':null)],
    ['Decoding applied',transforms.length?transforms.join(', ').replaceAll('_',' '):(kinds.length?'none':null)]]};
 }
 function tokenize(line){
  const out=[],re=/<!--.*?(?:-->|$)|<\/?[A-Za-z!?][^>]*>?|\[(?:REDACTED|MASKED)[^\]]*\]|\*{3,}|[^<[*]+|[<[*]/g;
  let m;
  while((m=re.exec(line))){const t=m[0];out.push({text:t,cls:t.startsWith('<!--')?'tok-comment':t[0]==='<'&&t.length>1?'tok-tag':/^\[(REDACTED|MASKED)|^\*{3}/.test(t)?'tok-mask':null})}
  return out;
 }
 function sourceViewer(content){
  const box=el('div','src-viewer');
  const bar=el('div','src-toolbar');
  const html=/html/i.test(String(content.media_type||''));
  bar.append(el('span','chip chip-accent',html?'HTML source':'Body text'),el('span','chip','Masked'));
  if(content.media_type)bar.append(el('span',null,String(content.media_type).slice(0,80)));
  let text=content.text,cut=!!content.truncated;
  if(text.length>MAX_SOURCE_CHARS){text=text.slice(0,MAX_SOURCE_CHARS);cut=true}
  const lines=text.split(/\r\n|\r|\n/);
  if(lines.length>MAX_LINES){lines.length=MAX_LINES;cut=true}
  bar.append(el('span',null,nf(lines.length)+' lines'+(cut?' · truncated':'')));
  const pre=el('pre','src-code'),code=el('code');
  pre.setAttribute('tabindex','0');pre.setAttribute('aria-label',html?'HTML source, shown as plain text':'Body text');
  for(const line of lines){const ln=el('span','src-line');for(const t of tokenize(line))ln.append(t.cls?el('span',t.cls,t.text):el('span',null,t.text));code.append(ln)}
  pre.append(code);
  const wrap=el('button','btn btn-ghost btn-sm','Wrap lines');wrap.type='button';wrap.setAttribute('aria-pressed','false');
  wrap.addEventListener('click',()=>{const on=!pre.classList.contains('wrap');pre.classList.toggle('wrap',on);wrap.setAttribute('aria-pressed',String(on))});
  bar.append(wrap);
  box.append(bar,pre);
  const out=el('div','xchg');
  out.append(box,note('Shown as inert text. Scripts in the captured page do not run, and images, styles and links in it are not loaded or followed.'));
  if(cut)out.append(note('Only part of the body is shown. Lines or characters beyond the display limit are omitted.',true));
  return out;
 }
 function contentOf(m){const c=m&&m.content;return c&&typeof c==='object'&&c.redacted===true&&typeof c.text==='string'?c:null}
 function bodySection(kind,m,fields){
  const b=bodyFacts(m,fields),content=contentOf(m);
  const title=kind==='response'?'Response body and HTML source':'Request body';
  if(content)return section(title,facts(b.pairs),sourceViewer(content));
  if(b.size===0)return section(title,note(kind==='response'?'This response has no body.':'This request has no body.'));
  const msg=kind==='response'
   ?'HTML source is not available. This version of the TRACE engine records where the body sits in the TCP stream and which fields it extracted, but it does not keep the body itself. Nothing has been reconstructed or guessed.'
   :'The body content is not kept by this version of the engine. Values extracted from it appear in the field list above, masked where detected.';
  return section(title,facts(b.pairs),note(msg));
 }
 function fieldTable(fields,hits){
  if(!fields)return null;
  if(!fields.total)return note('No fields were extracted from this message.');
  const wrap=el('div','x-scroll'),t=el('table','x-table'),head=el('thead'),hr=el('tr');
  for(const h of ['#','Field','Mapping','Decoding','Stream bytes'])hr.append(el('th',null,h));
  head.append(hr);const body=el('tbody');
  for(const f of fields.rows){
   const tr=el('tr',hits.has(f.field_id)?'x-hit':null);
   tr.append(el('td','mono',f.field_index));
   const loc=el('td');loc.append(el('span',null,String(f.location||f.source_category||'—')));
   if(hits.has(f.field_id)){loc.append(el('span',null,' '),el('span','x-tag','Finding'))}
   tr.append(loc,el('td',null,GRANULARITY[f.granularity]||String(f.granularity||'—')),
    el('td',null,Array.isArray(f.transformations)&&f.transformations.length?f.transformations.join(', ').replaceAll('_',' '):'none'),
    el('td','mono',(f.stream_ranges||[]).slice(0,2).map(r=>range(r.start,r.end)).join(' ')+((f.stream_ranges||[]).length>2?' …':'')||'—'));
   body.append(tr);
  }
  t.append(head,body);wrap.append(t);
  const out=el('div','xchg');out.append(wrap,el('p','hint','Exact: the value appears byte for byte at these stream positions. Decoded: the value was decoded from these bytes, so it cannot be highlighted as an exact match.'));
  if(fields.shown<fields.total)out.append(note('Showing '+nf(fields.shown)+' of '+nf(fields.total)+' fields'+(fields.failed?' ('+nf(fields.failed)+' could not be loaded)':'')+'.',true));
  return out;
 }
 function findingList(m,onFinding){
  const items=pageFindings().filter(f=>messageOf(f)===m.http_message_id);
  if(!items.length)return {node:note('No findings on the current Findings page refer to this message.'),hits:new Set()};
  const hits=new Set(items.flatMap(f=>f.evidence&&Array.isArray(f.evidence.field_ids)&&f.evidence.field_ids.length===1?f.evidence.field_ids:[]));
  const ul=el('ul','x-findings');
  for(const f of items){
   const li=el('li'),b=el('button');b.type='button';
   if(st.finding===f)b.setAttribute('aria-current','true');
   b.append(el('span','x-ftype',typeof typeLabel==='function'?typeLabel(f.pii_type):String(f.pii_type||'Unknown')),
    el('span',f.detector==='bilstm'?'det-model':'det-rule',f.detector==='bilstm'?'Model':'Rule'),el('span','val-redacted',f.value||'[masked]'));
   b.setAttribute('aria-label','Inspect '+String(f.pii_type||'finding')+' in '+String(f.location||'field'));
   b.addEventListener('click',()=>onFinding(f));
   li.append(b);ul.append(li);
  }
  return {node:ul,hits};
 }
 function renderSide(root,kind,data,fields,src,onFinding){
  root.replaceChildren();
  const m=kind==='request'?data.request:data.response;
  if(!m){
   const other=data.selected;
   root.append(note(other.pairing_status==='unpaired'||!other.http_request_id
    ?'No matching '+kind+' was observed for this message in the capture. TRACE does not create a placeholder.'
    :'The matching '+kind+' could not be located within the bounded lookup.',true));
   for(const n of data.notes)root.append(note(n,true));
   return;
  }
  const head=el('div','x-start');
  head.append(el('span','x-dir '+(kind==='request'?'x-dir-req':'x-dir-resp'),kind==='request'?'Request':'Response'),el('span','chip',protocolLabel(m.protocol)));
  if(data.selected===m&&st.view==='findings'&&st.finding)head.append(el('span','chip chip-accent','Contains selected finding'));
  root.append(head,el('code','x-line',m.start_line||'Start line unavailable'));
  const r=route(kind,src,data);if(r)root.append(r);
  root.append(facts([['Message ID',m.http_message_id,true],['Flow',m.flow_id,true],['Pairing',PAIRING[m.pairing_status]||m.pairing_status],
   ['Stream bytes',range(m.stream_start,m.stream_end)+' of '+m.stream_id,true],
   ['Headers end at',m.protocol!=='h2'&&Number.isInteger(m.header_end)?'byte '+nf(m.header_end):null],
   ['HTTP/2 stream',m.protocol==='h2'&&m.http2_stream_id!=null?String(m.http2_stream_id):null],
   ['Fields extracted',Number.isInteger(m.field_count)?nf(m.field_count):null]]));
  const fl=findingList(m,onFinding);
  root.append(section('Findings in this '+kind,fl.node),section('Extracted fields',fieldTable(fields,fl.hits)),bodySection(kind,m,fields));
  if(m.start_line&&/\[path-redacted\]/.test(m.start_line))root.append(note('The URL path and query are hidden because they can contain personal information.'));
  if(Array.isArray(m.limitations)&&m.limitations.length)root.append(note('Engine limitations: '+m.limitations.join(', ').replaceAll('_',' '),true));
 }
 function frameTable(src){
  const wrap=el('div','x-scroll'),t=el('table','x-table'),head=el('thead'),hr=el('tr');
  for(const h of ['Frame','Stream bytes','File bytes'])hr.append(el('th',null,h));
  head.append(hr);const body=el('tbody');
  for(const f of src.frames){const tr=el('tr');tr.append(el('td','mono',f.frame),el('td','mono',range(f.a,f.b)),el('td','mono',f.fa==null?'unavailable':range(f.fa,f.fb)));body.append(tr)}
  t.append(head,body);wrap.append(t);return wrap;
 }
 function renderPackets(root,data){
  root.replaceChildren();
  root.append(el('h3',null,'Packets supporting this exchange'));
  if(!data.verified){root.append(note('Original capture identity is not verified, so packet references are withheld.',true));return}
  for(const [kind,m,src] of [['Request',data.request,data.reqSrc],['Response',data.response,data.respSrc]]){
   if(!m){root.append(section(kind,note('No '+kind.toLowerCase()+' was observed, so it has no packets.')));continue}
   if(!src){root.append(section(kind,note('Packet references could not be loaded for this message.',true)));continue}
   const meta=src.meta,parts=[];
   if(meta){parts.push(meta.syn_observed?'connection start seen':'connection start not seen');if(meta.fin_observed)parts.push('close seen');if(meta.rst_observed)parts.push('reset seen');if(meta.unsafe)parts.push('reassembly marked unsafe')}
   const s=section(kind+' · '+m.stream_id,route(kind.toLowerCase(),src,data),parts.length?el('p','hint','Stream: '+parts.join(' · ')+'.'):null,
    src.frames.length?frameTable(src):note('No frame ranges were resolved within the bounded lookup. Packet numbers are not inferred.',true));
   if(src.partial)s.append(note('Showing a bounded subset of frames for this message.',true));
   root.append(s);
  }
  root.append(note('Frames are listed by their position in the capture file. File byte ranges point into the original capture and require its matching SHA-256 to be meaningful.'));
 }
 function placeholders(ids,text,warn){for(const id of ids){const n=q(id);if(n){n.replaceChildren(note(text,warn))}}}

 // ------------------------------------------------------------- tabs
 function selectTab(tab,focus){
  const list=tab.parentElement;if(!list)return;
  for(const t of list.querySelectorAll('[role=tab]')){
   const on=t===tab;t.setAttribute('aria-selected',String(on));t.tabIndex=on?0:-1;
   const panel=q(t.getAttribute('aria-controls'));if(panel)panel.hidden=!on;
  }
  if(focus)tab.focus();
  onTab(list.dataset.tablist,tab.id);
 }
 function bindTabs(){
  for(const list of document.querySelectorAll('[data-tablist]')){
   const tabs=[...list.querySelectorAll('[role=tab]')];
   for(const tab of tabs){
    tab.addEventListener('click',()=>selectTab(tab,false));
    tab.addEventListener('keydown',ev=>{
     const i=tabs.indexOf(tab);let n=null;
     if(ev.key==='ArrowRight')n=tabs[(i+1)%tabs.length];else if(ev.key==='ArrowLeft')n=tabs[(i-1+tabs.length)%tabs.length];
     else if(ev.key==='Home')n=tabs[0];else if(ev.key==='End')n=tabs[tabs.length-1];
     if(n){ev.preventDefault();selectTab(n,true)}
    });
   }
  }
 }
 function activeTab(list){const t=document.querySelector('[data-tablist="'+list+'"] [aria-selected=true]');return t?t.id:null}
 function onTab(list,id){
  if(list==='fi'&&id!=='fi-tab-finding')ensureFindingExchange();
  if(list==='tr'&&id==='tr-tab-messages'&&!st.listLoaded)loadMessages(st.msgOffset);
 }

 // ------------------------------------------------------------- findings inspector
 function showFinding(f){
  st.finding=f;st.findingMessage=messageOf(f);st.findingLoaded=null;st.fEpoch++;
  placeholders(['fx-request','fx-response'],job()&&st.findingMessage?'Loading the HTTP exchange…':'Request and response details are available for analyses run in this session that link the finding to an HTTP message.');
  const p=q('fx-packets');if(p)p.replaceChildren();
  if(st.view==='findings'&&activeTab('fi')!=='fi-tab-finding')ensureFindingExchange();
 }
 async function ensureFindingExchange(){
  const id=st.findingMessage,jobId=job();
  if(!id||!jobId||st.findingLoaded===id)return;
  st.findingLoaded=id;const epoch=++st.fEpoch;
  try{
   const data=await loadExchange(id);
   if(epoch!==st.fEpoch||jobId!==job())return;
   const pick=f=>{if(typeof inspectFinding==='function')inspectFinding(f)};
   renderSide(q('fx-request'),'request',data,data.reqFields,data.reqSrc,pick);
   renderSide(q('fx-response'),'response',data,data.respFields,data.respSrc,pick);
   renderPackets(q('fx-packets'),data);
  }catch(e){
   if(epoch!==st.fEpoch)return;st.findingLoaded=null;
   placeholders(['fx-request','fx-response'],'The HTTP exchange could not be loaded: '+(e instanceof Error?e.message:'unavailable')+'.',true);
  }
 }

 // ------------------------------------------------------------- HTTP message list (Network traffic)
 function pairingShort(m){return m.pairing_status==='paired_by_http2_stream_id'?'Paired (stream ID)':m.pairing_status==='paired_best_effort'?'Paired':m.pairing_status==='unpaired'?'Unpaired':String(m.pairing_status||'—')}
 function paintMessages(rows,total,offset,partial){
  const body=q('msg-body');body.replaceChildren();
  q('msg-total').textContent=st.msgFlow?'':nf(total);
  if(!rows.length){const tr=el('tr'),td=el('td','table-empty','No HTTP messages were decoded'+(st.msgFlow?' in this flow.':' in this capture.'));td.colSpan=6;tr.append(td);body.append(tr)}
  for(const m of rows){
   const tr=el('tr');if(m.http_message_id===st.openMessage)tr.classList.add('selected');
   const idc=el('td');idc.append(el('span','mono',m.http_message_id),el('span','cell-sub',m.flow_id));
   const kind=el('td');kind.append(el('span','x-dir '+(isResponse(m)?'x-dir-resp':'x-dir-req'),isResponse(m)?'Response':'Request'));
   const btn=el('button','inspect-btn','Open');btn.type='button';btn.setAttribute('aria-label','Open exchange for '+m.http_message_id);
   btn.addEventListener('click',ev=>{ev.stopPropagation();openMessage(m.http_message_id,isResponse(m))});
   const act=el('td');act.append(btn);
   tr.append(idc,kind,el('td','val-redacted',m.start_line||'—'),el('td',null,pairingShort(m)),el('td','num',nf(m.field_count)),act);
   tr.addEventListener('click',()=>openMessage(m.http_message_id,isResponse(m)));
   body.append(tr);
  }
  q('msg-scope').textContent=st.msgFlow?'Messages in flow '+st.msgFlow+(partial?' (first '+nf(PAGE)+' per direction)':''):'All HTTP messages in this capture';
  q('msg-clear-flow').classList.toggle('hidden',!st.msgFlow);
  q('msg-page').textContent=rows.length?nf(offset+1)+'–'+nf(offset+rows.length)+' of '+nf(total):'0 of '+nf(total);
  q('msg-prev').disabled=!!st.msgFlow||offset===0;q('msg-next').disabled=!!st.msgFlow||offset+rows.length>=total;
 }
 async function loadMessages(offset){
  if(!job()){paintEmptyList('Message-level evidence is available for analyses run in this session.');return}
  const epoch=++st.listEpoch;st.listLoaded=true;
  try{
   let rows,total,partial=false;
   if(st.msgFlow){
    const pages=await Promise.all([0,1].map(n=>page('http_evidence',{stream_id:st.msgFlow+'_direction_'+n})));
    rows=pages.flatMap(p=>p.items).filter(x=>x.flow_id===st.msgFlow);
    rows.sort((a,b)=>String(a.http_request_id||'~'+a.http_message_id).localeCompare(String(b.http_request_id||'~'+b.http_message_id))||(isResponse(a)-isResponse(b)));
    partial=pages.some(p=>p.total>p.items.length);total=rows.length;offset=0;
   }else{const pg=await page('http_evidence',{offset});rows=pg.items;total=pg.total}
   if(epoch!==st.listEpoch)return;
   st.msgOffset=offset;st.msgTotal=total;paintMessages(rows,total,offset,partial);
  }catch(e){if(epoch===st.listEpoch){st.listLoaded=false;paintEmptyList('HTTP messages could not be loaded: '+(e instanceof Error?e.message:'unavailable')+'.')}}
 }
 function paintEmptyList(text){
  const body=q('msg-body');if(!body)return;body.replaceChildren();
  const tr=el('tr'),td=el('td','table-empty',text);td.colSpan=6;tr.append(td);body.append(tr);
  q('msg-page').textContent='—';q('msg-prev').disabled=true;q('msg-next').disabled=true;q('msg-total').textContent='';
 }
 async function openMessage(id,response){
  st.openMessage=id;const epoch=++st.mEpoch,jobId=job();
  for(const row of q('msg-body').children)row.classList.toggle('selected',row.querySelector&&row.querySelector('.mono')?.textContent===id);
  q('mi-title').textContent=id;q('mi-sub').textContent='Loading the HTTP exchange…';
  placeholders(['mx-request','mx-response','mx-packets'],'Loading…');
  const tab=q(response?'mi-tab-response':'mi-tab-request');if(tab)selectTab(tab,false);
  try{
   const data=await loadExchange(id);
   if(epoch!==st.mEpoch||jobId!==job())return;
   const r=data.request,s=data.response;
   q('mi-title').textContent=(r?r.start_line:'No request observed')||id;
   q('mi-sub').textContent=[data.flow,s?s.start_line:'no response observed'].filter(Boolean).join(' · ');
   const pick=f=>{if(typeof inspectFinding==='function'){if(typeof switchTab==='function')switchTab('findings');inspectFinding(f)}};
   renderSide(q('mx-request'),'request',data,data.reqFields,data.reqSrc,pick);
   renderSide(q('mx-response'),'response',data,data.respFields,data.respSrc,pick);
   renderPackets(q('mx-packets'),data);
  }catch(e){
   if(epoch!==st.mEpoch)return;
   q('mi-sub').textContent='';placeholders(['mx-request','mx-response','mx-packets'],'The HTTP exchange could not be loaded: '+(e instanceof Error?e.message:'unavailable')+'.',true);
  }
 }
 function showFlowMessages(flowId){
  st.msgFlow=typeof flowId==='string'&&flowId.length<=150?flowId:null;
  const tab=q('tr-tab-messages');st.listLoaded=false;
  if(typeof switchTab==='function')switchTab('flows');
  if(tab)selectTab(tab,false);else loadMessages(0);
 }

 // ------------------------------------------------------------- hooks used by app.js
 function reset(text){
  st.finding=null;st.findingMessage=null;st.findingLoaded=null;st.fEpoch++;st.mEpoch++;st.listEpoch++;
  st.msgOffset=0;st.msgFlow=null;st.openMessage=null;st.listLoaded=false;
  placeholders(['fx-request','fx-response'],'Select a finding to see its HTTP exchange.');
  placeholders(['mx-request','mx-response','mx-packets'],'No message selected.');
  const p=q('fx-packets');if(p)p.replaceChildren();
  q('mi-title').textContent='Select a message';q('mi-sub').textContent='Choose a request or response to see both sides of the exchange.';
  paintEmptyList(text||'No capture analysed yet.');
 }
 function onResult(){
  reset('Open this tab to load the HTTP messages.');
  if(activeTab('tr')==='tr-tab-messages')loadMessages(0);
 }
 function onAttempt(){/* Previous results stay visible; the banner in app.js explains which capture they describe. */}
 function onView(name){st.view=name;if(name==='findings'&&activeTab('fi')!=='fi-tab-finding')ensureFindingExchange()}
 function init(){
  bindTabs();
  q('msg-prev').addEventListener('click',()=>loadMessages(Math.max(0,st.msgOffset-PAGE)));
  q('msg-next').addEventListener('click',()=>loadMessages(st.msgOffset+PAGE));
  q('msg-clear-flow').addEventListener('click',()=>{st.msgFlow=null;loadMessages(0)});
 }
 if(typeof document!=='undefined'&&document.readyState!=='loading'&&typeof document.querySelectorAll==='function')init();
 else if(typeof document!=='undefined'&&document.addEventListener)document.addEventListener('DOMContentLoaded',init);
 return {init,showFinding,showFlowMessages,openMessage,onResult,onAttempt,onView,loadExchange,tokenize,sourceViewer,_state:st};
})();
