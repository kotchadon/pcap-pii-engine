/* Bounded authenticated investigation. Captured content is always text, never markup. */
'use strict';
const TraceInvestigation = (() => {
  const el = id => document.getElementById(id);
  let job = null, token = null, epoch = 0, selection = 0, listRequest = 0, contentRequest = 0;
  let pageOffset = 0, pageTotal = 0, loaded = false, current = null, chosenFinding = null;
  const text = (id, value) => { el(id).textContent = String(value ?? 'Unavailable'); };
  const endpoint = ep => ep ? `${ep.ip}:${ep.port}` : 'Unknown';
  const interval = (a, b) => Number.isInteger(a) && Number.isInteger(b) ? `[${a}, ${b})` : 'unknown';
  function button(label, action, selected = false) {
    const b = document.createElement('button'); b.type = 'button'; b.textContent = label;
    b.className = 'investigation-choice'; b.setAttribute('aria-pressed', String(selected));
    b.addEventListener('click', action); return b;
  }
  function fact(parent, label, value) {
    const row = document.createElement('div'), key = document.createElement('strong'), val = document.createElement('span');
    row.className = 'investigation-fact'; key.textContent = label; val.textContent = String(value ?? 'Unavailable');
    row.append(key, val); parent.appendChild(row);
  }
  function clearSource() {
    contentRequest++;
    el('conversation-content').replaceChildren(); el('content-ack').checked = false;
    el('content-reveal').disabled = true; text('content-status', 'Response source is hidden.');
  }
  async function request(path, options = {}) {
    const response = await fetch('/api/jobs/' + encodeURIComponent(job) + '/' + path,
      {...options, headers: {'X-Dashboard-Token': token, ...(options.headers || {})}});
    if (!response.ok) throw Error('Investigation unavailable (' + response.status + ').');
    return response.json();
  }
  function setReport(payload, auth) {
    epoch++; selection++; listRequest++; job = payload.job_id || null; token = auth;
    current = chosenFinding = null; loaded = false; pageOffset = pageTotal = 0;
    for (const id of ['conversation-list','conversation-messages','conversation-meta','conversation-fields',
      'conversation-findings','conversation-sources','conversation-packet','selected-finding']) el(id).replaceChildren();
    clearSource(); text('conversation-status', job ? 'Choose a conversation to inspect.' : 'Conversation navigation requires a completed scan job.');
    text('conversation-page', 'No page loaded'); text('conversation-mapping', 'Select a field to inspect its supporting source.');
    el('conversation-prev').disabled = el('conversation-next').disabled = true;
  }
  async function loadConversations(offset = 0) {
    if (!job) return;
    const version = epoch, serial = ++listRequest;
    try {
      const data = await request('conversations?' + new URLSearchParams({offset, limit: 25}));
      if (version !== epoch || serial !== listRequest) return;
      loaded = true; pageOffset = data.offset; pageTotal = data.total;
      const root = el('conversation-list'); root.replaceChildren();
      for (const tx of data.items) {
        const messages = tx.messages || [], first = messages.find(m => m.message_type === 'request') || messages[0];
        if (!first) continue;
        const statuses = messages.filter(m => m.message_type === 'response').map(m => m.status).join(', ');
        const label = `${tx.transaction_id} · ${first.method || 'Unpaired response'} · ${statuses || 'No response observed'}`;
        root.appendChild(button(label, () => selectMessage(first.http_message_id), current?.transaction?.transaction_id === tx.transaction_id));
      }
      text('conversation-page', `${data.total ? offset + 1 : 0}–${offset + data.items.length} of ${data.total} conversations`);
      el('conversation-prev').disabled = offset === 0;
      el('conversation-next').disabled = offset + data.items.length >= data.total;
      if (!data.items.length) text('conversation-status', 'No supported HTTP conversation was reconstructed. Encrypted and unsupported traffic is not decoded.');
    } catch (error) { if (version === epoch && serial === listRequest) text('conversation-status', error.message); }
  }
  function paintFinding(f) {
    chosenFinding = f; const root = el('selected-finding'); root.replaceChildren();
    if (!f) { fact(root, 'Finding', 'Choose a finding. An HTTP message can exist without a PII finding.'); return; }
    fact(root, 'Category', f.pii_type); fact(root, 'Masked value', f.value || '[withheld]');
    fact(root, 'Detector', f.detector === 'bilstm' ? 'BiLSTM contextual prediction' : 'Deterministic rules');
    fact(root, 'Score', `${f.confidence ?? 'unknown'} · ${f.detector === 'bilstm' ? 'uncalibrated model score' : 'heuristic score'}; not verified accuracy`);
    fact(root, 'Field location', f.location); fact(root, 'HTTP message', f.http_message_id);
    fact(root, 'Identity', f.evidence?.scope || 'Unknown');
    if (f.evidence?.decoded_text_span) fact(root, 'Decoded character span',
      interval(f.evidence.decoded_text_span.start, f.evidence.decoded_text_span.end) + ' — not packet bytes');
    fact(root, 'Mapping limitations', (f.evidence?.limitations || []).join('; ') || 'No detector byte mapping supplied');
    const ids = f.evidence?.field_ids || [];
    for (const id of ids) root.appendChild(button(`${ids.length > 1 ? 'Candidate field' : 'Locate field'} ${id}`,
      () => selectMessage(f.http_message_id, id, f)));
  }
  async function selectMessage(messageId, fieldId = '', finding = null, fieldOffset = 0, findingOffset = 0) {
    if (!job) return;
    if (finding && (finding.http_message_id !== messageId ||
        (fieldId && !(finding.evidence?.field_ids || []).includes(fieldId)))) finding = null;
    const version = epoch, serial = ++selection;
    clearSource(); current = null; paintFinding(finding);
    for (const id of ['conversation-messages','conversation-meta','conversation-fields','conversation-findings',
      'conversation-sources','conversation-packet']) el(id).replaceChildren();
    text('conversation-status', 'Loading selected message…'); text('conversation-mapping', 'Loading supporting evidence…');
    try {
      const data = await request('investigation?' + new URLSearchParams({message_id: messageId, field_id: fieldId,
        field_offset: fieldOffset, finding_offset: findingOffset, limit: 25}));
      if (version !== epoch || serial !== selection) return;
      current = data; const m = data.message, meta = el('conversation-meta');
      text('conversation-status', `${m.http_message_id} · ${m.message_type === 'request' ? 'Request: what the computer asked' : 'Response: what the website replied'}`);
      for (const other of data.transaction.messages || []) {
        const label = `${other.message_type === 'request' ? 'Request' : other.interim_response ? 'Interim response' : 'Response'} · ${other.start_line}`;
        el('conversation-messages').appendChild(button(label, () => selectMessage(other.http_message_id), other.http_message_id === messageId));
      }
      if (data.transaction.messages_truncated) fact(meta, 'Conversation limit', 'Only the first bounded page of associated messages is shown; later messages are not represented here.');
      fact(meta, 'Client → server', `${endpoint(m.client)} → ${endpoint(m.server)}`);
      fact(meta, 'This message direction', `${endpoint(m.source)} → ${endpoint(m.destination)}`);
      fact(meta, 'Flow / TCP session', `${m.flow_id} / ${m.session}`);
      fact(meta, 'Stream / protocol', `${m.stream_id} / ${m.protocol}`);
      fact(meta, 'Start line (redacted)', m.start_line);
      fact(meta, 'Timestamp', Number.isFinite(m.timestamp) ? new Date(m.timestamp * 1000).toISOString() : 'Unknown');
      fact(meta, 'Association', `${m.pairing_status}; ${m.association_basis}`);
      fact(meta, 'HTTP reconstruction', m.reconstruction_complete === true ? 'Supported message reconstructed; capture completeness remains unknown' :
        m.reconstruction_complete === false ? 'Incomplete / partial HTTP message' : 'Message completeness unavailable');
      fact(meta, 'HTTP message limitations', (m.limitations || []).join('; ') || 'None reported for this message');
      if (data.flow?.http_diagnostics?.length) fact(meta, 'Flow HTTP diagnostics',
        data.flow.http_diagnostics.slice(0, 30).map(d => typeof d === 'string' ? d : d.reason || 'Unspecified HTTP diagnostic').join('; '));
      fact(meta, 'Stream bytes', interval(m.stream_start, m.stream_end));
      fact(meta, 'Observed transport', `SYN ${!!data.stream?.syn_observed}; FIN ${!!data.stream?.fin_observed}; RST ${!!data.stream?.rst_observed}. Flags alone do not prove a complete handshake/capture.`);
      fact(meta, 'Stream diagnostics', (data.stream?.diagnostics || []).join('; ') || 'No observed damage; completeness remains unknown');
      if (m.header_names) fact(meta, 'Supported header names', m.header_names.map(h => h + ': [value withheld]').join('\n') || 'None');
      fact(meta, 'Capture SHA-256', data.capture_identity?.capture_sha256);
      fact(meta, 'Verification', data.verification?.description || data.verification?.status);
      for (const item of data.limitations || []) fact(meta, 'Limitation', item);
      const fields = [...data.fields.items];
      if (data.selected_field && !fields.some(f => f.field_id === data.selected_field.field_id)) fields.unshift(data.selected_field);
      for (const field of fields) el('conversation-fields').appendChild(button(
        `Field ${field.field_index} · ${field.source_category} · ${field.granularity}`,
        () => selectMessage(messageId, field.field_id, chosenFinding, fieldOffset, 0), field.field_id === fieldId));
      paginate('conversation-fields', data.fields, n => selectMessage(messageId, fieldId, chosenFinding, n, findingOffset));
      for (const f of data.findings.items) el('conversation-findings').appendChild(button(
        `${f.pii_type} · ${f.value || '[masked]'} · ${f.detector}`, () => openFinding(f)));
      paginate('conversation-findings', data.findings, n => selectMessage(messageId, fieldId, chosenFinding, fieldOffset, n));
      const field = data.selected_field;
      const scope = field ? field.granularity === 'exact_stream_range' ? 'Exact source mapping for the whole field; detector substring bytes are not asserted.' :
        field.granularity === 'transformed_source_range' ? 'Transformed data: supporting captured ranges only; decoded characters are not raw byte offsets.' :
        'Incomplete or ambiguous field source; message support only.' : 'Supporting source range for the HTTP message; select a field for field-specific mapping.';
      text('conversation-mapping', (data.verification?.coverage_complete === false ? 'Incomplete source coverage: some requested ranges cannot be shown. ' : '') + scope + ' ' + (field?.transformations || []).join(', ') + ' ' + (field?.limitations || []).join('; ') +
        (data.source_ranges_truncated ? ' Source list bounded: additional ranges are not shown.' : ''));
      for (const source of data.source_ranges || []) el('conversation-sources').appendChild(button(
        `${source.frame_id} · file bytes ${interval(source.file_start, source.file_end)} · stream ${interval(source.stream_start, source.stream_end)}`,
        () => showPacket(source)));
      if (!data.source_ranges?.length) fact(el('conversation-sources'), 'Source', 'No proven captured-byte interval available for this selection.');
      const available = data.content_available && m.message_type === 'response' && m.protocol !== 'h2';
      el('content-ack').disabled = !available;
      text('content-status', available ? 'Optional local response source can contain unmasked sensitive data. A fresh capture hash check is required on reveal.' :
        'Response source unavailable: retention was not enabled, this is a request, or the protocol is unsupported.');
    } catch (error) {
      if (version === epoch && serial === selection) { current = null; text('conversation-status', error.message); text('conversation-mapping', 'Evidence unavailable; no ranges are inferred.'); }
    }
  }
  function paginate(id, page, callback) {
    fact(el(id), 'Page', `${page.total ? page.offset + 1 : 0}–${page.offset + page.items.length} of ${page.total}`);
    if (page.offset > 0) el(id).appendChild(button('Previous page', () => callback(Math.max(0, page.offset - 25))));
    if (page.offset + page.items.length < page.total) el(id).appendChild(button('Next page', () => callback(page.offset + 25)));
  }
  function showPacket(source) {
    const root = el('conversation-packet'); root.replaceChildren(); const p = source.packet || {};
    fact(root, 'Packet reference', source.frame_id); fact(root, 'Original file bytes', interval(source.file_start, source.file_end));
    fact(root, 'Within captured frame', interval(source.frame_start, source.frame_end));
    fact(root, 'TCP sequence support', interval(source.tcp_seq_start, source.tcp_seq_end));
    fact(root, 'Captured / wire length', `${p.captured_length ?? '?'} / ${p.wire_length ?? '?'}`);
    fact(root, 'Capture record offset', p.record_offset); fact(root, 'Flags', p.tcp_datagram?.flags);
    fact(root, 'Mapping', 'Ranges support this selection; they are not a fabricated detector byte span.');
  }
  function openFinding(f) {
    const ids = f.evidence?.field_ids || [];
    return selectMessage(f.http_message_id || f.evidence?.http_message_id, ids.length === 1 ? ids[0] : '', f);
  }
  async function reveal() {
    if (!current || !el('content-ack').checked || el('content-ack').disabled) return;
    const version = epoch, serial = selection, contentSerial = ++contentRequest, messageId = current.message.http_message_id;
    el('content-reveal').disabled = true; text('content-status', 'Verifying retained capture and recovering response source…');
    try {
      const result = await request('content', {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({message_id: messageId, acknowledge_sensitive_content: true})});
      if (version !== epoch || serial !== selection || contentSerial !== contentRequest) return;
      // Never innerHTML, srcdoc, iframe, a URL, or a downloadable raw file.
      text('conversation-content', result.text);
      text('content-status', `${result.is_html ? 'HTML source' : 'Decoded response text'} · ${result.status}. Capture SHA-256 ${result.capture_sha256}. ` +
        'Unmasked local text only. Scripts/resources are not executed or fetched; this is not a reconstructed browser page. ' + (result.limitations || []).join('; '));
    } catch (error) { if (version === epoch && serial === selection && contentSerial === contentRequest) text('content-status', error.message); }
  }
  el('conversation-prev').addEventListener('click', () => loadConversations(Math.max(0, pageOffset - 25)));
  el('conversation-next').addEventListener('click', () => loadConversations(pageOffset + 25));
  el('content-ack').addEventListener('change', () => { el('content-reveal').disabled = !current || !el('content-ack').checked || el('content-ack').disabled; });
  el('content-reveal').addEventListener('click', reveal);
  el('content-hide').addEventListener('click', clearSource);
  return {setReport, activate: () => { if (!loaded) return loadConversations(); }, openFinding, hideSource: clearSource};
})();
