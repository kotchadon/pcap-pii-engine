"""Controlled ground-truth fixture: a small, fully fictional HTTP/1.1 capture plus an independent manifest.

Labels are *constructed*: every name or username is inserted into a field by this script, which records its exact span while
building the text. No TRACE module, rule or model is imported or run, so the manifest cannot depend on a detector's output.
The scenario table below was written once, before any model was run on it, and must not be edited to improve a score.

Outputs (deterministic, byte-identical on every run):
    examples/groundtruth/controlled_fixture_v1.pcap
    examples/groundtruth/controlled_fixture_v1.manifest.json
Usage: python examples/generate_groundtruth_fixture.py [output_directory]

The manifest lists EVERY field of every message (headers, query parameters, body values) so that negative fields - including
hard negatives such as companies, places, products and given-name look-alikes - contribute to false-positive analysis.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
import socket
import struct
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

# Python 3.11 may let zlib supply the gzip OS header byte; newer versions
# normalise it to 255. Stable fixture bytes must not depend on Python minor
# version or operating system. RFC 1952 defines 255 as 'unknown OS'.
def _portable_gzip(data: bytes) -> bytes:
    encoded = bytearray(gzip.compress(data, mtime=0))
    encoded[9] = 255
    return bytes(encoded)


CLIENT, SERVER = '192.0.2.', '198.51.100.'
BASE_TIME = 1_760_100_000
MARK = re.compile(r'⟦(PN|UN):([^⟧]+)⟧')
LABEL = {'PN': 'PERSON_NAME', 'UN': 'USERNAME'}
HN = 'hard_negative:'

# Each scenario: (name, [exchange, ...]); exchange = dict(req=..., resp=...).
# req: method, path, kind ('json'|'form'|'gzip-json'|'chunked-json'|'none'), body (dict, marked strings), headers (extra dict),
#      categories: {field-location: category} for negative / special fields.
# resp: kind and body likewise.
S = []


def scenario(name, *exchanges):
    S.append((name, exchanges))


def ex(method, path, kind='json', body=None, headers=None, resp=None, resp_kind='json', cat=None, resp_cat=None):
    return dict(method=method, path=path, kind=kind, body=body, headers=headers or {}, resp=resp, resp_kind=resp_kind,
                cat=cat or {}, resp_cat=resp_cat or {})


scenario('profile', ex('POST', '/v2/profile', body={'profile': {'displayName': '⟦PN:Tamsin Okonkwo-Hale⟧', 'bio': 'Trail runner and amateur astronomer', 'timezone': 'Australia/Perth'}, 'marketing_opt_in': False}, resp={'status': 'updated', 'revision': 18}))
scenario('shipping', ex('POST', '/orders', body={'order_id': 'ORD-77310', 'ship_to': {'name': '⟦PN:Bjarni Thorvaldsson⟧', 'street': '14 Wattle Street', 'city': 'Fremantle'}, 'items': [{'sku': 'LAMP-AURORA-02', 'qty': 1}]}, resp={'order_id': 'ORD-77310', 'state': 'accepted', 'note': 'Estimated delivery 3 days'}))
scenario('login_form', ex('POST', '/session', kind='form', body={'username': '⟦UN:kestrel_moss19⟧', 'password': 'pw-fixture-0001', 'remember': '1'}, resp={'token_type': 'bearer', 'expires_in': 3600}))
scenario('comment', ex('POST', '/posts/4410/comments', body={'post_id': 4410, 'author': '⟦PN:Rhiannon Vasquez-Lee⟧', 'body': 'Great article, thanks for sharing!'}, resp={'accepted': True}))
scenario('chat_mention', ex('POST', '/chat/send', body={'channel': 'eng-reviews', 'text': 'hey @⟦UN:quill_harbor88⟧ can you review the migration today?'}, resp={'delivered': True}))
scenario('ticket', ex('POST', '/support/tickets', body={'reporter': '⟦PN:Oluwaseun Adeyemi-Clarke⟧', 'subject': 'Cannot export monthly report', 'description': 'Hi team, this is ⟦PN:Oluwaseun⟧ again. The export button fails with a timeout.'}, resp={'ticket': 'SUP-2291', 'status': 'open'}))
scenario('search_query', ex('GET', '/search?' + urlencode({'user': '⟦UN:thistle_rain42⟧', 'q': 'winter boots', 'page': '2'}), kind='none', resp={'results': 0, 'suggestion': 'Try a broader term'}, cat={'query_parameter.q': HN + 'search_terms'}))
scenario('gzip_member', ex('POST', '/members/sync', kind='gzip-json', body={'member': {'handle': '⟦UN:cobalt_finch07⟧', 'tier': 'gold'}, 'synced_at': '2025-06-02T10:15:00Z'}, resp={'ok': True}))
scenario('chunked_signup', ex('POST', '/events', kind='chunked-json', body={'event': 'signup', 'user': {'login': '⟦UN:marlin_tide_03⟧', 'full_name': '⟦PN:Zofia Wiśniewska⟧'}}, resp={'id': 'evt_00921'}))
scenario('greeting_response', ex('GET', '/me', kind='none', resp={'greeting': 'Welcome back, ⟦PN:Imelda Nakashima⟧!', 'unread': 3}))
scenario('reviewers', ex('POST', '/reviews/assign', body={'pull_request': 981, 'reviewers': ['⟦PN:Anneliese Brandt⟧', '⟦PN:Kofi Mensah-Boateng⟧'], 'due': '2025-06-09'}, resp={'assigned': 2}))
scenario('contact_split', ex('POST', '/contacts', body={'first_name': '⟦PN:Joaquín⟧', 'last_name': '⟦PN:Espinosa-Rivas⟧', 'company': 'Casa Marea S.A.'}, resp={'saved': True}, cat={'json_body.company': HN + 'company_name'}))
scenario('header_identity', ex('GET', '/account', kind='none', headers={'X-Customer-Name': '⟦PN:Ngozi Eze-Collins⟧', 'X-Forwarded-User': '⟦UN:ember_lantern55⟧'}, resp={'account': 'active'}))
scenario('neg_company', ex('POST', '/vendors', body={'vendor': {'name': 'Harborview Logistics Pty Ltd', 'contact_dept': 'Accounts Payable'}, 'author': 'Beckett & Marlowe Associates'}, resp={'vendor_id': 'V-5519'}, cat={'json_body.vendor.name': HN + 'company_name', 'json_body.author': HN + 'company_name'}))
scenario('neg_places', ex('POST', '/address/validate', body={'street': 'Lincoln Street', 'suburb': 'Victoria Park', 'state': 'WA', 'country': 'Jordan', 'landmark': 'Washington Reserve'}, resp={'valid': True}, cat={f'json_body.{k}': HN + 'place_name' for k in ('street', 'suburb', 'country', 'landmark')}))
scenario('neg_products', ex('POST', '/catalog', body={'name': 'Aurora Desk Lamp', 'brand': 'Kensington Oak', 'collection': 'Madison Collection', 'description': 'Warm white LED lamp with brass finish'}, resp={'sku': 'LAMP-AURORA-02'}, cat={f'json_body.{k}': HN + 'product_name' for k in ('name', 'brand', 'collection')}))
scenario('neg_technical_ids', ex('POST', '/deploy', body={'service': 'payments-gateway', 'branch': 'feature_login_fix', 'artifact': 'build_20250602_final', 'pipeline': 'nightly_build_main', 'file': 'report_final_v2.pdf', 'sku': 'SKU_BLUE_42', 'request_id': 'req_8f3a21c9'}, resp={'queued': True}, cat={f'json_body.{k}': HN + 'identifier_lookalike' for k in ('branch', 'artifact', 'pipeline', 'file', 'sku', 'request_id')}))
scenario('neg_roles_errors', ex('POST', '/admin/test', body={'role': 'admin', 'fallback_role': 'guest', 'message': 'Invalid token supplied', 'level': 'error'}, resp={'ok': False}, cat={'json_body.role': HN + 'role_or_status', 'json_body.fallback_role': HN + 'role_or_status', 'json_body.message': HN + 'role_or_status'}))
scenario('neg_feedback', ex('POST', '/feedback', body={'rating': 4, 'comment': 'The checkout flow was quick but the confirmation email arrived late.'}, resp={'thanks': True}, cat={'json_body.comment': HN + 'free_text_without_names'}))
scenario('neg_teams_regions', ex('POST', '/org/lookup', body={'team': 'Blue Heron Support', 'region': 'Northern Territory', 'ship': 'MV Pacific Dawn'}, resp={'found': True}, cat={f'json_body.{k}': HN + 'organisation_or_place' for k in ('team', 'region', 'ship')}))
scenario('neg_numbers', ex('POST', '/ledger', body={'account_id': 10442918, 'balance': 1532.55, 'currency': 'AUD', 'created': '2024-11-03'}, resp={'balanced': True}, cat={'json_body.currency': HN + 'identifier_lookalike'}))
scenario('neg_given_name_lookalikes', ex('POST', '/billing/cycle', body={'month': 'April', 'billing_cycle': 'June', 'note': 'Invoice issued in August'}, resp={'ok': True}, cat={f'json_body.{k}': HN + 'given_name_lookalike' for k in ('month', 'billing_cycle', 'note')}))
scenario('mixed_free_text', ex('POST', '/notifications', body={'message': 'Order shipped to Lincoln Street for ⟦PN:Marguerite Delacourt-Obi⟧ on Monday'}, resp={'queued': True}))
scenario('keepalive_cart', ex('POST', '/cart', body={'cart': 'c-88213', 'item': 'LAMP-AURORA-02'}, resp={'added': True}), ex('POST', '/cart/owner', body={'owner': '⟦PN:Sigrún Haraldsdóttir⟧', 'cart': 'c-88213'}, resp={'saved': True}))
scenario('keepalive_log', ex('GET', '/health', kind='none', resp={'status': 'ok'}), ex('POST', '/logs', body={'log': '[2025-06-02 10:21] login ok for ⟦UN:peppermint_owl_61⟧ from device Pixel'}, resp={'stored': True}))
scenario('signup_form', ex('POST', '/signup', kind='form', body={'first_name': '⟦PN:Lindiwe⟧', 'last_name': '⟦PN:Mahlangu-Reyes⟧', 'nickname': '⟦UN:solar_pebble_14⟧', 'newsletter': 'yes'}, resp={'created': True}))
scenario('profile_put', ex('PUT', '/users/profile', body={'user_name': '⟦UN:cinder_vale_28⟧', 'display': '⟦PN:Teodor Wrzesiński⟧'}, resp={'updated': True}))
scenario('standup_notes', ex('POST', '/notes', body={'title': 'Standup notes', 'body': 'Action items: ⟦PN:Haruka Ishikawa-Mendes⟧ to update the runbook; ⟦PN:Bashir Al-Rahmani⟧ to review alerts.'}, resp={'saved': True}))
scenario('audit_actor', ex('POST', '/audit', body={'event': 'password_reset_requested', 'actor': '⟦UN:willow_drift_90⟧', 'ip_hint': '203.0.113.77'}, resp={'logged': True}))
scenario('neg_contact_points', ex('POST', '/vendors/contact', body={'contact_email': 'billing@harborview.example.test', 'phone': '0412345678', 'card': '4111 1111 1111 1111'}, resp={'saved': True}, cat={f'json_body.{k}': HN + 'contact_point' for k in ('contact_email', 'phone', 'card')}))


# Second block of scenarios: more positives in varied contexts and more hard negatives (still written before any model run).
def many(prefix, items):
    for n, (method, path, kind, body, kw) in enumerate(items, 1):
        scenario(f'{prefix}{n:02d}', ex(method, path, kind=kind, body=body, **kw))


many('pos', [
    ('POST', '/customers', 'json', {'customer': {'firstName': '⟦PN:Ayesha⟧', 'familyName': '⟦PN:Karimi-Lund⟧'}}, dict(resp={'id': 8812})),
    ('POST', '/gifts', 'json', {'recipient_name': '⟦PN:Dmitri Sokolovsky⟧', 'gift_message': 'Happy birthday!'}, dict(resp={'wrapped': True})),
    ('PATCH', '/tasks/301', 'json', {'assignee': '⟦UN:granite.fox.72⟧', 'status': 'in_progress'}, dict(resp={'ok': True})),
    ('POST', '/repos/transfer', 'json', {'owner': '⟦UN:lunar-heron-09⟧', 'repo': 'inventory-service'}, dict(resp={'queued': True})),
    ('POST', '/commits', 'json', {'committer': '⟦PN:Nadira Qureshi-Bell⟧', 'message': 'Fix off-by-one in pagination'}, dict(resp={'sha': 'a41f9c2'})),
    ('POST', '/calendar/notes', 'json', {'summary': 'Meeting with ⟦PN:Percival Oyelaran⟧ moved to Thursday'}, dict(resp={'saved': True})),
    ('POST', '/mail/index', 'json', {'emailSubject': 'Re: invoice question from ⟦PN:Leontyne Achterberg⟧'}, dict(resp={'indexed': True})),
    ('POST', '/status', 'json', {'nick': '⟦UN:dusk_walker_2024⟧', 'mood': 'curious'}, dict(resp={'set': True})),
    ('POST', '/bio', 'form', {'handle': '⟦UN:amber_kettle_31⟧', 'bio': 'Coffee and code'}, dict(resp={'saved': True})),
    ('GET', '/profile?' + 'viewer=%E2%9F%A6UN%3Ariver_stone_88%E2%9F%A7&lang=en', 'none', None, dict(resp={'visible': True})),
    ('POST', '/checkin', 'json', {'passenger': {'surname': '⟦PN:Fontaine-Adeyemi⟧', 'given': '⟦PN:Cosima⟧', 'seat': '14C'}}, dict(resp={'boarding': 'B'})),
    ('POST', '/approvals', 'json', {'approved_by': '⟦PN:Emeka Obiora⟧', 'approved_at': '2025-06-03T08:30:00Z'}, dict(resp={'ok': True})),
    ('POST', '/chat/reply', 'json', {'text': 'Thanks ⟦PN:Marisol Quintanilla⟧! Will do. cc @⟦UN:pine_ledger_5⟧'}, dict(resp={'delivered': True})),
    ('POST', '/chat/mentions', 'json', {'mentions': ['@⟦UN:crimson_lark_17⟧', '@⟦UN:opal_harbor_44⟧']}, dict(resp={'notified': 2})),
    ('POST', '/parcels', 'json', {'deliver_to': 'Attn: ⟦PN:Hyun-woo Baek⟧, Level 3 Reception'}, dict(resp={'label': 'L-3318'})),
    ('POST', '/drafts', 'json', {'signature': 'Regards,\n⟦PN:Philippa Vandenberg⟧'}, dict(resp={'saved': True})),
    ('POST', '/accounts/lookup', 'json', {'user': {'id': 55, 'username': '⟦UN:jasper_wren_66⟧', 'roles': ['viewer']}}, dict(resp={'found': True})),
    ('POST', '/loyalty', 'json', {'customer_name': '⟦PN:Thandiwe Mokoena⟧', 'tier': 'standard'}, dict(resp={'points': 120})),
    ('POST', '/talks', 'json', {'speaker': 'Dr. ⟦PN:Ingeborg Strand⟧', 'topic': 'Coastal erosion'}, dict(resp={'scheduled': True})),
    ('POST', '/forward', 'json', {'cc': '⟦PN:Raul Bermúdez-Okafor⟧'}, dict(resp={'sent': True})),
    ('POST', '/rooms/join', 'json', {'participants': [{'alias': '⟦UN:tangerine_moth_81⟧'}, {'alias': '⟦UN:slate_orchid_19⟧'}]}, dict(resp={'joined': 2})),
    ('POST', '/crm/notes', 'json', {'comment': 'Spoke with ⟦PN:Anouk Verhoeven⟧ and ⟦PN:Rashid Haddad⟧ about the schedule.'}, dict(resp={'saved': True})),
    ('GET', '/users/self', 'none', None, dict(resp={'user': {'username': '⟦UN:mistral_cove_93⟧', 'display_name': '⟦PN:Saoirse Lindqvist⟧'}})),
    ('GET', '/orders/latest', 'none', None, dict(resp={'message': 'Hello ⟦PN:Takumi Fujimoto-Reyes⟧, your order has shipped.'})),
    ('POST', '/leaderboard', 'json', {'leaderboard': [{'rank': 1, 'player': '⟦UN:neon_badger_07⟧'}, {'rank': 2, 'player': '⟦UN:velvet_crow_12⟧'}]}, dict(resp={'stored': True})),
    ('POST', '/pets/register', 'json', {'given_name': '⟦PN:Ottilie⟧', 'nickname': '⟦UN:otti_the_brave⟧'}, dict(resp={'registered': True})),
])
many('neg', [
    ('POST', '/geo/resolve', 'json', {'city': 'Charlotte', 'state': 'NC'}, dict(resp={'ok': True}, cat={'json_body.city': HN + 'given_name_lookalike'})),
    ('POST', '/projects', 'json', {'project': 'Project Aurora', 'codename': 'Falcon Ridge'}, dict(resp={'ok': True}, cat={'json_body.project': HN + 'organisation_or_place', 'json_body.codename': HN + 'organisation_or_place'})),
    ('POST', '/shipping/carriers', 'json', {'carrier': 'Royal Mail Group', 'service': 'Express Parcel'}, dict(resp={'ok': True}, cat={'json_body.carrier': HN + 'company_name'})),
    ('POST', '/venues', 'json', {'venue': 'Marcus Garvey Library', 'address': '22 Oak Avenue'}, dict(resp={'ok': True}, cat={'json_body.venue': HN + 'place_name', 'json_body.address': HN + 'place_name'})),
    ('POST', '/ui/labels', 'json', {'username_field_label': 'Username', 'password_field_label': 'Password'}, dict(resp={'ok': True}, cat={'json_body.username_field_label': HN + 'ui_label', 'json_body.password_field_label': HN + 'ui_label'})),
    ('POST', '/templates', 'json', {'greeting_template': 'Welcome back, {first_name}!'}, dict(resp={'ok': True}, cat={'json_body.greeting_template': HN + 'template_placeholder'})),
    ('POST', '/search/history', 'json', {'search_history': ['wireless headphones', 'standing desk', 'usb c hub']}, dict(resp={'ok': True})),
    ('POST', '/locale', 'json', {'language': 'Swahili', 'script': 'Latin'}, dict(resp={'ok': True}, cat={'json_body.language': HN + 'given_name_lookalike'})),
    ('POST', '/pharmacy', 'json', {'medication': 'Ibuprofen', 'dose_mg': 200}, dict(resp={'ok': True})),
    ('POST', '/flights', 'json', {'airline': 'Pacific Dawn Airways', 'flight': 'PD212', 'gate': 'B7'}, dict(resp={'ok': True}, cat={'json_body.airline': HN + 'company_name'})),
    ('POST', '/auth/errors', 'json', {'error': 'User not found', 'hint': 'Check the username and try again'}, dict(resp={'ok': False}, cat={'json_body.hint': HN + 'free_text_without_names'})),
    ('POST', '/promos', 'json', {'event_name': "Mother's Day Sale", 'sponsor': 'Sunrise Foods Ltd'}, dict(resp={'ok': True}, cat={'json_body.sponsor': HN + 'company_name'})),
    ('POST', '/films', 'json', {'title': 'Dr. Strangelove retrospective'}, dict(resp={'ok': True}, cat={'json_body.title': HN + 'title_lookalike'})),
    ('POST', '/tags', 'json', {'tags': ['summer', 'beach', 'family'], 'visibility': 'public'}, dict(resp={'ok': True})),
])


# ----------------------------------------------------------------------------------------- field model (independent of TRACE)
def strip(text):
    """Return (clean text, [(start, end, label)]) in code points."""
    out, spans, last, cursor = [], [], 0, 0
    for m in MARK.finditer(text):
        out.append(text[last:m.start()])
        cursor += len(text[last:m.start()])
        spans.append((cursor, cursor + len(m.group(2)), LABEL[m.group(1)]))
        out.append(m.group(2))
        cursor += len(m.group(2))
        last = m.end()
    out.append(text[last:])
    return ''.join(out), spans


def flatten(value, path):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from flatten(v, f'{path}.{k}')
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from flatten(v, f'{path}[{i}]')
    elif value is not None:
        yield path, ('true' if value is True else 'false' if value is False else str(value))


def clean_tree(value):
    """Strip markers from every string leaf; return (clean tree, {path: spans})."""
    spans = {}

    def walk(v, path):
        if isinstance(v, dict):
            return {k: walk(x, f'{path}.{k}') for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x, f'{path}[{i}]') for i, x in enumerate(v)]
        if isinstance(v, str):
            text, found = strip(v)
            if found:
                spans[path] = found
            return text
        return v
    return walk(value, 'json_body'), spans


def build_message(kind, start_line, headers, body, is_request, cats):
    """Return (wire bytes, [field dicts]) for one HTTP message. ``headers`` is an ordered dict of extra header lines."""
    fields = []
    hdr = dict(headers)
    wire_body, spans = b'', {}
    if kind in ('json', 'gzip-json', 'chunked-json') and body is not None:
        tree, spans = clean_tree(body)
        raw = json.dumps(tree, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        hdr['Content-Type'] = 'application/json'
        if kind == 'gzip-json':
            wire_body, hdr['Content-Encoding'] = _portable_gzip(raw), 'gzip'
        elif kind == 'chunked-json':
            mid = len(raw) // 2
            wire_body = (f'{mid:X}\r\n'.encode() + raw[:mid] + b'\r\n' + f'{len(raw) - mid:X}\r\n'.encode() + raw[mid:] + b'\r\n0\r\n\r\n')
            hdr['Transfer-Encoding'] = 'chunked'
        else:
            wire_body = raw
        body_fields = [(p, t) for p, t in flatten(tree, 'json_body')]
    elif kind == 'form':
        clean = {}
        for k, v in body.items():
            clean[k], found = strip(v)
            if found:
                spans[f'form.{k}'] = found
        wire_body = urlencode(clean).encode()
        hdr['Content-Type'] = 'application/x-www-form-urlencoded'
        body_fields = [(f'form.{k}', v) for k, v in clean.items()]
    else:
        body_fields = []
    if wire_body and 'Transfer-Encoding' not in hdr:
        hdr['Content-Length'] = str(len(wire_body))
    hdr['Connection'] = 'close' if not is_request else 'keep-alive'
    head = start_line
    query_fields = []
    if is_request:
        target = start_line.split(' ')[1]
        clean_query, qspans = [], {}
        for key, value in parse_qsl(urlsplit(target).query, keep_blank_values=True):
            text, found = strip(value)
            clean_query.append((key, text))
            if found:
                qspans[f'query_parameter.{key}'] = found
        method, _, version = start_line.split(' ')
        path = target.split('?')[0]
        if clean_query:
            path += '?' + urlencode(clean_query)
            query_fields = [(f'query_parameter.{k}', v) for k, v in clean_query]
            spans.update(qspans)
        head = f'{method} {path} {version}'
    # headers: strip markers (identity headers carry marked values)
    header_fields = []
    wire_headers = []
    for name, value in hdr.items():
        text, found = strip(value)
        if found:
            spans[f'header.{name.lower()}'] = found
        wire_headers.append(f'{name}: {text}')
        header_fields.append((f'header.{name.lower()}', text))
    wire = (head + '\r\n' + '\r\n'.join(wire_headers) + '\r\n\r\n').encode('utf-8') + wire_body
    for location, text in header_fields + query_fields + body_fields:
        fields.append({'location': location, 'text': text, 'spans': spans.get(location, []), 'category': cats.get(location)})
    return wire, fields


# ----------------------------------------------------------------------------------------- packets
def _sum16(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def frame(src, dst, sp, dp, seq, ack, flags, payload, ident):
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack('!HHIIHHHH', sp, dp, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, (5 << 12) | flags, 32768, 0, 0)
    tcp = tcp[:16] + struct.pack('!H', _sum16(s + d + struct.pack('!BBH', 0, 6, len(tcp) + len(payload)) + tcp + payload)) + tcp[18:] + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), ident & 0xFFFF, 0x4000, 64, 6, 0, s, d)
    ip = ip[:10] + struct.pack('!H', _sum16(ip)) + ip[12:]
    return b'\x02\xaa\xbb\xcc\xdd\x01\x02\xaa\xbb\xcc\xdd\x02\x08\x00' + ip + tcp


def build():
    packets, fields_out, ident = [], [], 0
    for index, (name, exchanges) in enumerate(S):
        src, dst, sport, dport = CLIENT + str(10 + index), SERVER + str(20 + index % 3), 43100 + index, 80
        client, server = f'{src}:{sport}', f'{dst}:{dport}'
        t = BASE_TIME + index * 0.25
        cseq, sseq = 10000 + index * 5000, 20000 + index * 5000

        def emit(a, b, ap, bp, seq, ack, flags, payload=b''):
            nonlocal ident
            packets.append((t + len(packets) * 1e-6, frame(a, b, ap, bp, seq, ack, flags, payload, ident)))
            ident += 1
        emit(src, dst, sport, dport, cseq, 0, 0x02)
        emit(dst, src, dport, sport, sseq, cseq + 1, 0x12)
        emit(src, dst, sport, dport, cseq + 1, sseq + 1, 0x10)
        c_off, s_off = 0, 0
        for ordinal, e in enumerate(exchanges, 1):
            host = f'{name.replace("_", "-")}.example.test'
            req_headers = {'Host': host, **e['headers']}
            wire, fields = build_message(e['kind'], f"{e['method']} {e['path']} HTTP/1.1", req_headers, e['body'], True, e['cat'])
            for f in fields:
                f.update(message_type='request', ordinal=ordinal, client=client, server=server)
            fields_out += fields
            for pos in range(0, len(wire), 700):
                chunk = wire[pos:pos + 700]
                emit(src, dst, sport, dport, cseq + 1 + c_off + pos, sseq + 1 + s_off, 0x18, chunk)
            c_off += len(wire)
            resp_wire, rfields = build_message(e['resp_kind'], 'HTTP/1.1 200 OK', {}, e['resp'], False, e['resp_cat'])
            for f in rfields:
                f.update(message_type='response', ordinal=ordinal, client=client, server=server)
            fields_out += rfields
            emit(dst, src, dport, sport, sseq + 1 + s_off, cseq + 1 + c_off, 0x18, resp_wire)
            s_off += len(resp_wire)
    return packets, fields_out


def write_pcap(path, packets):
    with open(path, 'wb') as out:
        out.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            sec = int(ts)
            out.write(struct.pack('<IIII', sec, int(round((ts - sec) * 1e6)), len(data), len(data)) + data)


def manifest(fields, pcap_bytes):
    entries, seen = [], {}
    for n, f in enumerate(fields, 1):
        key = (f['client'], f['server'], f['message_type'], f['ordinal'], f['location'])
        occurrence = seen.get(key, 0)
        seen[key] = occurrence + 1
        category = f['category'] or ('positive' if f['spans'] else 'negative:ordinary')
        if f['spans'] and f['location'].startswith('header.'):
            category = 'positive:header'
        elif f['spans'] and f['message_type'] == 'response':
            category = 'positive:response'
        elif f['spans']:
            category = 'positive:request'
        elif f['category'] is None and f['location'].startswith('header.'):
            category = 'negative:header'
        entries.append({
            'field_id': f'f{n:04d}',
            'flow': {'client': f['client'], 'server': f['server']},
            'message': {'type': f['message_type'], 'ordinal': f['ordinal']},
            'location': f['location'], 'occurrence': occurrence,
            'text_sha256': hashlib.sha256(f['text'].encode('utf-8')).hexdigest(), 'text_length': len(f['text']),
            'spans': [{'start': a, 'end': b, 'label': l} for a, b, l in f['spans']],
            'category': category.replace(' ', '_')})
    return {
        'schema_version': 'trace-ground-truth/1',
        'dataset': {
            'name': 'TRACE controlled fixture v1',
            'kind': 'controlled_synthetic_fixture',
            'description': ('Fictional HTTP/1.1 traffic built by examples/generate_groundtruth_fixture.py. Names and usernames are '
                            'invented; every span was recorded when the text was constructed. Contains hard negatives '
                            '(companies, places, products, identifier look-alikes, given-name look-alikes).'),
            'created': '2025-06-02',
            'synthetic': True,
            'provenance': {'label_source': 'constructed_by_generator', 'labels_derived_from_model_output': False,
                           'generator': 'examples/generate_groundtruth_fixture.py',
                           'notes': 'Scenario table fixed before any model was run on it. All fields of every message are listed.'}},
        'capture': {'sha256': hashlib.sha256(pcap_bytes).hexdigest(), 'bytes': len(pcap_bytes)},
        'labels': ['PERSON_NAME', 'USERNAME'],
        'annotation_scope': 'all_fields_in_listed_messages',
        'fields': entries}


def generate(out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    packets, fields = build()
    pcap = out / 'controlled_fixture_v1.pcap'
    write_pcap(pcap, packets)
    doc = manifest(fields, pcap.read_bytes())
    target = out / 'controlled_fixture_v1.manifest.json'
    target.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    return pcap, target


if __name__ == '__main__':
    directory = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parent / 'groundtruth')
    pcap_path, manifest_path = generate(directory)
    print(pcap_path, manifest_path)
