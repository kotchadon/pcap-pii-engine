import json
from html.parser import HTMLParser

import pytest

from packet_pii.static_page import project_content, export_document, MAX_NODES, MAX_DEPTH
from test_http_investigation import evidence, server, upload, request


def recovered(text, status='recovered'):
    return dict(text=text, is_html=True, verification='capture_sha256_reverified', status=status)


def test_static_projection_preserves_captured_text_structure_but_no_active_content():
    source = ('<base href="https://example.invalid"><h1 onclick="attack()">Receipt</h1>'
              '<p>Élodie &amp; Alex &lt;script&gt;</p><script>attack()</script>'
              '<style>body{background:url(https://example.invalid)}</style>'
              '<svg><script>attack()</script><text>foreign</text></svg>'
              '<a href="javascript:attack()">captured link text</a><img src=x onerror=attack()>'
              '<form action="https://example.invalid"><input value="secret"><p>Form label</p></form>'
              '<table><tr><td>captured cell</td></tr></table>')
    projection = project_content(recovered(source))
    document = export_document(projection)
    assert 'Receipt' in document and 'Élodie &amp; Alex &lt;script&gt;' in document
    assert '<td>captured cell</td>' in document and 'captured link text' in document
    assert 'attack()' not in document and 'foreign' not in document and 'secret' not in document
    assert 'https://' not in document and 'javascript:' not in document
    class Check(HTMLParser):
        def handle_starttag(self, tag, attrs):
            assert tag not in {'script','style','img','iframe','object','svg','form','input','a','base'}
            assert not any(k.startswith('on') or k in {'src','href','style','srcdoc'} for k,_ in attrs)
    Check().feed(document)
    assert projection['resources_recovered']==0 and projection['attributes_discarded']>0
    assert projection['omitted_elements']['script']==1


def test_projection_bounds_partial_and_invalid_sources():
    p=project_content(recovered('<div>'*(MAX_DEPTH+2)+'value'))
    assert p['projection_truncated'] and 'Partial source' in export_document(p)
    p=project_content(recovered('<br>'*(MAX_NODES+1)))
    assert p['projection_truncated'] and p['node_count']==MAX_NODES
    p=project_content(recovered('<p>partial',status='partial'))
    assert p['source_status']=='partial' and 'incomplete' in export_document(p)
    for source in ({'text':'x','is_html':False}, recovered('x'*65537)):
        with pytest.raises(ValueError):project_content(source)


def test_static_api_requires_same_authorization_ack_and_retained_source(evidence):
    path, _, report, _=evidence
    with server(retain=True) as s:
        job=upload(s,path)
        url='/api/jobs/'+job.job_id+'/content'
        payload={'message_id':report['http_evidence'][2]['http_message_id'],
                 'acknowledge_sensitive_content':True,'representation':'static'}
        headers={'Content-Type':'application/json'}
        assert request(s,'POST',url,json.dumps(payload),headers,auth=False)[0]==403
        no_ack=dict(payload,acknowledge_sensitive_content=False)
        assert request(s,'POST',url,json.dumps(no_ack),headers)[0]==400
        code, data, _=request(s,'POST',url,json.dumps(payload),headers)
        assert code==200 and data['verification']=='capture_sha256_reverified'
        p=data['static_representation']
        assert 'Profile received' in export_document(p) and p['omitted_elements']['script']==1
        assert 'TRACE_UNTRUSTED_EXECUTED' not in json.dumps(p)
        payload['representation']='live'
        assert request(s,'POST',url,json.dumps(payload),headers)[0]==400
