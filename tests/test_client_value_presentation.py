"""Client-facing value presentation: ordinary values visible, credentials inspectable separately.

The default low-level API stays masked. The dashboard's authenticated job
path selects the noncredential display policy and publishes its value policy.
"""
from packet_pii.detect import detect_fields
from packet_pii.engine import analyze
from pathlib import Path


def test_default_low_level_detection_is_still_masked():
    fields=[('json_body.full_name','Aaradhita Sharma'),
            ('json_body.email','person@example.test'),
            ('json_body.password','fixture-secret-value')]
    findings=detect_fields(fields)
    assert 'Aaradhita Sharma' not in [f.value for f in findings]
    assert 'person@example.test' not in [f.value for f in findings]
    assert 'fixture-secret-value' not in [f.value for f in findings]


def test_client_view_shows_ordinary_values_but_not_any_secret_field():
    fields=[('json_body.full_name','Aaradhita Sharma'),
            ('json_body.email','person@example.test'),
            ('json_body.phone','+61412345678'),
            ('json_body.password','fixture-secret-value'),
            ('json_body.token','person@example.test'),
            ('header.authorization','Bearer fixture-secret-value')]
    findings=detect_fields(fields,display_nonsecret_values=True)
    values={(f.pii_type,f.location):f.value for f in findings}
    assert values['PERSON_NAME_CANDIDATE','json_body.full_name']=='Aaradhita Sharma'
    assert values['EMAIL','json_body.email']=='person@example.test'
    assert any(f.location=='json_body.phone' and f.value=='+61412345678' for f in findings)
    assert all(f.value!='fixture-secret-value' for f in findings)
    assert all(f.value!='person@example.test' for f in findings if f.location=='json_body.token')
    assert all(f.value!='Bearer fixture-secret-value' for f in findings)


def test_original_visibility_is_explicit_in_report_metadata(tmp_path):
    from importlib.util import module_from_spec, spec_from_file_location
    root=Path(__file__).resolve().parents[1]
    spec=spec_from_file_location('trace_demo_values',root/'examples/generate_mentor_demo.py')
    module=module_from_spec(spec);spec.loader.exec_module(module)
    source=tmp_path/'demo.pcap';module.write_demo(source)
    redacted=analyze(source)
    client=analyze(source,display_nonsecret_values=True)
    assert redacted['metadata']['raw_values_included'] is False
    assert redacted['metadata']['finding_value_policy']=='masked'
    assert client['metadata']['raw_values_included'] is True
    assert client['metadata']['finding_value_policy']=='noncredential_original'
    assert redacted['summary']['potential_leaks']==client['summary']['potential_leaks']
    assert [(x['pii_type'],x['location']) for x in redacted['findings']]==[
        (x['pii_type'],x['location']) for x in client['findings']]
    assert any(f['pii_type']=='EMAIL' and '@' in f['value'] and '***' not in f['value']
               for f in client['findings'])
    assert all('fictional-demo-only-token' not in f['value'] for f in client['findings'])
