"""End-to-end tests use generated synthetic traffic, never personal user captures."""
import importlib.util
from pathlib import Path
import pytest
from packet_pii.engine import analyze
from packet_pii.http_extract import HttpMessage, extract_fields,parse_http_stream
from packet_pii.detect import detect_fields

SCRIPT=Path(__file__).resolve().parents[1]/'examples'/'generate_demo.py'
spec=importlib.util.spec_from_file_location('generate_demo',SCRIPT)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

@pytest.mark.parametrize('extension',['pcap','pcapng'])
def test_synthetic_capture(tmp_path,extension):
    file=tmp_path/f'demo.{extension}'
    (mod.write_pcapng if extension=='pcapng' else mod.write_pcap)(file)
    report=analyze(file)
    summary=report['summary']
    assert summary['packets_captured']==8
    assert summary['flows_processed']==1
    assert summary['http_messages']==2
    assert summary['stream_gaps']==0
    items={(f['pii_type'],f['location']) for f in report['findings']}
    assert ('EMAIL','json_body.email') in items
    assert ('PHONE','query_parameter.phone') in items
    assert ('CREDIT_CARD','json_body.card') in items
    assert ('PERSON_NAME_CANDIDATE','json_body.full_name') in items
    assert ('CREDENTIAL_OR_TOKEN','json_body.password') in items
    assert ('CREDENTIAL_OR_TOKEN','header.authorization') in items
    assert summary['potential_leaks']>=5
    assert not any(f['value']=='demo-only-secret' for f in report['findings'])
    assert not any(f['value']=='student@example.com' for f in report['findings'])
    assert not any('0412345678' in f['http_start_line'] for f in report['findings'])
    assert any(f['source_ip']=='192.0.2.10' for f in report['findings'])
    assert any(f['source_ip']=='198.51.100.20' for f in report['findings'])


def test_include_values_explicit(tmp_path):
    file=tmp_path/'demo.pcap';mod.write_pcap(file)
    report=analyze(file,include_values=True)
    assert any(f['value']=='student@example.com' for f in report['findings'])


def test_threshold(tmp_path):
    file=tmp_path/'demo.pcap';mod.write_pcap(file)
    report=analyze(file,threshold=0.99)
    assert all(f['confidence']>=0.99 for f in report['findings'])
    with pytest.raises(ValueError):analyze(file,1.1)


def test_truncated_packet_ignored(tmp_path):
    file=tmp_path/'demo.pcap';mod.write_pcap(file)
    with file.open('ab') as stream:
        stream.write(b'\x00'*8)
    assert analyze(file)['summary']['http_messages']==2


def test_form_and_chunked():
    msg=(b'POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n'
         b'Transfer-Encoding: chunked\r\n\r\n'
         b'1b\r\nemail=alex%40example.com&x=1\r\n0\r\n\r\n')
    # Verify exact chunk size instead of assuming a fixed length
    body=b'email=alex%40example.com&x=1'
    msg=(b'POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n'
         b'Transfer-Encoding: chunked\r\n\r\n'+f'{len(body):x}\r\n'.encode()+body+b'\r\n0\r\n\r\n')
    parsed=parse_http_stream(msg)
    assert len(parsed)==1
    assert ('form.email','alex@example.com') in extract_fields(parsed[0])


def test_multipart_form():
    body=(b'--BoundXYZ\r\nContent-Disposition: form-data; name="email"\r\n\r\n'
          b'hello@example.com\r\n--BoundXYZ--\r\n')
    obj=HttpMessage('POST / HTTP/1.1',{'content-type':'multipart/form-data; boundary=BoundXYZ'},body,True)
    assert ('form.email','hello@example.com') in extract_fields(obj)


def test_incomplete_http_skipped():
    assert parse_http_stream(b'POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort')==[]


def test_rules_reject_invalid_card():
    assert not any(d.pii_type=='CREDIT_CARD' for d in detect_fields([('body.text','4111 1111 1111 1112')]))
