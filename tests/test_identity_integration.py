"""Identity categories flow through the real engine: PCAP -> HTTP fields -> detect_fields -> report (fictional values)."""
import importlib.util
import json
from pathlib import Path

import pytest

from packet_pii.engine import analyze
from packet_pii.ml import EntityLabel, EntitySpan, ScoreType

IDFA = 'E621E1F8-C36C-495A-93FC-0C247A3E6E5F'
GAID = '38400000-8cf0-11bd-b23e-10b96e40000d'
RAW = [IDFA, GAID, 'non-binary', 'acct_7Hq2x9', 'a1b2c3d4e5f60718']


def _module():
    script = Path(__file__).resolve().parents[1] / 'examples' / 'generate_demo.py'
    spec = importlib.util.spec_from_file_location('identity_demo', script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def capture(tmp_path):
    mod = _module()
    body = json.dumps({'idfa': IDFA, 'device': {'os': 'Android 14', 'advertising_id': GAID, 'id': 'a1b2c3d4e5f60718'},
                       'user': {'age': 27, 'gender': 'non-binary', 'full_name': 'Alex Example'},
                       'account_id': 'acct_7Hq2x9', 'page': 27, 'request_id': '9b2f6c1e-4d7a-4c3b-8e2f-1a6d5c4b3a29'}).encode()
    request = (b'POST /collect?sex=F&retry_count=3 HTTP/1.1\r\nHost: ads.example\r\nContent-Type: application/json\r\n'
               b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
    response = b'HTTP/1.1 204 No Content\r\nAge: 27\r\nContent-Length: 0\r\n\r\n'
    client, server = '192.0.2.10', '198.51.100.20'

    def packets():
        return [(1.0, mod.tcp_frame(client, 50123, server, 80, 1000, b'', 0x02)),
                (1.01, mod.tcp_frame(server, 80, client, 50123, 2000, b'', 0x12)),
                (1.02, mod.tcp_frame(client, 50123, server, 80, 1001, b'', 0x10)),
                (1.10, mod.tcp_frame(client, 50123, server, 80, 1001, request)),
                (1.30, mod.tcp_frame(server, 80, client, 50123, 2001, response))]
    mod.packets = packets
    path = tmp_path / 'identity.pcap'
    mod.write_pcap(path)
    return path


EXPECTED = {('APPLE_ADVERTISING_ID', 'json_body.idfa'), ('ANDROID_ADVERTISING_ID', 'json_body.device.advertising_id'),
            ('DEVICE_ID', 'json_body.device.id'), ('AGE', 'json_body.user.age'), ('GENDER', 'json_body.user.gender'),
            ('USER_ACCOUNT_ID', 'json_body.account_id'), ('SEX', 'query_parameter.sex')}
IDENTITY = {kind for kind, _ in EXPECTED} | {'ADVERTISING_ID'}


class StubModel:
    model_version = 'stub-v1'

    def predict_fields(self, fields):
        out = []
        for f in fields:
            start = f.text.find('Alex Example')
            if start >= 0:
                out.append(EntitySpan(f.field_index, EntityLabel.PERSON_NAME, start, start + 12, self.model_version, 0.91,
                                      ScoreType.UNCALIBRATED_MODEL_SCORE))
        return out


def test_rules_only_report_contains_masked_identity_findings(capture):
    report = analyze(capture)
    assert report['metadata']['detection_method'] == 'rules_only'
    found = {(f['pii_type'], f['location']) for f in report['findings'] if f['pii_type'] in IDENTITY}
    assert found == EXPECTED  # page, retry_count, request_id and the HTTP ``Age`` header stay unclassified
    for f in report['findings']:
        if f['pii_type'] in IDENTITY:
            assert f['detector'] == 'rule' and f['flow_id'] and f['http_message_id']
            assert 'fingerprint' not in f
    dumped = json.dumps(report)
    for raw in RAW:
        assert raw not in dumped


def test_hybrid_keeps_identity_findings_rule_attributed(capture):
    rules = analyze(capture)
    hybrid = analyze(capture, ml_detector=StubModel())
    assert hybrid['metadata']['detection_method'] == 'rules_plus_bilstm'
    assert hybrid['summary']['rules_findings'] == rules['summary']['rules_findings']
    rule_rows = sorted((f['pii_type'], f['location']) for f in hybrid['findings'] if f['detector'] == 'rule')
    assert rule_rows == sorted((f['pii_type'], f['location']) for f in rules['findings'])
    ml_rows = [f for f in hybrid['findings'] if f['detector'] == 'bilstm']
    assert {f['pii_type'] for f in ml_rows} == {'PERSON_NAME'}
    assert not any(f['pii_type'] in IDENTITY for f in ml_rows)
