"""HTTP-level checks for opt-in hybrid mode, no real PCAP or external network."""
from contextlib import contextmanager
from http.client import HTTPConnection
import json
import threading

from packet_pii.dashboard import DashboardServer
from packet_pii.ml import EntityLabel, EntitySpan, ScoreType


class FakeContextDetector:
    model_version = 'synthetic-test-v1'

    def predict_fields(self, fields):
        result = []
        for field in fields:
            start = field.text.find('Alex Example')
            if start >= 0:
                result.append(EntitySpan(field.field_index, EntityLabel.PERSON_NAME,
                                         start, start + 12, self.model_version,
                                         0.91, ScoreType.UNCALIBRATED_MODEL_SCORE))
        return result


@contextmanager
def live_server(detector):
    server = DashboardServer(('127.0.0.1', 0), ml_detector=detector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def call(server, method, path, **headers):
    connection = HTTPConnection('127.0.0.1', server.server_port, timeout=10)
    connection.request(method, path, headers=headers)
    response = connection.getresponse()
    body = response.read()
    status = response.status
    connection.close()
    return status, json.loads(body)


def test_dashboard_reports_selected_model_and_live_evidence():
    with live_server(FakeContextDetector()) as server:
        status, session = call(server, 'GET', '/api/session')
        assert status == 200
        assert session['model_enabled'] is True
        assert session['model_version'] == 'synthetic-test-v1'
        status, result = call(server, 'POST', '/api/demo', **{'X-Dashboard-Token': session['token']})
        assert status == 200
        assert result['model_enabled'] is True
        assert result['report']['summary']['rules_findings'] == 7
        assert result['report']['summary']['ml_findings'] == 1
        item = next(x for x in result['report']['findings'] if x['detector'] == 'bilstm')
        assert item['value'] == 'Alex Example'
        assert item['confidence_type'] == 'uncalibrated_model_score'
        assert item['model_version'] == 'synthetic-test-v1'
        assert 'Alex Example' in json.dumps(result)


def test_dashboard_default_mode_is_explicitly_rules_only():
    with live_server(None) as server:
        status, session = call(server, 'GET', '/api/session')
        assert status == 200
        assert session['model_enabled'] is False
        assert session['detector_mode'] == 'rules_only'
        assert session['model_version'] is None
