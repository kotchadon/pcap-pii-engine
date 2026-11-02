"""Per-scan TRACE detection selection: real local HTTP, no external traffic."""
from contextlib import contextmanager
from http.client import HTTPConnection
import json
import threading

from packet_pii.dashboard import DashboardServer
from packet_pii.ml import EntityLabel, EntitySpan, ScoreType


class CountingDetector:
    model_version = "test-v2"
    def __init__(self):
        self.calls = 0

    def predict_fields(self, fields):
        self.calls += 1
        spans = []
        for f in fields:
            i = f.text.find("Alex Example")
            if i >= 0:
                spans.append(EntitySpan(f.field_index, EntityLabel.PERSON_NAME, i,
                                        i + len("Alex Example"), self.model_version,
                                        0.91, ScoreType.UNCALIBRATED_MODEL_SCORE))
        return spans


@contextmanager
def server_with(detector):
    server = DashboardServer(("127.0.0.1", 0), ml_detector=detector)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=4)


def request(server, method, path, token=None, mode=None):
    headers = {}
    if token is not None:
        headers["X-Dashboard-Token"] = token
    if mode is not None:
        headers["X-Detection-Mode"] = mode
    c = HTTPConnection("127.0.0.1", server.server_port, timeout=10)
    c.request(method, path, headers=headers)
    resp = c.getresponse()
    result = (resp.status, json.loads(resp.read()))
    c.close()
    return result


def test_user_can_switch_between_rules_and_real_model():
    detector = CountingDetector()
    with server_with(detector) as server:
        session = request(server, "GET", "/api/session")[1]
        assert session["model_available"] is True
        assert session["model_version"] == "test-v2"
        status, rules = request(server, "POST", "/api/demo", session["token"], "rules")
        assert status == 200
        assert rules["model_enabled"] is False
        assert rules["scan_mode"] == "rules"
        assert rules["report"]["summary"]["ml_findings"] == 0
        assert detector.calls == 0
        status, hybrid = request(server, "POST", "/api/demo", session["token"], "hybrid")
        assert status == 200
        assert hybrid["model_enabled"] is True
        assert hybrid["scan_mode"] == "hybrid"
        assert hybrid["report"]["metadata"]["ml_model_version"] == "test-v2"
        assert hybrid["report"]["summary"]["ml_findings"] == 1
        assert detector.calls > 0
        assert "Alex Example" in json.dumps(hybrid), "Client-facing name should be shown in full"


def test_unavailable_ml_and_invalid_modes_fail_closed():
    with server_with(None) as server:
        session = request(server, "GET", "/api/session")[1]
        assert session["model_available"] is False
        assert request(server, "POST", "/api/demo", session["token"], "hybrid")[0] == 422
        assert request(server, "POST", "/api/demo", session["token"], "invalid")[0] == 400
        assert request(server, "POST", "/api/demo", session["token"], "rules")[0] == 200
