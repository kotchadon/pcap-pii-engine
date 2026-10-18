"""Real synthetic PCAP through production parser, detector and local dashboard.

The showcase contains no hardcoded report output: results come from analyze().
"""
from __future__ import annotations

from contextlib import contextmanager
from http.client import HTTPConnection
import json
from pathlib import Path
import threading

from packet_pii.dashboard import DashboardServer
from packet_pii.engine import analyze
from packet_pii.ml import EntityLabel, EntitySpan, ScoreType


def _capture(tmp_path):
    from importlib.util import module_from_spec, spec_from_file_location
    file = Path(__file__).resolve().parents[1] / "examples" / "generate_showcase.py"
    spec = spec_from_file_location("_showcase_test", file)
    mod = module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    out = tmp_path / "showcase.pcap"
    mod.write_pcap(out)
    assert len(mod.SCENARIOS) == 12
    return out


def test_showcase_real_http_and_rule_findings(tmp_path):
    capture = _capture(tmp_path)
    report = analyze(capture)
    s = report["summary"]
    assert s["flows_processed"] == 12
    assert s["http_messages"] == 24
    assert s["http_transactions"] == 12
    assert s["packets_captured"] >= 70
    assert s["rules_findings"] >= 12
    assert s["ml_findings"] == 0
    assert s["analysis_incomplete"] is False
    types = {f["pii_type"] for f in report["findings"]}
    assert {"EMAIL", "PHONE", "CREDIT_CARD", "CREDENTIAL_OR_TOKEN", "PERSON_NAME_CANDIDATE", "USERNAME"} <= types
    output = json.dumps(report)
    for raw in ("Priyanka Venkataraman", "night_owl_77", "fictional-demo-password", "4111 1111 1111 1111"):
        assert raw not in output
    assert all("fingerprint" not in f for f in report["findings"])


def test_generator_is_deterministic(tmp_path):
    first = _capture(tmp_path / "a") if False else None
    # Avoid relying on timestamps or random process state: separate files, same bytes.
    from importlib.util import module_from_spec, spec_from_file_location
    file = Path(__file__).resolve().parents[1] / "examples" / "generate_showcase.py"
    spec = spec_from_file_location("_showcase_determinism", file)
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    mod.write_pcap(a)
    mod.write_pcap(b)
    assert a.read_bytes() == b.read_bytes()


class MockV2:
    model_version = "test-bilstm-v2"

    def predict_fields(self, fields):
        spans = []
        for f in fields:
            for value, label in (("Priyanka Venkataraman", EntityLabel.PERSON_NAME),
                                 ("night_owl_77", EntityLabel.USERNAME)):
                start = f.text.find(value)
                if start >= 0:
                    spans.append(EntitySpan(f.field_index, label, start, start + len(value),
                                            self.model_version, 0.91,
                                            ScoreType.UNCALIBRATED_MODEL_SCORE))
        return spans


def test_showcase_hybrid_provenance_is_live(tmp_path):
    capture = _capture(tmp_path)
    report = analyze(capture, ml_detector=MockV2())
    summary = report["summary"]
    assert summary["ml_fields_evaluated"] >= 12
    assert summary["ml_findings"] >= 3
    assert summary["rules_findings"] >= 12
    for f in report["findings"]:
        if f["detector"] == "bilstm":
            assert f["model_version"] == "test-bilstm-v2"
            assert f["confidence_type"] == "uncalibrated_model_score"
            assert f["span_start"] < f["span_end"]
            assert f["http_message_id"]
            assert f["flow_id"]
    assert "Priyanka Venkataraman" not in json.dumps(report)


@contextmanager
def _server(detector):
    s = DashboardServer(("127.0.0.1", 0), ml_detector=detector)
    thread = threading.Thread(target=s.serve_forever, daemon=True)
    thread.start()
    try:
        yield s
    finally:
        s.shutdown()
        s.server_close()
        thread.join(timeout=4)


def _req(s, method, url, token=None, mode=None):
    c = HTTPConnection("127.0.0.1", s.server_port, timeout=20)
    headers = {}
    if token:
        headers["X-Dashboard-Token"] = token
    if mode:
        headers["X-Detection-Mode"] = mode
    c.request(method, url, headers=headers)
    response = c.getresponse()
    result = response.status, json.loads(response.read())
    c.close()
    return result


def test_showcase_endpoint_real_detection_and_mode_switch():
    with _server(MockV2()) as s:
        _, session = _req(s, "GET", "/api/session")
        status, rules = _req(s, "POST", "/api/showcase", session["token"], "rules")
        assert status == 200
        assert rules["filename"] == "trace-vp-showcase.pcap"
        assert rules["report"]["summary"]["http_messages"] == 24
        assert rules["report"]["summary"]["ml_findings"] == 0
        assert rules["model_enabled"] is False
        status, hybrid = _req(s, "POST", "/api/showcase", session["token"], "hybrid")
        assert status == 200
        assert hybrid["model_enabled"] is True
        assert hybrid["report"]["summary"]["http_messages"] == 24
        assert hybrid["report"]["summary"]["ml_findings"] > 0
        assert hybrid["report"]["metadata"]["ml_model_version"] == "test-bilstm-v2"
        assert rules["report"]["summary"]["rules_findings"] == hybrid["report"]["summary"]["rules_findings"]
        assert "night_owl_77" not in json.dumps(hybrid)


def test_showcase_with_real_saved_model_when_available(tmp_path):
    import pytest
    pytest.importorskip("torch")
    from packet_pii.hybrid import load_experimental_bilstm
    checkpoint = (Path(__file__).resolve().parents[1] / "src" / "packet_pii"
                  / "ml" / "artifacts" / "bilstm_v2")
    det = load_experimental_bilstm(str(checkpoint))
    r = analyze(_capture(tmp_path), ml_detector=det)
    assert r["metadata"]["ml_model_version"] == det.model_version
    assert r["summary"]["ml_fields_evaluated"] >= 12
    assert r["summary"]["http_messages"] == 24
    assert r["summary"]["rules_findings"] >= 12
    # Avoid asserting a specific model output; research models can have false negatives.
