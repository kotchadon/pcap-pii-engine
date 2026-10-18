"""Local dashboard integration tests: real HTTP endpoints, security and report integrity."""
from contextlib import contextmanager
from http.client import HTTPConnection
import json
from pathlib import Path
import threading
from urllib.parse import urlparse

from packet_pii.dashboard import DashboardServer
from packet_pii.engine import analyze


@contextmanager
def running_server():
    server = DashboardServer(('127.0.0.1', 0))
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=4)


def query(server, method, path, body=None, headers=None):
    conn = HTTPConnection('127.0.0.1', server.server_port, timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    data = response.read()
    status = response.status
    response_headers = dict(response.getheaders())
    conn.close()
    return status, data, response_headers


def test_dashboard_serves_assets_without_external_dependencies():
    with running_server() as server:
        for name in ('/', '/app.js', '/app.css'):
            status, data, h = query(server, 'GET', name)
            assert status == 200 and len(data) > 100
            assert "default-src 'self'" in h['Content-Security-Policy']
            assert h['X-Content-Type-Options'] == 'nosniff'
        status, _, _ = query(server, 'GET', '/foo')
        assert status == 404


def test_synthetic_demo_uses_real_capture_engine():
    with running_server() as server:
        code, body, _ = query(server, 'GET', '/api/session')
        assert code == 200
        token = json.loads(body)['token']
        code, body, _ = query(server, 'POST', '/api/demo', headers={'X-Dashboard-Token': token})
        assert code == 200
        result = json.loads(body)
        report = result['report']
        assert report['summary']['packets_captured'] == 8
        assert report['summary']['potential_leaks'] == 7
        assert report['metadata']['detection_method'] == 'rules_only'
        assert result['model_enabled'] is False
        assert all('fingerprint' not in f for f in report['findings'])
        assert all(f['value'] != 'demo-only-secret' for f in report['findings'])


def test_dashboard_upload_real_pcap(tmp_path):
    from importlib.util import spec_from_file_location, module_from_spec
    demo = Path(__file__).resolve().parents[1] / 'examples' / 'generate_demo.py'
    spec = spec_from_file_location('synthetic', demo)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    file = tmp_path / 'in.pcap'
    module.write_pcap(file)
    with running_server() as server:
        token = json.loads(query(server, 'GET', '/api/session')[1])['token']
        code, body, _ = query(server, 'POST', '/api/analyze', body=file.read_bytes(), headers={
            'X-Dashboard-Token': token, 'Content-Type': 'application/octet-stream',
            'X-Capture-Name': 'in.pcap'})
        assert code == 200
        assert json.loads(body)['report']['summary']['potential_leaks'] == 7


def test_dashboard_denies_cross_site_and_tokenless_requests():
    with running_server() as server:
        assert query(server, 'POST', '/api/demo')[0] == 403
        token = json.loads(query(server, 'GET', '/api/session')[1])['token']
        assert query(server, 'POST', '/api/demo', headers={
            'X-Dashboard-Token': token, 'Origin': 'https://attacker.example'})[0] == 403
        assert query(server, 'GET', '/', headers={'Host': 'attacker.example'})[0] == 403
        assert query(server, 'POST', '/api/analyze', headers={
            'X-Dashboard-Token': token, 'Content-Type': 'application/octet-stream',
            'X-Capture-Name': 'test.pcap', 'Content-Length': '10000000000'})[0] == 413
