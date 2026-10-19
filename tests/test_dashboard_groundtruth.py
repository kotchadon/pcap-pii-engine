"""Dashboard ground-truth flow: manifest upload, evaluation inside a scan job, download and rejection paths."""
import json
from pathlib import Path

import pytest

from packet_pii.ml import EntityLabel, EntitySpan, ScoreType
from test_dashboard_jobs import finish, request, server

ROOT = Path(__file__).resolve().parents[1]
SHOWCASE_MANIFEST = ROOT / 'examples' / 'groundtruth' / 'showcase_demo.manifest.json'


class NameDetector:
    """Flags fixed fictional strings anywhere in a field (deterministic test double)."""
    model_version = 'name-detector-1'
    LABELS = {'Priyanka Venkataraman': 'PERSON_NAME', 'Alex Example': 'PERSON_NAME', 'night_owl_77': 'USERNAME'}

    def predict_fields(self, fields):
        out = []
        for f in fields:
            for text, label in self.LABELS.items():
                at = f.text.find(text)
                if at >= 0:
                    out.append(EntitySpan(f.field_index, EntityLabel(label), at, at + len(text), self.model_version, .9,
                                          ScoreType.UNCALIBRATED_MODEL_SCORE))
        return out


def headers(s, **extra):
    return {'X-Dashboard-Token': s.token, **extra}


def upload_manifest(s, data=None, **extra):
    body = SHOWCASE_MANIFEST.read_bytes() if data is None else data
    return request(s, 'POST', '/api/manifests', body=body, headers=headers(s, **{'Content-Type': 'application/json', **extra}))


def start(s, request_id, path='/api/jobs/showcase', mode='rules', manifest_id=None):
    extra = {'X-Request-ID': request_id, 'X-Detection-Mode': mode, 'X-Analysis-Profile': 'standard'}
    if manifest_id:
        extra['X-Ground-Truth-Manifest'] = manifest_id
    return request(s, 'POST', path, headers=headers(s, **extra))


def test_manifest_upload_validates_and_returns_only_a_public_summary():
    with server() as s:
        code, body, _ = upload_manifest(s)
        data = json.loads(body)
        assert code == 201 and len(data['manifest_id']) == 32 and data['manifest']['kind'] == 'hand_designed_demonstration'
        assert data['manifest']['fields'] == 12 and 'text_sha256' not in json.dumps(data) and data['manifest']['labels_derived_from_model_output'] is False
        broken = json.loads(SHOWCASE_MANIFEST.read_text())
        broken['dataset']['provenance']['labels_derived_from_model_output'] = True
        code, body, _ = upload_manifest(s, json.dumps(broken).encode())
        assert code == 400 and 'model output cannot be reference truth' in json.loads(body)['error']
        assert upload_manifest(s, b'not json')[0] == 400
        assert request(s, 'POST', '/api/manifests', body=b'{}', headers=headers(s, **{'Content-Type': 'text/plain'}))[0] == 415
        assert request(s, 'POST', '/api/manifests', body=b'{}', headers={'Content-Type': 'application/json'})[0] == 403
        assert request(s, 'POST', '/api/manifests', body=b'{}', headers=headers(s, **{'Content-Type': 'application/json', 'Content-Length': '999999999'}))[0] in (400, 413)
        assert request(s, 'POST', '/api/manifests/showcase', headers=headers(s))[0] == 201


def test_manifest_store_is_bounded():
    with server() as s:
        ids = [json.loads(upload_manifest(s)[1])['manifest_id'] for _ in range(6)]
        assert start(s, 'gt-oldest-0001', manifest_id=ids[0])[0] == 400          # evicted: only the newest few are kept
        assert start(s, 'gt-newest-0001', manifest_id=ids[-1])[0] == 202


def test_rules_only_scan_with_a_manifest_returns_a_verified_file_specific_evaluation():
    with server() as s:
        manifest_id = json.loads(upload_manifest(s)[1])['manifest_id']
        code, body, _ = start(s, 'gt-rules-0001', manifest_id=manifest_id)
        assert code == 202
        done = finish(s, json.loads(body)['job_id'])
        assert done['status'] == 'completed' and done['evaluation_requested'] is True and done['evaluation_status'] == 'complete'
        job_id = done['job_id']
        code, body, response_headers = request(s, 'GET', f'/api/jobs/{job_id}/evaluation', headers=headers(s))
        result = json.loads(body)
        assert code == 200 and result['status'] == 'complete' and list(result['systems']) == ['rules_only']
        assert result['manifest']['verified'] is True and result['capture']['verified_against_manifest'] is True
        assert result['manifest']['kind'] == 'hand_designed_demonstration'
        micro = result['systems']['rules_only']['micro']
        assert (micro['tp'], micro['fp'], micro['fn']) == (4, 0, 5)
        for secret in ('Priyanka', 'night_owl', 'Alex Example', 'violet_dev22', 'Fatima'):
            assert secret not in body.decode()
        code, body, response_headers = request(s, 'GET', f'/api/jobs/{job_id}/evaluation?download=1', headers=headers(s))
        assert code == 200 and 'attachment' in {k.lower(): v for k, v in response_headers.items()}['content-disposition']


def test_hybrid_scan_with_a_manifest_scores_the_model_and_the_combination():
    with server(NameDetector()) as s:
        manifest_id = json.loads(upload_manifest(s)[1])['manifest_id']
        code, body, _ = start(s, 'gt-hybrid-0001', mode='hybrid', manifest_id=manifest_id)
        done = finish(s, json.loads(body)['job_id'])
        assert done['status'] == 'completed' and done['evaluation_status'] == 'complete'
        result = json.loads(request(s, 'GET', f"/api/jobs/{done['job_id']}/evaluation", headers=headers(s))[1])
        assert list(result['systems']) == ['rules_only', 'model_only', 'rules_plus_model'] and result['model_version'] == 'name-detector-1'
        assert result['analysis']['ml_coverage_status'] == 'complete'
        model = result['systems']['model_only']
        assert model['micro']['tp'] == 6 and model['micro']['fp'] == 0      # Priyanka x2, Alex Example, night_owl_77 x3
        assert result['systems']['rules_plus_model']['micro']['tp'] >= model['micro']['tp']


def test_a_manifest_for_a_different_capture_is_rejected_but_the_scan_still_completes():
    with server() as s:
        manifest_id = json.loads(upload_manifest(s)[1])['manifest_id']
        code, body, _ = start(s, 'gt-wrong-0001', path='/api/jobs/demo', manifest_id=manifest_id)
        done = finish(s, json.loads(body)['job_id'])
        assert done['status'] == 'completed' and done['evaluation_status'] == 'rejected'
        result = json.loads(request(s, 'GET', f"/api/jobs/{done['job_id']}/evaluation", headers=headers(s))[1])
        assert result['status'] == 'rejected' and 'SHA-256' in result['reason'] and 'systems' not in result
        assert 'File-specific accuracy unavailable' in result['scope'] and result['manifest']['verified'] is False


def test_unknown_manifest_ids_and_scans_without_a_manifest():
    with server() as s:
        assert start(s, 'gt-missing-0001', manifest_id='0' * 32)[0] == 400
        assert start(s, 'gt-badid-00001', manifest_id='not-an-id')[0] == 400
        code, body, _ = start(s, 'gt-none-000001')
        done = finish(s, json.loads(body)['job_id'])
        assert done['evaluation_requested'] is False and done['evaluation_status'] is None
        assert request(s, 'GET', f"/api/jobs/{done['job_id']}/evaluation", headers=headers(s))[0] == 400
        assert request(s, 'GET', f"/api/jobs/{done['job_id']}/evaluation")[0] == 403


def test_manifest_evaluation_binds_actual_analysis_bytes(monkeypatch):
    """A prehash matching the manifest cannot authorize different parsed bytes."""
    import packet_pii.jobs as jobs
    original = jobs.analyze_to_report
    def changed_capture(path, *args, **kwargs):
        # Mutate only the PCAP global timezone field: parsing still succeeds,
        # but exact capture identity changes after the evaluator prehash.
        with path.open('r+b') as stream:
            stream.seek(8)
            stream.write(b'\x01\x00\x00\x00')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(jobs, 'analyze_to_report', changed_capture)
    with server() as s:
        code, body, _ = upload_manifest(s)
        assert code == 201
        manifest_id = json.loads(body)['manifest_id']
        code, body, _ = start(s, 'evidence-hash-race', manifest_id=manifest_id)
        assert code == 202
        result = finish(s, json.loads(body)['job_id'])
        assert result['status'] == 'completed'
        job = s.jobs.get(result['job_id'])
        assert job.evaluation['status'] == 'rejected'
        assert 'identity changed' in job.evaluation['reason']
