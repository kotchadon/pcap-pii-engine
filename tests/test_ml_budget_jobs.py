"""Explicit ML budgets, real job cancellation, and no automatic retries."""
import json
import threading
from dataclasses import asdict

import pytest

from packet_pii.hybrid import MLWorkBudget
from packet_pii.jobs import JobManager, JobBusy
from packet_pii.dashboard import DashboardServer
from test_dashboard_jobs import server, request, finish


class EmptyDetector:
    model_version = 'empty-contract-test'

    def predict_fields(self, fields):
        return []


def test_budget_part_of_idempotency_identity():
    manager = JobManager(threading.Lock(), EmptyDetector())
    kwargs = dict(filename='fixture.pcap', source='upload', size=24,
                  mode='hybrid', profile='standard')
    try:
        job, created = manager.reserve('request-identity', **kwargs)
        assert created and job.ml_work_budget == MLWorkBudget()
        assert manager.reserve('request-identity', **kwargs) == (job, False)
        with pytest.raises(JobBusy):
            manager.reserve('request-identity', **kwargs,
                            ml_work_budget=MLWorkBudget.for_profile('extended'))
        manager.fail_upload(job)
    finally:
        manager.close()


def test_http_budget_selection_and_zero_predictions():
    with server(EmptyDetector()) as s:
        session = json.loads(request(s, 'GET', '/api/session')[1])
        assert session['ml_budget_profile'] == 'standard'
        assert session['ml_budget_profiles']['extended']['max_total_fields'] == 100000
        headers = {'X-Dashboard-Token': s.token, 'X-Request-ID': 'explicit-ml-budget',
                   'X-Detection-Mode': 'hybrid', 'X-ML-Budget-Profile': 'unlimited'}
        assert request(s, 'POST', '/api/jobs/showcase', headers=headers)[0] == 400
        headers['X-ML-Budget-Profile'] = 'extended'
        code, body, _ = request(s, 'POST', '/api/jobs/showcase', headers=headers)
        assert code == 202
        job_id = json.loads(body)['job_id']
        done = finish(s, job_id)
        assert done['status'] == 'completed'
        assert done['ml_work_budget'] == asdict(MLWorkBudget.for_profile('extended'))
        summary = done['report']['summary']
        assert summary['ml_inference_complete'] is True
        assert summary['ml_inference_invoked'] is True
        assert summary['ml_findings'] == 0
        assert summary['ml_fields_evaluated'] == summary['ml_fields_eligible']
        assert done['cancellation_requested'] is False
        headers['X-ML-Budget-Profile'] = 'standard'
        assert request(s, 'POST', '/api/jobs/showcase', headers=headers)[0] == 409


def test_admin_budget_is_explicit_and_capture_profile_independent():
    s = DashboardServer(('127.0.0.1', 0), ml_detector=EmptyDetector(),
                        ml_budget_profile='extended')
    try:
        manager = s.jobs
        job, _ = manager.reserve('admin-budget-request', filename='f.pcap', source='upload',
                                 size=24, mode='hybrid', profile='standard')
        assert job.ml_work_budget.max_total_fields == 100000
        manager.fail_upload(job)
    finally:
        s.server_close()


def test_cancel_between_batches_preserves_observed_progress_and_cleans_files():
    entered, release = threading.Event(), threading.Event()

    class Blocking(EmptyDetector):
        calls = 0

        def predict_fields(self, fields):
            self.calls += 1
            entered.set()
            assert release.wait(5)
            return []

    model = Blocking()
    with server(model) as s:
        s.jobs.ml_work_budget = MLWorkBudget(max_fields_per_batch=1)
        headers = {'X-Dashboard-Token': s.token, 'X-Request-ID': 'cancel-batch-request',
                   'X-Detection-Mode': 'hybrid'}
        code, body, _ = request(s, 'POST', '/api/jobs/showcase', headers=headers)
        assert code == 202 and entered.wait(3)
        job_id = json.loads(body)['job_id']
        try:
            code, raw, _ = request(s, 'POST', f'/api/jobs/{job_id}/cancel', headers=headers)
            assert code == 200 and json.loads(raw)['cancellation_requested']
        finally:
            release.set()
        done = finish(s, job_id)
        assert done['status'] == 'cancelled' and done['cancellation_completed']
        assert done['reason_code'] == 'ml_cancelled'
        assert 'report' not in done and model.calls == 1
        assert not list(s.jobs.get(job_id).directory.iterdir())
        assert not s.analysis_lock.locked()


def test_cli_passes_explicit_budget_without_model_reload(tmp_path, monkeypatch):
    from packet_pii import cli
    seen = {}
    detector = EmptyDetector()
    def fake_analysis(*args, **kwargs):
        seen.update(kwargs)
        return {'summary': dict(packets_captured=0, flows_processed=0,
                                http_messages=0, potential_leaks=0)}
    monkeypatch.setattr(cli, 'analyze_to_report', fake_analysis)
    monkeypatch.setattr(cli, 'load_experimental_bilstm', lambda path: detector)
    assert cli.main(['fixture.pcap', '-o', str(tmp_path/'report.json'), '--ml-checkpoint',
                     'local', '--ml-budget-profile', 'extended', '--ml-batch-fields', '7',
                     '--ml-max-total-fields', '120000']) == 0
    assert seen['ml_work_budget'].max_total_fields == 120000
    assert seen['ml_work_budget'].max_fields_per_batch == 7
    assert seen['ml_detector'] is detector


def test_terminal_status_is_published_only_after_cleanup(monkeypatch):
    import packet_pii.jobs as jobs
    entered, release = threading.Event(), threading.Event()
    manager = JobManager(threading.Lock(), EmptyDetector())
    job, _ = manager.reserve('cleanup-order-request', filename='f.pcap', source='upload',
                             size=24, mode='hybrid', profile='standard')
    job.capture.write_bytes(b'invalid synthetic capture')
    remove = manager._remove_files
    def delayed_cleanup(current):
        entered.set()
        assert release.wait(5)
        remove(current)
    monkeypatch.setattr(manager, '_remove_files', delayed_cleanup)
    try:
        manager.start(job)
        assert entered.wait(3)
        # Deliberately inspect the shared object: status snapshots acquire the
        # manager lock and cannot escape while terminal cleanup is in progress.
        assert job.status == 'running'
        assert manager.analysis_lock.locked()
        release.set()
        job.thread.join(3)
        assert job.status == 'failed' and job.released
        assert not manager.analysis_lock.locked() and not list(job.directory.iterdir())
    finally:
        release.set()
        manager.close()
