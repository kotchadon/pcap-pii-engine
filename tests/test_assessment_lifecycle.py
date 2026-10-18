"""Post-scan assessment lifecycle: automatic start, separation from the scan, failure/cancel isolation, clearing, compatibility."""
import json
import threading
import time

import pytest

from packet_pii import jobs as jobs_module
from packet_pii import quality
from packet_pii.ml import EntityLabel, EntitySpan, ScoreType
from test_dashboard_jobs import finish, request, server


def headers(s, **extra):
    return {'X-Dashboard-Token': s.token, **extra}


def start(s, request_id, mode='hybrid', path='/api/jobs/showcase'):
    return request(s, 'POST', path, headers=headers(s, **{'X-Request-ID': request_id, 'X-Detection-Mode': mode, 'X-Analysis-Profile': 'standard'}))


def assessment(s, job_id):
    return json.loads(request(s, 'GET', f'/api/jobs/{job_id}/assessment', headers=headers(s))[1])


def wait_assessment(s, job_id, timeout=30, until=('complete', 'partial', 'failed', 'cancelled', 'unavailable')):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = assessment(s, job_id)
        if data['status'] in until:
            return data
        time.sleep(0.02)
    pytest.fail('assessment did not reach a terminal state')


class Model:
    model_version = 'lifecycle-model-1'
    PROBE_FIRST = set(quality.FIRST)

    def __init__(self, probe_delay=0.0, fail_on_probe=False):
        self.probe_delay, self.fail_on_probe = probe_delay, fail_on_probe

    def is_probe(self, fields):
        return any(f.text.split(' ')[0] in self.PROBE_FIRST or f.text[:1] in '"N' and 'Note' in f.text for f in fields)

    def predict_fields(self, fields):
        if self.is_probe(fields) or any(f.location.startswith(('json_body.data', 'json_body.value')) for f in fields):
            if self.fail_on_probe:
                raise RuntimeError('probe-stage failure with secret-looking text')
            time.sleep(self.probe_delay)
        out = []
        for f in fields:
            at = f.text.find('night_owl_77')
            if at >= 0:
                out.append(EntitySpan(f.field_index, EntityLabel.USERNAME, at, at + 12, self.model_version, .9, ScoreType.UNCALIBRATED_MODEL_SCORE))
        return out


def test_hybrid_scan_starts_an_automatic_assessment_with_separate_counters():
    with server(Model()) as s:
        code, body, _ = start(s, 'qa-auto-000001')
        done = finish(s, json.loads(body)['job_id'])
        assert done['status'] == 'completed' and done['assessment_status'] in ('pending', 'running', 'complete')
        data = wait_assessment(s, done['job_id'])
        result = data['result']
        assert data['status'] == 'complete' == result['status'] and result['headline']['name'] == 'Context-matched synthetic probe F1'
        assert result['disclosure'] == quality.DISCLOSURE and result['reproducibility']['model_version'] == 'lifecycle-model-1'
        assert 'accuracy' not in json.dumps({k: v for k, v in result.items() if k not in ('disclosure', 'limitations')}).lower()
        # separate workload: the scan's ML counters are untouched by probes
        summary = done['report']['summary']
        assert summary['ml_fields_evaluated'] == summary['ml_fields_eligible'] and summary['ml_coverage_status'] == 'complete'
        assert result['probes']['generated'] != summary['ml_fields_evaluated']
        assert 'assessment' not in done['report'] and 'probes' not in json.dumps(done['report']).lower()
        assert data['elapsed_seconds'] >= 0 and 'elapsed_seconds' in data and result['workload']['elapsed_seconds'] >= 0


def test_rules_only_scan_does_not_pretend_the_model_ran():
    with server(Model()) as s:
        done = finish(s, json.loads(start(s, 'qa-rules-000001', mode='rules')[1])['job_id'])
        assert done['assessment_status'] == 'unavailable'
        data = assessment(s, done['job_id'])
        assert data['status'] == 'unavailable' and 'headline' not in data['result'] and 'did not run' in data['result']['reason']


def test_assessment_runs_without_holding_the_analysis_lock():
    with server(Model(probe_delay=0.15)) as s:
        done = finish(s, json.loads(start(s, 'qa-lock-0000001')[1])['job_id'])
        assert assessment(s, done['job_id'])['status'] in ('pending', 'running')
        assert s.analysis_lock.acquire(blocking=False)                 # the scan lock is free while probes run
        s.analysis_lock.release()
        code, body, _ = start(s, 'qa-second-000001', mode='rules')
        assert code == 202                                              # another scan is accepted immediately
        finish(s, json.loads(body)['job_id'])


def test_probe_failure_never_damages_the_completed_scan_and_fabricates_no_metrics():
    with server(Model(fail_on_probe=True)) as s:
        done = finish(s, json.loads(start(s, 'qa-fail-0000001')[1])['job_id'])
        assert done['status'] == 'completed' and done['report']['summary']['ml_coverage_status'] == 'complete'
        data = wait_assessment(s, done['job_id'])
        assert data['status'] == 'failed' and 'headline' not in data['result'] and 'probe-stage failure' not in json.dumps(data)
        assert request(s, 'GET', f"/api/jobs/{done['job_id']}/report", headers=headers(s))[0] == 200      # report still downloadable
        assert finish(s, done['job_id'])['report']['summary']['potential_leaks'] == done['report']['summary']['potential_leaks']


def test_assessment_can_be_cancelled_without_affecting_the_scan():
    with server(Model(probe_delay=0.3)) as s:
        done = finish(s, json.loads(start(s, 'qa-cancel-000001')[1])['job_id'])
        code, body, _ = request(s, 'POST', f"/api/jobs/{done['job_id']}/assessment/cancel", headers=headers(s))
        assert code == 200
        data = wait_assessment(s, done['job_id'])
        assert data['status'] == 'cancelled' and 'headline' not in data['result']
        assert finish(s, done['job_id'])['status'] == 'completed'


def test_starting_a_new_scan_cancels_the_previous_assessment_and_results_stay_job_scoped():
    with server(Model(probe_delay=0.3)) as s:
        first = finish(s, json.loads(start(s, 'qa-first-0000001')[1])['job_id'])
        second = finish(s, json.loads(start(s, 'qa-second-000002', mode='rules')[1])['job_id'])
        assert wait_assessment(s, first['job_id'])['status'] == 'cancelled'
        data = assessment(s, second['job_id'])
        assert data['status'] == 'unavailable' and 'headline' not in data['result']        # nothing inherited from the earlier scan


def test_assessment_is_disabled_when_the_server_turns_it_off():
    with server(Model()) as s:
        s.jobs.assessment_budget = None
        done = finish(s, json.loads(start(s, 'qa-off-00000001')[1])['job_id'])
        assert done['assessment_status'] == 'unavailable' and 'disabled' in assessment(s, done['job_id'])['result']['reason']


def test_scan_runs_exactly_one_analysis_pass(monkeypatch):
    calls = []
    original = jobs_module.analyze_to_report
    monkeypatch.setattr(jobs_module, 'analyze_to_report', lambda *a, **k: calls.append(1) or original(*a, **k))
    with server(Model()) as s:
        done = finish(s, json.loads(start(s, 'qa-once-0000001')[1])['job_id'])
        wait_assessment(s, done['job_id'])
    assert calls == [1]


def test_old_endpoints_and_unknown_jobs_remain_compatible():
    with server(Model()) as s:
        assert request(s, 'GET', '/api/jobs/' + '0' * 32 + '/assessment', headers=headers(s))[0] == 404
        assert request(s, 'GET', '/api/jobs/' + '0' * 32 + '/assessment')[0] == 403
        assert request(s, 'POST', '/api/jobs/' + '0' * 32 + '/assessment/cancel', headers=headers(s))[0] == 404
        done = finish(s, json.loads(start(s, 'qa-compat-000001')[1])['job_id'])
        assert {'findings', 'flows', 'summary', 'metadata', 'limitations'} <= set(done['report'])


def test_detector_calls_are_serialised_between_scan_and_assessment():
    class Probe(Model):
        active = 0
        overlap = False

        def predict_fields(self, fields):
            Probe.active += 1
            Probe.overlap |= Probe.active > 1
            time.sleep(0.01)
            Probe.active -= 1
            return super().predict_fields(fields)
    with server(Probe()) as s:
        done = finish(s, json.loads(start(s, 'qa-lockdet-00001')[1])['job_id'])
        second = start(s, 'qa-lockdet-00002')
        wait_assessment(s, done['job_id'])
    assert Probe.overlap is False
