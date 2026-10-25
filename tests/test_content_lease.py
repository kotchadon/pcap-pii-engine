"""Event-driven checks for unlocked verification and revocable capture leases."""
import os
import threading
import time

import pytest

from packet_pii import investigation
from packet_pii.jobs import JobManager
from test_http_investigation import fixture


@pytest.fixture
def retained(tmp_path):
    capture = tmp_path/'demo.pcap'
    fixture.write_demo(capture)
    manager = JobManager(threading.Lock(), retain_capture_for_inspection=True)
    job, _ = manager.reserve('lease-test', filename='demo.pcap', source='upload',
                             size=capture.stat().st_size, mode='rules', profile='standard')
    job.capture.write_bytes(capture.read_bytes())
    job.capture.chmod(0o600)
    manager.start(job)
    job.thread.join(10)
    assert job.status == 'completed'
    message = manager.investigate(job, 'conversations')['items'][0]['messages'][2]['http_message_id']
    try:
        yield manager, job, message
    finally:
        manager.close()


def start_work(action):
    done, result = threading.Event(), {}
    def run():
        try:
            result['value'] = action()
        except Exception as exc:
            result['error'] = exc
        finally:
            done.set()
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    return worker, done, result


def block_hash(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = investigation.hashlib.sha256
    class PausedHash:
        def __init__(self):
            self.digest = original()
        def update(self, value):
            entered.set()
            assert release.wait(5), 'test did not release blocked hash'
            self.digest.update(value)
        def hexdigest(self):
            return self.digest.hexdigest()
    monkeypatch.setattr(investigation.hashlib, 'sha256', PausedHash)
    return entered, release


def test_hash_does_not_block_status_navigation_or_other_job_cancellation(retained, monkeypatch):
    manager, job, mid = retained
    other, _ = manager.reserve('other-upload', filename='other.pcap', source='upload',
                               size=24, mode='rules', profile='standard')
    entered, release = block_hash(monkeypatch)
    worker, done, result = start_work(lambda: manager.investigate(job, 'content', message_id=mid))
    try:
        assert entered.wait(2)
        def unrelated():
            assert manager.snapshot(job)['status'] == 'completed'
            assert manager.investigate(job, 'conversations')['total'] == 2
            assert manager.cancel_job(other)['cancellation_requested']
            manager.fail_upload(other)
        observer, observed, observations = start_work(unrelated)
        assert observed.wait(2), 'shared manager lock held during capture hash'
        observer.join(2)
        assert 'error' not in observations
        assert not done.is_set()
    finally:
        release.set()
        worker.join(5)
    assert done.is_set() and 'error' not in result
    assert 'alex@example.invalid' in result['value']['text']
    assert other.status == 'cancelled'


@pytest.mark.parametrize('revocation', ['expiry', 'prune', 'close', 'cancel', 'replace'])
def test_inflight_lease_never_discloses_after_revocation(retained, monkeypatch, revocation):
    manager, job, mid = retained
    entered, release = block_hash(monkeypatch)
    worker, done, result = start_work(lambda: manager.investigate(job, 'content', message_id=mid))
    try:
        assert entered.wait(2)
        def revoke():
            with manager.lock:
                if revocation == 'expiry':
                    job.updated = time.monotonic()-manager.ttl-1
                    manager._expire_capture(job)
                    assert not job.capture.exists()
                elif revocation == 'prune':
                    manager.max_retained = 1
                    manager._prune()
                    assert not job.directory.exists()
                elif revocation == 'close':
                    manager.close()
                    assert not job.capture.exists()
                elif revocation == 'cancel':
                    job.cancel.set()
                else:
                    replacement = job.directory/'replacement.bin'
                    replacement.write_bytes(job.capture.read_bytes().replace(b'alex@example.invalid', b'zoey@example.invalid'))
                    os.replace(replacement, job.capture)
        revoker, revoked, revocation_result = start_work(revoke)
        assert revoked.wait(2), 'revocation blocked behind capture hash'
        revoker.join(2)
        assert 'error' not in revocation_result
    finally:
        release.set()
        worker.join(5)
    assert done.is_set() and 'value' not in result
    assert isinstance(result.get('error'), (KeyError, ValueError, OSError))


@pytest.mark.parametrize('revocation', ['expiry', 'mutation'])
def test_lease_revalidated_after_decode_and_descriptor_always_closed(retained, monkeypatch, revocation):
    manager, job, mid = retained
    original = investigation.recover_content_stream
    borrowed = []
    def expire_after_decode(stream, identity, prepared, **kwargs):
        borrowed.append(stream)
        result = original(stream, identity, prepared, **kwargs)
        with manager.lock:
            if revocation == 'expiry':
                job.updated = time.monotonic()-manager.ttl-1
                manager._expire_capture(job)
            else:
                raw = bytearray(job.capture.read_bytes());raw[24] ^= 1
                job.capture.write_bytes(raw)
        return result
    monkeypatch.setattr(investigation, 'recover_content_stream', expire_after_decode)
    with pytest.raises((KeyError, ValueError, OSError)):
        manager.investigate(job, 'content', message_id=mid)
    assert len(borrowed) == 1 and borrowed[0].closed


def test_hash_mismatch_closes_descriptor_and_releases_manager(retained, monkeypatch):
    manager, job, mid = retained
    raw = bytearray(job.capture.read_bytes());raw[24] ^= 1
    job.capture.write_bytes(raw)
    borrowed = []
    original = investigation.recover_content_stream
    def track(stream, *args, **kwargs):
        borrowed.append(stream)
        return original(stream, *args, **kwargs)
    monkeypatch.setattr(investigation, 'recover_content_stream', track)
    with pytest.raises(ValueError, match='identity mismatch'):
        manager.investigate(job, 'content', message_id=mid)
    assert borrowed[0].closed
    assert manager.snapshot(job)['status'] == 'completed'


def test_unknown_message_fails_before_capture_open(retained, monkeypatch):
    manager, job, _ = retained
    def no_open(*args, **kwargs):
        pytest.fail('unknown message attempted a source read')
    monkeypatch.setattr(os, 'open', no_open)
    with pytest.raises(KeyError):
        manager.investigate(job, 'content', message_id='other_job_message')
