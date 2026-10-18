"""Loopback-only, dependency-free investigation dashboard for the existing engine.

The existing rules-only pipeline is the default. A trained BiLSTM can be
explicitly enabled with --ml-checkpoint for experimental live inference.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import tempfile
import time
from urllib.parse import urlsplit, parse_qs, unquote
from http.cookies import SimpleCookie

from .engine import AnalysisLimits, analyze
from .hybrid import load_experimental_bilstm
from threading import Lock, BoundedSemaphore
from .jobs import JobManager, JobBusy, JobQuota

_STATIC = Path(__file__).with_name('dashboard_static')
_MAX_UPLOAD = 512 * 1024 * 1024
_MAX_SYNC_UPLOAD = 8 * 1024 * 1024
_ALLOWED = {'/': ('index.html', 'text/html; charset=utf-8'),
            '/app.css': ('app.css', 'text/css; charset=utf-8'),
            '/app.js': ('app.js', 'text/javascript; charset=utf-8')}


class DashboardServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr: tuple[str, int], max_upload: int = _MAX_UPLOAD, ml_detector=None,
                 *, job_disk_mib: int = 12288):
        if addr[0] != '127.0.0.1':
            raise ValueError('Dashboard must bind to 127.0.0.1')
        if type(max_upload) is not int or not 24 <= max_upload <= _MAX_UPLOAD:
            raise ValueError('Invalid dashboard upload limit')
        super().__init__(addr, DashboardHandler)
        self.max_upload = max_upload
        self.token = secrets.token_urlsafe(32)
        self.ml_detector = ml_detector
        self.analysis_lock = Lock()
        self.request_slots = BoundedSemaphore(8)
        self.jobs = JobManager(self.analysis_lock,ml_detector,disk_quota_bytes=job_disk_mib*1024*1024)

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request,client_address)
        except BaseException:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request,client_address)
        finally:
            self.request_slots.release()

    def server_close(self):
        self.jobs.close()
        super().server_close()


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def log_message(self, fmt: str, *args) -> None:
        # HTTP request URLs / user-controlled fields may contain sensitive data.
        # Deliberately don't log request target or uploaded file name.
        pass

    def _headers(self, status: int, mime: str, size: int, *, download=None) -> None:
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(size))
        if urlsplit(self.path).path == '/api/session':
            self.send_header('Set-Cookie',f'trace_session={self.server.token}; Path=/api/jobs/; HttpOnly; SameSite=Strict')
        if download is not None:
            self.send_header('Content-Disposition',f'attachment; filename="{download}"')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()

    def _reply(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode('utf-8')
        try:
            self._headers(status, 'application/json; charset=utf-8', len(body))
            self.wfile.write(body)
        except OSError:
            # A browser tab/navigation may disconnect after analysis but before
            # receiving its result. Sending a second HTTP error is impossible.
            # Never mislabel this transport failure as an engine-analysis failure.
            self.close_connection = True

    def _allowed_host(self) -> bool:
        host = self.headers.get('Host', '')
        return host in {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}

    def _same_origin(self) -> bool:
        origin = self.headers.get('Origin')
        if origin is None:
            return True
        return origin in {f'http://127.0.0.1:{self.server.server_port}', f'http://localhost:{self.server.server_port}'}

    def do_GET(self) -> None:
        if not self._allowed_host() or not self._same_origin():
            self._reply({'error': 'Invalid host'}, 403)
            return
        path = urlsplit(self.path).path
        if path.startswith('/api/jobs/'):
            self._job_get(path)
            return
        if path == '/api/benchmark':
            from .research import benchmark_metadata
            self._reply(benchmark_metadata())
            return
        if path == '/api/session':
            self._reply({'token': self.server.token, 'max_upload_bytes': self.server.max_upload,
                         'jobs_supported': True, 'active_job_id': self.server.jobs.latest_id,
                         'profiles': {name:vars(AnalysisLimits.for_profile(name)) for name in ('standard','large','stress')},
                         'detector_mode': 'rules_plus_bilstm' if self.server.ml_detector else 'rules_only',
                         'model_enabled': self.server.ml_detector is not None,
                         'model_available': self.server.ml_detector is not None,
                         'model_version': (self.server.ml_detector.model_version
                                           if self.server.ml_detector else None)})
            return
        if path not in _ALLOWED:
            self._reply({'error': 'Not found'}, 404)
            return
        filename, mime = _ALLOWED[path]
        data = (_STATIC / filename).read_bytes()
        try:
            self._headers(200, mime, len(data))
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True

    def do_POST(self) -> None:
        if not self._allowed_host() or not self._same_origin() or self.headers.get('X-Dashboard-Token') != self.server.token:
            self._reply({'error': 'Request refused'}, 403)
            return
        path = urlsplit(self.path).path
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length',[])) > 1:
            self.close_connection = True
            self._reply({'error':'Unsupported request framing'},400)
            return
        if path.startswith('/api/jobs'):
            self._job_post(path)
            return
        requested_mode = self.headers.get('X-Detection-Mode')
        if requested_mode is not None and requested_mode not in ('rules', 'hybrid'):
            self._reply({'error': 'Invalid detection mode'}, 400)
            return
        if requested_mode == 'hybrid' and self.server.ml_detector is None:
            self._reply({'error': 'Contextual AI model is unavailable; start with --ml-checkpoint'}, 422)
            return
        if path == '/api/showcase':
            # A richer deterministic fixture, analysed by the same engine as uploads.
            # No precomputed labels, PII findings, scores, or report JSON.
            from importlib.util import module_from_spec, spec_from_file_location
            generator = Path(__file__).resolve().parents[2] / 'examples' / 'generate_showcase.py'
            if not generator.is_file():
                self._reply({'error': 'Synthetic showcase generator unavailable'}, 404)
                return
            spec = spec_from_file_location('_packet_pii_showcase', generator)
            if spec is None or spec.loader is None:
                self._reply({'error': 'Synthetic showcase generator unavailable'}, 500)
                return
            module = module_from_spec(spec)
            spec.loader.exec_module(module)
            with tempfile.TemporaryDirectory(prefix='trace_showcase_') as directory:
                capture = Path(directory) / 'trace-vp-showcase.pcap'
                module.write_pcap(capture)
                self._analyze(capture, 'trace-vp-showcase.pcap', requested_mode)
            return
        if path == '/api/demo':
            # Demo data are synthetic. Only demo traffic is used, never user data.
            from importlib.util import module_from_spec, spec_from_file_location
            generator = Path(__file__).resolve().parents[2] / 'examples' / 'generate_demo.py'
            if not generator.is_file():
                self._reply({'error': 'Synthetic demo generator unavailable'}, 404)
                return
            spec = spec_from_file_location('_packet_pii_local_demo', generator)
            if spec is None or spec.loader is None:
                self._reply({'error': 'Demo generator unavailable'}, 500)
                return
            module = module_from_spec(spec)
            spec.loader.exec_module(module)
            with tempfile.TemporaryDirectory(prefix='pii_demo_') as directory:
                capture = Path(directory) / 'synthetic-demo.pcap'
                module.write_pcap(capture)
                self._analyze(capture, 'synthetic-demo.pcap', requested_mode)
            return
        if path != '/api/analyze':
            self._reply({'error': 'Not found'}, 404)
            return
        if self.headers.get('Content-Type') != 'application/octet-stream':
            self._reply({'error': 'Expected application/octet-stream'}, 415)
            return
        size_raw = self.headers.get('Content-Length', '')
        if not re.fullmatch(r'[0-9]{1,12}', size_raw):
            self._reply({'error': 'Invalid Content-Length'}, 400)
            return
        size = int(size_raw)
        if size < 24 or size > min(self.server.max_upload,_MAX_SYNC_UPLOAD):
            self.close_connection = True
            self._reply({'error': 'Use the background scan endpoint for captures above 8 MiB'}, 413)
            return
        # No user-provided pathname ever reaches the filesystem.
        name = self.headers.get('X-Capture-Name', 'capture.pcap')[:120]
        if not name.lower().endswith(('.pcap', '.pcapng')):
            self._reply({'error': 'Select a PCAP or PCAPNG file'}, 400)
            return
        with tempfile.TemporaryDirectory(prefix='pii_upload_') as directory:
            capture = Path(directory) / 'capture.bin'
            remaining = size
            with os.fdopen(os.open(capture,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as output:
                while remaining:
                    block = self.rfile.read(min(1024 * 1024, remaining))
                    if not block:
                        self._reply({'error': 'Upload ended early'}, 400)
                        return
                    output.write(block)
                    remaining -= len(block)
            from urllib.parse import unquote
            safe_name = unquote(name).replace('\\', '/').split('/')[-1]
            safe_name = ''.join(ch for ch in safe_name if ch.isprintable())[:120] or 'uploaded-capture'
            self._analyze(capture, safe_name, requested_mode)

    def _analyze(self, capture: Path, label: str, requested_mode: str | None = None) -> None:
        if not self.server.analysis_lock.acquire(blocking=False):
            self._reply({'error':'Another scan is active; wait or cancel it'},409)
            return
        try:
            # Serialise inference to avoid overlapping CPU-heavy analyses on the same
            # shared checkpoint during a live presentation.
            use_ml = self.server.ml_detector is not None and requested_mode != 'rules'
            report = analyze(capture, include_values=False,
                             limits=AnalysisLimits(max_capture_bytes=min(self.server.max_upload,_MAX_SYNC_UPLOAD),
                                                   max_report_bytes=4*1024*1024,max_findings=10000),
                             ml_detector=self.server.ml_detector if use_ml else None)
            self._reply({'filename': label, 'capture_bytes': capture.stat().st_size,
                         'report': report,
                         'model_enabled': use_ml,
                         'model_available': self.server.ml_detector is not None,
                         'scan_mode': 'hybrid' if use_ml else 'rules'})
        except Exception as exc:
            # Engine errors may include paths; never expose them verbatim in the UI.
            from .engine import AnalysisLimitError
            if isinstance(exc, AnalysisLimitError):
                # Safe diagnostic: predefined bounded budget failure, not a user path.
                self._reply({'error': str(exc), 'reason_type': 'AnalysisLimitError'}, 422)
            else:
                self._reply({'error': 'Capture rejected or analysis could not complete',
                             'reason_type': type(exc).__name__}, 422)
        finally:
            self.server.analysis_lock.release()

    def _job_get(self,path):
        match=re.fullmatch(r'/api/jobs/([0-9a-f]{32})(?:/(findings|flows|report))?',path)
        if not match:
            self._reply({'error':'Job not found'},404);return
        job_id,kind=match.groups()
        authenticated=self.headers.get('X-Dashboard-Token')==self.server.token
        if kind=='report' and not authenticated:
            try:
                cookie=SimpleCookie(self.headers.get('Cookie',''))
                authenticated=cookie.get('trace_session') is not None and secrets.compare_digest(cookie['trace_session'].value,self.server.token)
            except Exception:
                authenticated=False
        if not authenticated:
            self._reply({'error':'Request refused'},403);return
        try:
            job=self.server.jobs.get(job_id)
            if kind=='report':
                if job.status!='completed':raise ValueError('Result not complete')
                with job.report.open('rb') as stream:
                    self._headers(200,'application/json',os.fstat(stream.fileno()).st_size,
                                  download=f'trace-report-{job_id}.json')
                    while block:=stream.read(256*1024):self.wfile.write(block)
            elif kind:
                query=parse_qs(urlsplit(self.path).query)
                page=self.server.jobs.page(job,kind,offset=int(query.get('offset',['0'])[0]),
                    limit=int(query.get('limit',['100'])[0]),q=query.get('q',[''])[0],
                    pii_type=query.get('type',[''])[0])
                self._reply(page)
            else:self._reply(self.server.jobs.snapshot(job))
        except KeyError:self._reply({'error':'Job unavailable or expired'},404)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, socket.timeout):
            self.close_connection=True
        except ValueError:self._reply({'error':'Invalid page or result not complete'},400)
        except (OSError,sqlite3.Error):self._reply({'error':'Result unavailable'},404)

    def _job_post(self,path):
        cancel=re.fullmatch(r'/api/jobs/([0-9a-f]{32})/cancel',path)
        if cancel:
            try:self._reply(self.server.jobs.cancel_job(self.server.jobs.get(cancel[1])))
            except KeyError:self._reply({'error':'Job unavailable or expired'},404)
            return
        if path not in ('/api/jobs','/api/jobs/showcase','/api/jobs/demo'):
            self._reply({'error':'Not found'},404);return
        mode=self.headers.get('X-Detection-Mode','rules')
        profile=self.headers.get('X-Analysis-Profile','standard')
        request_id=self.headers.get('X-Request-ID','')
        if mode not in ('rules','hybrid') or profile not in ('standard','large','stress') or not re.fullmatch(r'[A-Za-z0-9_-]{8,80}',request_id):
            self._reply({'error':'Valid scan mode, profile and request ID are required'},400);return
        if mode=='hybrid' and self.server.ml_detector is None:
            self._reply({'error':'Requested model is unavailable'},422);return
        source=path.rsplit('/',1)[-1]
        size=0
        label='trace-vp-showcase.pcap' if source=='showcase' else 'synthetic-demo.pcap'
        if path=='/api/jobs':
            if self.headers.get('Content-Type')!='application/octet-stream':
                self._reply({'error':'Expected application/octet-stream'},415);return
            length=self.headers.get('Content-Length','')
            if not re.fullmatch(r'[0-9]{1,12}',length):
                self._reply({'error':'Invalid Content-Length'},400);return
            size=int(length)
            if not 24<=size<=min(self.server.max_upload,AnalysisLimits.for_profile(profile).max_capture_bytes):
                self.close_connection=True
                self._reply({'error':'Capture exceeds selected profile or upload limit'},413);return
            name=unquote(self.headers.get('X-Capture-Name','capture.pcap')[:400]).replace('\\','/').split('/')[-1]
            label=''.join(ch for ch in name if ch.isprintable())[:120]
            if not label.lower().endswith(('.pcap','.pcapng')):
                self._reply({'error':'Select a PCAP or PCAPNG file'},400);return
        job=None
        started=False
        try:
            job,created=self.server.jobs.reserve(request_id,filename=label,source=source,size=size,mode=mode,profile=profile)
            if not created:
                self.close_connection=True
                self._reply({'job_id':job.job_id,'status':job.status},202);return
            if path=='/api/jobs':
                job.upload_abort=lambda:self.connection.shutdown(socket.SHUT_RD)
                deadline=time.monotonic()+120
                with os.fdopen(os.open(job.capture,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as output:
                    remaining=size
                    while remaining:
                        if job.cancel.is_set():raise ValueError('Upload cancelled')
                        if time.monotonic()>deadline:raise ValueError('Upload deadline exceeded')
                        block=self.rfile.read1(min(256*1024,remaining))
                        if not block:raise ValueError('Upload ended early')
                        output.write(block);remaining-=len(block)
                        job.progress={'stage':'uploading','bytes_received':size-remaining,'capture_bytes':size}
            else:
                from importlib.util import module_from_spec,spec_from_file_location
                filename='generate_showcase.py' if source=='showcase' else 'generate_demo.py'
                generator=Path(__file__).resolve().parents[2]/'examples'/filename
                spec=spec_from_file_location('_trace_job_fixture',generator)
                module=module_from_spec(spec);spec.loader.exec_module(module)
                module.write_pcap(job.capture);job.capture.chmod(0o600)
            job.upload_abort=None
            self.server.jobs.start(job)
            started=True
            self._reply({'job_id':job.job_id,'status':job.status},202)
        except JobBusy:self._reply({'error':'Another scan is active or request ID conflicts'},409)
        except JobQuota:self._reply({'error':'Insufficient private job disk budget or free disk space'},507)
        except Exception:
            self.close_connection=True
            if started:
                # A response failure cannot cancel/release an active worker.
                return
            if job is not None:self.server.jobs.fail_upload(job)
            self._reply({'error':'Upload or scan could not start'},422)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description='Run local-only PCAP PII investigation dashboard')
    p.add_argument('--port', type=int, default=8765)
    p.add_argument('--ml-checkpoint', default=None, help='Opt in to offline research BiLSTM checkpoint')
    p.add_argument('--job-disk-mib',type=int,default=12288,help='Private job disk quota MiB; conservative capacity is checked before accepting a scan')
    args = p.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        p.error('Port must be 1024–65535')
    ml_detector = load_experimental_bilstm(args.ml_checkpoint) if args.ml_checkpoint else None
    server = DashboardServer(('127.0.0.1', args.port), ml_detector=ml_detector,job_disk_mib=args.job_disk_mib)
    print(f'PCAP PII dashboard: http://127.0.0.1:{args.port}/ (Ctrl+C to stop)')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
