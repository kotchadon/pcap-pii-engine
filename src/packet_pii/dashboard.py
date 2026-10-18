"""Loopback-only, dependency-free investigation dashboard for the existing engine.

The existing rules-only pipeline is the default. A trained BiLSTM can be
explicitly enabled with --ml-checkpoint for experimental live inference.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import tempfile
from urllib.parse import urlsplit

from .engine import AnalysisLimits, analyze
from .hybrid import load_experimental_bilstm
from threading import Lock

_STATIC = Path(__file__).with_name('dashboard_static')
_MAX_UPLOAD = 128 * 1024 * 1024
_ALLOWED = {'/': ('index.html', 'text/html; charset=utf-8'),
            '/app.css': ('app.css', 'text/css; charset=utf-8'),
            '/app.js': ('app.js', 'text/javascript; charset=utf-8')}


class DashboardServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr: tuple[str, int], max_upload: int = _MAX_UPLOAD, ml_detector=None):
        super().__init__(addr, DashboardHandler)
        self.max_upload = max_upload
        self.token = secrets.token_urlsafe(32)
        self.ml_detector = ml_detector
        self.analysis_lock = Lock()


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def log_message(self, fmt: str, *args) -> None:
        # HTTP request URLs / user-controlled fields may contain sensitive data.
        # Deliberately don't log request target or uploaded file name.
        pass

    def _headers(self, status: int, mime: str, size: int) -> None:
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(size))
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
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
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
        if not self._allowed_host():
            self._reply({'error': 'Invalid host'}, 403)
            return
        path = urlsplit(self.path).path
        if path == '/api/session':
            self._reply({'token': self.server.token, 'max_upload_bytes': self.server.max_upload,
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
        self._headers(200, mime, len(data))
        self.wfile.write(data)

    def do_POST(self) -> None:
        if not self._allowed_host() or not self._same_origin() or self.headers.get('X-Dashboard-Token') != self.server.token:
            self._reply({'error': 'Request refused'}, 403)
            return
        path = urlsplit(self.path).path
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
        if size < 24 or size > self.server.max_upload:
            self._reply({'error': 'Capture file outside configured size limit'}, 413)
            return
        # No user-provided pathname ever reaches the filesystem.
        name = self.headers.get('X-Capture-Name', 'capture.pcap')[:120]
        if not name.lower().endswith(('.pcap', '.pcapng')):
            self._reply({'error': 'Select a PCAP or PCAPNG file'}, 400)
            return
        with tempfile.TemporaryDirectory(prefix='pii_upload_') as directory:
            capture = Path(directory) / 'capture.bin'
            remaining = size
            with capture.open('wb') as output:
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
        try:
            # Serialise inference to avoid overlapping CPU-heavy analyses on the same
            # shared checkpoint during a live presentation.
            use_ml = self.server.ml_detector is not None and requested_mode != 'rules'
            with self.server.analysis_lock:
                report = analyze(capture, include_values=False,
                                 limits=AnalysisLimits(max_capture_bytes=self.server.max_upload),
                                 ml_detector=self.server.ml_detector if use_ml else None)
            self._reply({'filename': label, 'capture_bytes': capture.stat().st_size,
                         'report': report,
                         'model_enabled': use_ml,
                         'model_available': self.server.ml_detector is not None,
                         'scan_mode': 'hybrid' if use_ml else 'rules'})
        except (OSError, ValueError, TypeError, OverflowError) as exc:
            # Engine errors may include paths; never expose them verbatim in the UI.
            from .engine import AnalysisLimitError
            if isinstance(exc, AnalysisLimitError):
                # Safe diagnostic: predefined bounded budget failure, not a user path.
                self._reply({'error': str(exc), 'reason_type': 'AnalysisLimitError'}, 422)
            else:
                self._reply({'error': 'Capture rejected or analysis could not complete',
                             'reason_type': type(exc).__name__}, 422)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description='Run local-only PCAP PII investigation dashboard')
    p.add_argument('--port', type=int, default=8765)
    p.add_argument('--ml-checkpoint', default=None, help='Opt in to offline research BiLSTM checkpoint')
    args = p.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        p.error('Port must be 1024–65535')
    ml_detector = load_experimental_bilstm(args.ml_checkpoint) if args.ml_checkpoint else None
    server = DashboardServer(('127.0.0.1', args.port), ml_detector=ml_detector)
    print(f'PCAP PII dashboard: http://127.0.0.1:{args.port}/ (Ctrl+C to stop)')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
