"""Shared helpers for the independent TRACE VP QA tests (no tests in this module).

Everything is synthetic and fictional: RFC 5737 documentation addresses, example.test hosts, invented people.
A small self-contained classic-PCAP writer is used instead of the showcase generator's private helpers, so the QA tests do
not depend on another engineer's fixture code, except where the showcase itself is the thing being verified.
"""
from __future__ import annotations

import json
import socket
import struct
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
V2_DIR = ROOT / "src" / "packet_pii" / "ml" / "artifacts" / "bilstm_v2"
V2_VERSION = "bilstm-v2-d1f9e9fb9a2b"
CLIENT, SERVER = "192.0.2.", "198.51.100."


# ------------------------------------------------------------------ detector (shared, loaded once per session)
_DETECTOR = None


def v2_detector():
    """The real V2 ensemble. Skips (never fakes) when PyTorch or the artifact is unavailable."""
    global _DETECTOR
    pytest.importorskip("torch")
    if not (V2_DIR / "ensemble.json").is_file():
        pytest.skip("V2 checkpoint not present")
    if _DETECTOR is None:
        from packet_pii.hybrid import load_experimental_bilstm
        _DETECTOR = load_experimental_bilstm(str(V2_DIR))
    return _DETECTOR


def is_v2_checkpoint(det) -> bool:
    return det.model_version == V2_VERSION


# ------------------------------------------------------------------ showcase fixture
def showcase_module():
    spec = spec_from_file_location("_vp_qa_showcase", ROOT / "examples" / "generate_showcase.py")
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def showcase_pcap(tmp_path) -> Path:
    out = tmp_path / "showcase.pcap"
    showcase_module().write_pcap(out)
    return out


# ------------------------------------------------------------------ minimal PCAP builder
def _sum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def frame(src, dst, sp, dp, seq, ack, flags, payload=b"", ident=0) -> bytes:
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIHHHH", sp, dp, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, (5 << 12) | flags, 32768, 0, 0)
    pseudo = s + d + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", _sum16(pseudo + tcp + payload)) + tcp[18:] + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), ident & 0xFFFF, 0x4000, 64, 6, 0, s, d)
    ip = ip[:10] + struct.pack("!H", _sum16(ip)) + ip[12:]
    return b"\x02\xaa\xbb\xcc\xdd\x01\x02\xaa\xbb\xcc\xdd\x02\x08\x00" + ip + tcp


def write_pcap(path: Path, frames: list[tuple[float, bytes]]) -> Path:
    with open(path, "wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in frames:
            sec = int(ts)
            out.write(struct.pack("<IIII", sec, int(round((ts - sec) * 1e6)), len(data), len(data)) + data)
    return path


def conversation(idx: int, request: bytes, response: bytes = b"", *, seg: int = 0, order=None, drop=(), dup=(),
                 cseq: int = 1000, sseq: int = 50000, extra_segments=(), t0: float = 1_760_000_000.0):
    """One TCP conversation as a frame list.

    seg: split the request into segments of this many bytes (0 = one segment).
    order: permutation of segment indices to emit (out-of-order capture).
    drop: segment indices that are never captured. dup: indices emitted twice (retransmission).
    extra_segments: (offset, bytes) pairs emitted after the request (overlapping / conflicting data).
    """
    src, dst = CLIENT + str(10 + idx), SERVER + str(20 + idx)
    sport, dport = 43000 + idx, 80
    t = t0 + idx
    frames: list[tuple[float, bytes]] = []

    def emit(a, b, ap, bp, seq, ack, flags, payload=b""):
        frames.append((t + len(frames) * 1e-6, frame(a, b, ap, bp, seq, ack, flags, payload, len(frames) + idx * 100)))

    emit(src, dst, sport, dport, cseq, 0, 0x02)
    emit(dst, src, dport, sport, sseq, cseq + 1, 0x12)
    emit(src, dst, sport, dport, cseq + 1, sseq + 1, 0x10)
    size = seg or min(1400, max(1, len(request)))      # one MSS-sized segment unless told otherwise
    chunks = [(i, request[i:i + size]) for i in range(0, len(request), size)]
    seq_order = list(order) if order is not None else list(range(len(chunks)))
    for n in seq_order:
        if n in drop:
            continue
        off, data = chunks[n]
        emit(src, dst, sport, dport, cseq + 1 + off, sseq + 1, 0x18, data)
        if n in dup:
            emit(src, dst, sport, dport, cseq + 1 + off, sseq + 1, 0x18, data)
    for off, data in extra_segments:
        emit(src, dst, sport, dport, cseq + 1 + off, sseq + 1, 0x18, data)
    if response:
        emit(dst, src, dport, sport, sseq + 1, cseq + 1 + len(request), 0x18, response)
    return frames


def build_pcap(path: Path, conversations: list[list[tuple[float, bytes]]]) -> Path:
    frames = sorted((f for c in conversations for f in c), key=lambda x: x[0])
    return write_pcap(path, frames)


# ------------------------------------------------------------------ HTTP builders
def post_json(obj, path="/api/qa", host="qa.example.test", extra_headers: bytes = b"") -> bytes:
    body = obj if isinstance(obj, bytes) else json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n".encode() + extra_headers
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)


def ok_response(body: bytes = b'{"ok":true}') -> bytes:
    return b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body


def one_request_pcap(tmp_path: Path, request: bytes, response: bytes | None = None, name="qa.pcap", **kw) -> Path:
    return build_pcap(tmp_path / name, [conversation(0, request, ok_response() if response is None else response, **kw)])


def ml_findings(report):
    return [f for f in report["findings"] if f.get("detector") == "bilstm"]


def rule_findings(report):
    return [f for f in report["findings"] if f.get("detector") != "bilstm"]
