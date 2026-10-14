"""Bounded, defensive PCAP/PCAPNG and Ethernet/IP/TCP decoding.

This is an educational MVP, not a replacement for Wireshark's mature dissectors.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ipaddress
import math
import os
import stat
import struct
from typing import Iterator


@dataclass(frozen=True)
class RawFrame:
    timestamp: float
    linktype: int
    data: bytes


@dataclass(frozen=True)
class TcpPacket:
    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    seq: int
    flags: int
    payload: bytes


class CaptureFormatError(ValueError):
    """The input capture is unreadable or not a supported PCAP/PCAPNG."""


MAX_CAPTURE_FILE_BYTES = 128 * 1024 * 1024
MAX_RECORD_BYTES = 16 * 1024 * 1024


@dataclass
class CaptureDiagnostics:
    """Nonfatal capture corruption; an otherwise valid report may be incomplete."""
    truncated_records: int = 0
    malformed_records: int = 0

    @property
    def incomplete(self) -> bool:
        return bool(self.truncated_records or self.malformed_records)


def _read_pcap(stream, diagnostics: CaptureDiagnostics) -> Iterator[RawFrame]:
    magic = stream.read(4)
    formats = {
        b'\xd4\xc3\xb2\xa1': ('<', 1_000_000),
        b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
        b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000),
        b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000),
    }
    if magic not in formats:
        raise CaptureFormatError('Unknown PCAP magic')
    endian, denominator = formats[magic]
    header = stream.read(20)
    if len(header) != 20:
        raise CaptureFormatError('Truncated PCAP header')
    major, minor, _tz, _sig, snaplen, linktype = struct.unpack(endian+'HHiIII', header)
    if major != 2 or minor != 4 or snaplen == 0:
        raise CaptureFormatError('Unsupported or invalid PCAP global header')
    linktype &= 0xFFFF
    while True:
        header = stream.read(16)
        if not header:
            break
        if len(header) != 16:
            diagnostics.truncated_records += 1
            break
        sec, frac, included_len, original_len = struct.unpack(endian+'IIII', header)
        if included_len > MAX_RECORD_BYTES:
            diagnostics.malformed_records += 1
            break  # Refuse attacker-sized allocation; no partial record accepted.
        if included_len > snaplen or included_len > original_len or frac >= denominator:
            diagnostics.malformed_records += 1
            break
        data = stream.read(included_len)
        if len(data) != included_len:
            diagnostics.truncated_records += 1
            break
        if included_len < original_len:
            diagnostics.truncated_records += 1
        yield RawFrame(sec + frac / denominator, linktype, data)


def _options(data: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack_from(endian+'HH', data, offset)
        offset += 4
        if code == 0:
            return
        if offset + length > len(data):
            return
        yield code, data[offset:offset+length]
        offset += (length+3) & ~3


def _read_pcapng(stream, diagnostics: CaptureDiagnostics) -> Iterator[RawFrame]:
    endian = None
    interfaces: list[tuple[int, float, float, int]] = []
    while True:
        header = stream.read(8)
        if not header:
            break
        if len(header) != 8:
            diagnostics.truncated_records += 1
            break
        if header[:4] == b'\x0a\x0d\x0d\x0a':
            bom = stream.read(4)
            if bom == b'\x4d\x3c\x2b\x1a':
                endian = '<'
            elif bom == b'\x1a\x2b\x3c\x4d':
                endian = '>'
            else:
                raise CaptureFormatError('Invalid PCAPNG byte order magic')
            block_len = struct.unpack(endian+'I', header[4:])[0]
            if block_len < 28 or block_len > MAX_RECORD_BYTES or block_len % 4:
                raise CaptureFormatError('Invalid PCAPNG section header length')
            rest = stream.read(block_len-12)
            if len(rest) != block_len-12:
                diagnostics.truncated_records += 1
                break
            if struct.unpack_from(endian+'I', rest, len(rest)-4)[0] != block_len:
                diagnostics.malformed_records += 1
                break  # A broken section cannot safely establish byte order.
            interfaces = []
            continue
        if endian is None:
            raise CaptureFormatError('PCAPNG needs a section header block')
        kind, block_len = struct.unpack(endian+'II', header)
        if block_len < 12 or block_len > MAX_RECORD_BYTES or block_len % 4:
            diagnostics.malformed_records += 1
            break
        remainder = stream.read(block_len-8)
        if len(remainder) != block_len-8:
            diagnostics.truncated_records += 1
            break
        if struct.unpack_from(endian+'I', remainder, len(remainder)-4)[0] != block_len:
            diagnostics.malformed_records += 1
            continue
        body = remainder[:-4]
        if kind == 1:  # Interface Description Block
            if len(body) < 8:
                diagnostics.malformed_records += 1
                continue
            linktype = struct.unpack_from(endian+'H', body, 0)[0]
            resolution, offset = 1e-6, 0.0
            for code, value in _options(body[8:], endian):
                if code == 9 and value:
                    resolution = (2.0 ** -(value[0] & 0x7f)) if value[0]&0x80 else (10.0 ** -value[0])
                elif code == 14 and len(value) == 8:
                    offset = float(struct.unpack(endian+'q',value)[0])
            interfaces.append((linktype, resolution, offset,
                               struct.unpack_from(endian+'I', body, 4)[0]))
        elif kind == 6:  # Enhanced Packet Block
            if len(body) < 20:
                diagnostics.malformed_records += 1
                continue
            interface, high, low, caplen, wirelen = struct.unpack_from(endian+'IIIII', body, 0)
            if interface >= len(interfaces) or caplen > wirelen or caplen > len(body)-20:
                diagnostics.malformed_records += 1
                continue
            linktype, resolution, offset, snaplen = interfaces[interface]
            if (snaplen and caplen > snaplen) or ((caplen + 3) & ~3) > len(body)-20:
                diagnostics.malformed_records += 1
                continue
            if caplen < wirelen:
                diagnostics.truncated_records += 1
            stamp = ((high << 32)|low) * resolution + offset
            # Reject invalid/out-of-range clocks before datetime processing.
            if not math.isfinite(stamp) or not (-62135596800 <= stamp <= 253402300799):
                diagnostics.malformed_records += 1
                continue
            yield RawFrame(stamp, linktype, body[20:20+caplen])


def read_frames(path: str | Path, *,
                diagnostics: CaptureDiagnostics | None = None,
                max_file_bytes: int = MAX_CAPTURE_FILE_BYTES) -> Iterator[RawFrame]:
    """Read capture records, rejecting large/non-regular inputs before reading.

    A truncated trailing record is ignored but surfaced via `diagnostics`;
    downstream reports must not suggest the entire capture was processed.
    Limits apply to the input file, including non-payload record overhead.
    """
    if type(max_file_bytes) is not int or max_file_bytes <= 0:
        raise ValueError('max_file_bytes must be a positive integer')
    diag = diagnostics if diagnostics is not None else CaptureDiagnostics()
    # Preflight prevents opening a FIFO/device from blocking indefinitely.
    if not stat.S_ISREG(Path(path).stat().st_mode):
        raise CaptureFormatError('Capture must be a regular file')
    with open(path, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise CaptureFormatError('Capture must be a regular file')
        if info.st_size > max_file_bytes:
            raise CaptureFormatError('Capture exceeds configured file-size limit')
        magic = stream.read(4)
        stream.seek(0)
        if magic == b'\x0a\x0d\x0d\x0a':
            yield from _read_pcapng(stream, diag)
        else:
            yield from _read_pcap(stream, diag)


def decode_tcp(frame: RawFrame) -> TcpPacket | None:
    data = frame.data
    try:
        if frame.linktype == 1:  # Ethernet, optionally VLAN tagged
            if len(data) < 14:
                return None
            proto = int.from_bytes(data[12:14], 'big')
            at = 14
            for _ in range(2):
                if proto not in (0x8100, 0x88A8, 0x9100) or len(data) < at+4:
                    break
                proto = int.from_bytes(data[at+2:at+4], 'big')
                at += 4
            data = data[at:]
        elif frame.linktype == 101:  # Raw IPv4/IPv6
            proto = 0x0800 if data and data[0] >> 4 == 4 else 0x86DD
        elif frame.linktype == 113 and len(data) >= 16:  # Linux cooked v1
            proto = int.from_bytes(data[14:16], 'big')
            data = data[16:]
        elif frame.linktype == 276 and len(data) >= 20:  # Linux cooked v2
            proto = int.from_bytes(data[0:2], 'big')
            data = data[20:]
        else:
            return None
        if proto == 0x0800:
            if len(data) < 20 or data[0] >> 4 != 4:
                return None
            ihl = (data[0] & 15) * 4
            total = int.from_bytes(data[2:4], 'big')
            if ihl < 20 or total < ihl or len(data) < total or data[9] != 6:
                return None
            frag = int.from_bytes(data[6:8], 'big')
            if frag & 0x3FFF:  # fragment: no IP reassembly in MVP
                return None
            src = str(ipaddress.IPv4Address(data[12:16]))
            dst = str(ipaddress.IPv4Address(data[16:20]))
            transport = data[ihl:total]
        elif proto == 0x86DD:
            if len(data) < 40 or data[0] >> 4 != 6 or data[6] != 6:
                return None  # IPv6 extension headers currently not supported
            src = str(ipaddress.IPv6Address(data[8:24]))
            dst = str(ipaddress.IPv6Address(data[24:40]))
            payload_len = int.from_bytes(data[4:6], 'big')
            if len(data) < 40 + payload_len:
                return None
            transport = data[40:40+payload_len]
        else:
            return None
        if len(transport) < 20:
            return None
        sport, dport, seq = struct.unpack_from('!HHI', transport, 0)
        thl = (transport[12] >> 4)*4
        if thl < 20 or thl > len(transport):
            return None
        return TcpPacket(frame.timestamp,src,dst,sport,dport,seq,transport[13],transport[thl:])
    except (ValueError, struct.error, IndexError):
        return None


def endpoint_key(pkt: TcpPacket) -> tuple[tuple[str,int],tuple[str,int]]:
    return tuple(sorted(((pkt.src,pkt.sport),(pkt.dst,pkt.dport))))  # type: ignore[return-value]


def sequence_offset(seq: int, base: int) -> int:
    """Signed TCP serial distance; callers must keep a window below 2**31."""
    return ((seq - base + (1 << 31)) & 0xffffffff) - (1 << 31)


@dataclass(frozen=True)
class ReassemblyResult:
    """Observed bytes, conservative usable prefix, and evidence limitations.

    `data` preserves the legacy conflict policy. Only `safe_prefix` excludes
    ambiguous bytes. Neither implies endpoint acceptance or capture completeness.
    `base_seq` is the sequence number of offset zero (None for no observed data).
    """
    data: bytes
    safe_prefix: bytes
    unsafe: bool
    diagnostics: tuple[str, ...]
    base_seq: int | None


def reassemble_detailed(segments: list[TcpPacket]) -> ReassemblyResult:
    """Reassemble ONE direction of ONE session within a 16 MiB window.

    Equal-sequence ties retain capture order; overlaps must match exactly. Gaps
    stop assembly. Missing SYN/FIN are unknown coverage, not inferred loss.
    """
    notes: list[str] = []
    base = None

    def result(data=b'', unsafe=False, reason=None, safe=None):
        labels = notes + ([reason] if reason else [])
        usable = data if safe is None else safe
        # Terminal evidence applies on every path, including an earlier gap or
        # conflict. Never expose post-FIN bytes just because assembly stopped.
        if base is not None:
            ends = [sequence_offset(p.seq + bool(p.flags & 2) + len(p.payload), base)
                    for p in segments if p.flags & 1]
            if ends and any(end != len(data) for end in ends):
                unsafe = True
                usable = usable[:max(0, min(ends))]
                if 'fin_boundary_mismatch' not in labels:
                    labels.append('fin_boundary_mismatch')
        return ReassemblyResult(data, usable, unsafe, tuple(labels), base)

    directions = {(p.src, p.sport, p.dst, p.dport) for p in segments}
    if len(directions) > 1:
        return result(unsafe=True, reason='mixed_directions')
    data_segs = [((p.seq + bool(p.flags & 2)) & 0xffffffff, p.payload)
                 for p in segments if p.payload]
    syn_starts = {(p.seq + 1) & 0xffffffff for p in segments if p.flags & 2}
    if len(syn_starts) > 1:
        return result(unsafe=True, reason='multiple_handshakes')
    if not syn_starts:
        notes.append('initial_coverage_unknown')
    if not any(p.flags & 1 for p in segments):
        notes.append('final_coverage_unknown')
    reset = any(p.flags & 4 for p in segments)
    if reset:
        notes.append('reset_observed')
    if not data_segs and not syn_starts:
        return result(unsafe=reset)
    anchor = next(iter(syn_starts)) if syn_starts else data_segs[0][0]
    offsets = [(sequence_offset(seq, anchor), payload) for seq, payload in data_segs]
    base_offset = 0 if syn_starts else min(at for at, _ in offsets)
    base = (anchor + base_offset) & 0xffffffff
    out = bytearray()
    for at, payload in sorted(offsets, key=lambda item: item[0]):
        start = at - base_offset
        if start < 0 or start > len(out):
            return result(bytes(out), True, 'sequence_gap')
        overlap = min(len(payload), len(out) - start)
        if overlap and out[start:start + overlap] != payload[:overlap]:
            return result(bytes(out), True, 'conflicting_overlap', bytes(out[:start]))
        extension = payload[overlap:]
        if len(out) + len(extension) > 16 * 1024 * 1024:
            return result(bytes(out), True, 'direction_limit')
        out.extend(extension)
    for p in segments:
        if p.flags & 1:
            fin_at = sequence_offset(p.seq + bool(p.flags & 2) + len(p.payload), base)
            if fin_at != len(out):
                safe = bytes(out[:max(0, fin_at)]) if fin_at < len(out) else bytes(out)
                return result(bytes(out), True, 'fin_boundary_mismatch', safe)
    return result(bytes(out), reset)


def reassemble(segments: list[TcpPacket]) -> tuple[bytes, bool]:
    """Legacy tuple API. New callers should inspect reassemble_detailed().

    The returned flag detects observed ambiguity/loss, not unobserved packets.
    Legacy conflicting-overlap bytes are retained for compatibility; callers
    needing unambiguous evidence must consume the detailed result's safe_prefix.
    """
    result = reassemble_detailed(segments)
    return result.data, result.unsafe


def split_tcp_sessions(packets: list[TcpPacket]) -> list[list[TcpPacket]]:
    """Partition one four-tuple's bidirectional packets in capture order.

    A changed SYN ISN starts a new epoch; repeated SYNs do not. RST or FIN in
    both directions closes an epoch. Payload after closure starts an unobserved
    epoch. A half-close still permits data in the opposite direction.

    This is an observational partition, not a TCP endpoint state machine:
    delayed old packets and reuse with missing handshakes remain ambiguous.
    Timestamps are not sorted because capture clocks can move backwards.
    """
    if len({endpoint_key(p) for p in packets}) > 1:
        raise ValueError('split_tcp_sessions requires one endpoint pair')
    sessions: list[list[TcpPacket]] = []
    current: list[TcpPacket] = []
    syns: dict[tuple[str, int], int] = {}
    fins: set[tuple[str, int]] = set()
    closed = False
    has_payload = False
    for p in packets:
        direction = (p.src, p.sport)
        syn = bool(p.flags & 2)
        new_syn = syn and (
            closed or (direction in syns and syns[direction] != p.seq) or
            (not p.flags & 16 and direction not in syns and has_payload)
        )
        if current and (new_syn or (closed and p.payload)):
            sessions.append(current)
            current, syns, fins = [], {}, set()
            closed = has_payload = False
        current.append(p)
        if syn:
            syns[direction] = p.seq
        if p.flags & 1:
            fins.add(direction)
        closed = closed or bool(p.flags & 4) or len(fins) == 2
        has_payload = has_payload or bool(p.payload)
    if current:
        sessions.append(current)
    return sessions
