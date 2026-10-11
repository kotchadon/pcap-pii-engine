"""Bounded, defensive PCAP/PCAPNG and Ethernet/IP/TCP decoding.

This is an educational MVP, not a replacement for Wireshark's mature dissectors.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ipaddress
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
    pass


def _read_pcap(stream) -> Iterator[RawFrame]:
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
    _ver_maj, _ver_min, _tz, _sig, _snaplen, linktype = struct.unpack(endian+'HHiIII', header)
    linktype &= 0xFFFF
    while True:
        header = stream.read(16)
        if not header:
            break
        if len(header) != 16:
            break
        sec, frac, included_len, _original_len = struct.unpack(endian+'IIII', header)
        if included_len > 16 * 1024 * 1024:
            break
        data = stream.read(included_len)
        if len(data) != included_len:
            break
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


def _read_pcapng(stream) -> Iterator[RawFrame]:
    endian = None
    interfaces: list[tuple[int, float, float]] = []
    while True:
        header = stream.read(8)
        if not header:
            break
        if len(header) != 8:
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
            if block_len < 28 or block_len > 16*1024*1024:
                raise CaptureFormatError('Invalid PCAPNG section header length')
            rest = stream.read(block_len-12)
            if len(rest) != block_len-12:
                break
            interfaces = []
            continue
        if endian is None:
            raise CaptureFormatError('PCAPNG needs a section header block')
        kind, block_len = struct.unpack(endian+'II', header)
        if block_len < 12 or block_len > 16*1024*1024 or block_len % 4:
            break
        remainder = stream.read(block_len-8)
        if len(remainder) != block_len-8:
            break
        if struct.unpack_from(endian+'I', remainder, len(remainder)-4)[0] != block_len:
            continue
        body = remainder[:-4]
        if kind == 1 and len(body) >= 8:  # Interface Description Block
            linktype = struct.unpack_from(endian+'H', body, 0)[0]
            resolution, offset = 1e-6, 0.0
            for code, value in _options(body[8:], endian):
                if code == 9 and value:
                    resolution = (2.0 ** -(value[0] & 0x7f)) if value[0]&0x80 else (10.0 ** -value[0])
                elif code == 14 and len(value) == 8:
                    offset = float(struct.unpack(endian+'q',value)[0])
            interfaces.append((linktype, resolution, offset))
        elif kind == 6 and len(body) >= 20:  # Enhanced Packet Block
            interface, high, low, caplen, _wirelen = struct.unpack_from(endian+'IIIII', body, 0)
            if interface >= len(interfaces) or caplen > len(body)-20:
                continue
            linktype, resolution, offset = interfaces[interface]
            stamp = ((high << 32)|low) * resolution + offset
            yield RawFrame(stamp, linktype, body[20:20+caplen])


def read_frames(path: str | Path) -> Iterator[RawFrame]:
    with open(path, 'rb') as stream:
        magic = stream.read(4)
        stream.seek(0)
        if magic == b'\x0a\x0d\x0d\x0a':
            yield from _read_pcapng(stream)
        else:
            yield from _read_pcap(stream)


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
            if ihl < 20 or len(data) < ihl or data[9] != 6:
                return None
            frag = int.from_bytes(data[6:8], 'big')
            if frag & 0x3FFF:  # fragment: no IP reassembly in MVP
                return None
            src = str(ipaddress.IPv4Address(data[12:16]))
            dst = str(ipaddress.IPv4Address(data[16:20]))
            transport = data[ihl:min(len(data),total)]
        elif proto == 0x86DD:
            if len(data) < 40 or data[0] >> 4 != 6 or data[6] != 6:
                return None  # IPv6 extension headers currently not supported
            src = str(ipaddress.IPv6Address(data[8:24]))
            dst = str(ipaddress.IPv6Address(data[24:40]))
            payload_len = int.from_bytes(data[4:6], 'big')
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


def reassemble(segments: list[TcpPacket]) -> tuple[bytes, bool]:
    """Return the contiguous TCP payload prefix and whether reconstruction was unsafe.

    Identical retransmissions are deduplicated; gaps or conflicting overlaps
    stop reconstruction. Sequence wraparound and reuse of
    the same 4-tuple for separate connections are limitations of this MVP.
    """
    data_segs = sorted(
        ((p.seq, p.payload) for p in segments if p.payload),
        key=lambda segment: segment[0],
    )
    if not data_segs:
        return b'', False

    # A SYN consumes one TCP sequence number. When observed, it gives us the
    # expected start of the byte stream, so missing initial data is visible.
    # Without a SYN, the capture may begin mid-stream; the first observed
    # payload is our best available starting point, not proof of completeness.
    syn_starts = [p.seq + 1 for p in segments if p.flags & 0x02]
    base = min(syn_starts) if syn_starts else data_segs[0][0]
    out = bytearray()
    for seq, payload in data_segs:
        start = seq - base
        if start < 0 or start > len(out):
            return bytes(out), True

        overlap = min(len(payload), len(out) - start)
        # A conflicting retransmission makes the stream ambiguous. Do not
        # silently choose one version and risk reporting invented content.
        if overlap and out[start:start + overlap] != payload[:overlap]:
            return bytes(out), True
        extension = payload[overlap:]
        if len(out) + len(extension) > 16 * 1024 * 1024:
            return bytes(out), True
        out.extend(extension)
    return bytes(out), False
