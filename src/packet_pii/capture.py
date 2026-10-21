"""Bounded, defensive PCAP/PCAPNG and Ethernet/IP/TCP decoding.

This is an educational MVP, not a replacement for Wireshark's mature dissectors.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
import hashlib
import ipaddress
import math
import os
import stat
import struct
from typing import Iterator

from .ip_reassembly import FragmentEvidence


@dataclass(frozen=True)
class RawFrame:
    timestamp: float
    linktype: int
    data: bytes
    # Packet record ordinals are 1-based, across all PCAPNG sections. Offsets
    # are absolute file byte offsets; absent metadata is never guessed.
    frame_index: int | None = None
    record_offset: int | None = None
    data_offset: int | None = None
    captured_length: int | None = None
    wire_length: int | None = None
    timestamp_resolution: float | None = None
    interface_id: int | None = None
    section_index: int | None = None
    truncated: bool = False


@dataclass(frozen=True)
class PacketSourceRange:
    """Half-open TCP payload and original captured frame byte ranges.

    No raw payload is retained here. `data_offset + frame_start` locates the
    source bytes in the capture file. A fragment may contribute only a slice.
    """
    payload_start: int
    payload_end: int
    frame_index: int
    frame_start: int
    frame_end: int
    record_offset: int | None
    data_offset: int | None
    captured_length: int
    wire_length: int
    timestamp: float
    timestamp_resolution: float | None
    linktype: int
    interface_id: int | None
    section_index: int | None


def _source_range(frame: RawFrame, start: int, end: int,
                  payload_start: int = 0) -> PacketSourceRange | None:
    if frame.frame_index is None:
        return None  # Legacy/programmatic packets have no capture identity.
    return PacketSourceRange(payload_start, payload_start + end - start,
        frame.frame_index, start, end, frame.record_offset, frame.data_offset,
        frame.captured_length if frame.captured_length is not None else len(frame.data),
        frame.wire_length if frame.wire_length is not None else len(frame.data),
        frame.timestamp, frame.timestamp_resolution, frame.linktype,
        frame.interface_id, frame.section_index)


def clip_packet_source(source: PacketSourceRange, start: int,
                       end: int, shift: int = 0) -> PacketSourceRange:
    """Clip using TCP payload coordinates, preserving original byte offsets.

    ``shift`` is subtracted from the clipped payload coordinates (re-basing after a header is removed); frame offsets
    are unaffected. Constructed directly rather than via ``dataclasses.replace``, which dominated decode profiles.
    """
    if not source.payload_start <= start <= end <= source.payload_end:
        raise ValueError('source clip outside range')
    base = source.frame_start - source.payload_start
    return PacketSourceRange(start - shift, end - shift, source.frame_index, base + start, base + end,
                             source.record_offset, source.data_offset, source.captured_length, source.wire_length,
                             source.timestamp, source.timestamp_resolution, source.linktype, source.interface_id,
                             source.section_index)


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
    ack: int | None = None
    network_protocol: str | None = None
    network_offset: int | None = None
    payload_offset: int | None = None
    ipv4_checksum: str = 'not_checked'
    tcp_checksum: str = 'not_checked'
    source_ranges: tuple[PacketSourceRange, ...] = ()
    frame_index: int | None = None
    # Fragmented packets have multiple source frames and no single payload offset.
    reassembled_fragments: bool = False
    fragment_evidence: FragmentEvidence | None = None


class CaptureFormatError(ValueError):
    """The input capture is unreadable or not a supported PCAP/PCAPNG."""


MAX_CAPTURE_FILE_BYTES = 128 * 1024 * 1024
MAX_RECORD_BYTES = 16 * 1024 * 1024


@dataclass
class CaptureDiagnostics:
    """Nonfatal capture corruption; an otherwise valid report may be incomplete."""
    truncated_records: int = 0
    malformed_records: int = 0
    unsupported_packet_records: int = 0
    capture_sha256: str | None = None
    capture_bytes: int | None = None
    identity_status: str = 'not_finalized'

    @property
    def incomplete(self) -> bool:
        return bool(self.truncated_records or self.malformed_records or self.unsupported_packet_records)


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
    frame_index = 0
    while True:
        record_offset = stream.tell()
        header = stream.read(16)
        if not header:
            break
        if len(header) != 16:
            diagnostics.truncated_records += 1
            break
        frame_index += 1
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
        yield RawFrame(sec + frac / denominator, linktype, data, frame_index,
                       record_offset, record_offset + 16, included_len,
                       original_len, 1 / denominator, 0, 0,
                       included_len < original_len)


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
    frame_index, section_index = 0, -1
    while True:
        record_offset = stream.tell()
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
            section_index += 1
            continue
        if endian is None:
            raise CaptureFormatError('PCAPNG needs a section header block')
        kind, block_len = struct.unpack(endian+'II', header)
        if kind in (2, 3, 6):  # Include unsupported/malformed packet records in ordinals.
            frame_index += 1
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
        if kind in (2, 3):
            diagnostics.unsupported_packet_records += 1
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
            yield RawFrame(stamp, linktype, body[20:20+caplen], frame_index,
                           record_offset, record_offset + 28, caplen, wirelen,
                           resolution, interface, section_index, caplen < wirelen)


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
        digest = hashlib.sha256()

        class _HashedReader:
            count = 0

            def tell(self):
                return stream.tell()

            def read(self, size=-1):
                chunk = stream.read(size)
                self.count += len(chunk)
                if self.count > max_file_bytes:
                    raise CaptureFormatError('Capture exceeds configured file-size limit')
                digest.update(chunk)
                return chunk

        reader = _HashedReader()
        diag.capture_sha256, diag.capture_bytes = None, None
        diag.identity_status = 'not_finalized'
        if magic == b'\x0a\x0d\x0d\x0a':
            yield from _read_pcapng(reader, diag)
        else:
            yield from _read_pcap(reader, diag)
        # A malformed record can terminate parsing early. The capture identity
        # includes its uninterpreted tail too, using this same open descriptor.
        while reader.read(1024 * 1024):
            pass
        after = os.fstat(stream.fileno())
        if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or reader.count != info.st_size):
            diag.identity_status = 'changed_during_read'
            raise CaptureFormatError('Capture changed during analysis')
        diag.capture_sha256 = digest.hexdigest()
        diag.capture_bytes = reader.count
        diag.identity_status = 'verified_read'


# Reasons a frame is not turned into a TCP packet. Those in EVIDENCE_LOSS_REASONS may hide TCP payload that TRACE
# cannot analyse, so a report containing them is incomplete; the others are outside the supported scope (non-TCP, unknown link).
SKIP_NON_TCP = 'non_tcp'
SKIP_UNSUPPORTED_LINK = 'unsupported_link_type'
SKIP_IP_FRAGMENT = 'ip_fragment'
SKIP_IPV6_EXTENSION = 'ipv6_extension_header'
SKIP_TRUNCATED = 'truncated_packet'
SKIP_MALFORMED = 'malformed_packet'
EVIDENCE_LOSS_REASONS = frozenset({SKIP_IP_FRAGMENT, SKIP_IPV6_EXTENSION, SKIP_TRUNCATED,
    'fragment_overlap', 'fragment_limit', 'fragment_timeout', 'fragment_incomplete',
    'fragment_identity_reuse', 'fragment_malformed'})
_IPV6_EXTENSION_HEADERS = frozenset({0, 43, 44, 50, 51, 60, 135, 139, 140})


def _checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum. Because 2**16 = 1 (mod 0xffff), the folded ones'-complement sum of the 16-bit
    words equals the big-endian integer modulo 0xffff, except that a non-zero sum folds to 0xffff rather than 0 and an
    all-zero input folds to 0 - handled explicitly. Equivalent to the word-by-word loop (fuzz-tested), in C speed."""
    if len(data) & 1:
        data += b'\0'
    value = int.from_bytes(data, 'big')
    folded = 0 if value == 0 else (value % 0xffff or 0xffff)
    return (~folded) & 0xffff


def _link_network(frame: RawFrame) -> tuple[int | None, int, str | None]:
    data = frame.data
    if frame.linktype == 1:
        if len(data) < 14:
            return None, 0, SKIP_MALFORMED
        proto, at = int.from_bytes(data[12:14], 'big'), 14
        for _ in range(2):
            if proto not in (0x8100, 0x88A8, 0x9100):
                break
            if len(data) < at + 4:
                return None, 0, SKIP_TRUNCATED
            proto, at = int.from_bytes(data[at+2:at+4], 'big'), at + 4
        return proto, at, None
    if frame.linktype == 101:
        return (0x0800 if data and data[0] >> 4 == 4 else 0x86DD), 0, None
    if frame.linktype == 113 and len(data) >= 16:
        return int.from_bytes(data[14:16], 'big'), 16, None
    if frame.linktype == 276 and len(data) >= 20:
        return int.from_bytes(data[:2], 'big'), 20, None
    return None, 0, SKIP_UNSUPPORTED_LINK


def _ipv6_chain(data: bytes, next_header: int, at: int, *, depth: int = 0):
    """Walk inspectable extensions with strict bounds; stop at fragment/TCP.

    ESP and unknown/mobility extensions remain unsupported. Routing with live
    segments is unsupported because the final pseudo-header destination differs.
    """
    start = at
    while next_header in (0, 43, 51, 60):
        depth += 1
        if depth > 8 or at + 2 > len(data):
            return next_header, at, depth, SKIP_IPV6_EXTENSION
        size = (data[at+1] + 2) * 4 if next_header == 51 else (data[at+1] + 1) * 8
        if size < 8 or at + size > len(data):
            return next_header, at, depth, SKIP_MALFORMED
        if at + size - start > 2048:
            return next_header, at, depth, SKIP_IPV6_EXTENSION
        if next_header == 43 and data[at+3]:
            return next_header, at, depth, SKIP_IPV6_EXTENSION
        next_header, at = data[at], at + size
    if next_header in _IPV6_EXTENSION_HEADERS and next_header != 44:
        return next_header, at, depth, SKIP_IPV6_EXTENSION
    return next_header, at, depth, None


def _tcp_packet(frame: RawFrame, transport: bytes, src: str, dst: str,
                network_offset: int, transport_offset: int | None,
                version: int, ip_checksum: str,
                sources: tuple[PacketSourceRange, ...] = (),
                fragmented: bool = False,
                fragment_evidence: FragmentEvidence | None = None,
                address_bytes: bytes | None = None) -> tuple[TcpPacket | None, str | None]:
    if len(transport) < 20:
        return None, SKIP_MALFORMED
    sport, dport, seq, ack = struct.unpack_from('!HHII', transport)
    thl = (transport[12] >> 4) * 4
    if thl < 20 or thl > len(transport):
        return None, SKIP_MALFORMED
    if transport_offset is not None:
        source = _source_range(frame, transport_offset + thl,
                               transport_offset + len(transport))
        payload_sources = (source,) if source is not None and len(transport) > thl else ()
    else:
        payload_sources = []
        for source in sources:
            start, end = max(thl, source.payload_start), min(len(transport), source.payload_end)
            if start < end:
                payload_sources.append(clip_packet_source(source, start, end, thl))
        payload_sources = tuple(payload_sources)
    # The decoder passes the raw source+destination address bytes; re-parsing the strings is only a fallback.
    packed = (address_bytes if address_bytes is not None
              else ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed)
    pseudo = packed + (struct.pack('!BBH', 0, 6, len(transport)) if version == 4 else
                       struct.pack('!I3xB', len(transport), 6))
    tcp_checksum = 'valid' if _checksum(pseudo + transport) == 0 else 'mismatch_offload_possible'
    return TcpPacket(frame.timestamp, src, dst, sport, dport, seq, transport[13], transport[thl:],
                     ack, f'ipv{version}', network_offset,
                     None if transport_offset is None else transport_offset + thl,
                     ip_checksum, tcp_checksum, payload_sources,
                     None if fragmented else frame.frame_index, fragmented, fragment_evidence), None


def _decode_tcp(frame: RawFrame, fragments=None) -> tuple[TcpPacket | None, str | None]:
    try:
        proto, network_at, reason = _link_network(frame)
        if reason:
            return None, reason
        data = frame.data[network_at:]
        if proto == 0x0800:
            if len(data) < 20 or data[0] >> 4 != 4:
                return None, SKIP_MALFORMED
            ihl, total = (data[0] & 15) * 4, int.from_bytes(data[2:4], 'big')
            if ihl < 20 or total < ihl:
                return None, SKIP_MALFORMED
            if data[9] != 6:
                return None, SKIP_NON_TCP
            if len(data) < total:
                return None, SKIP_TRUNCATED
            src, dst = '%d.%d.%d.%d' % tuple(data[12:16]), '%d.%d.%d.%d' % tuple(data[16:20])  # == str(IPv4Address)
            ip_checksum = 'valid' if _checksum(data[:ihl]) == 0 else 'mismatch_offload_possible'
            frag = int.from_bytes(data[6:8], 'big')
            if frag & 0x8000 or (frag & 0x4000 and frag & 0x3fff):
                return None, SKIP_MALFORMED
            if frag & 0x3fff:
                if fragments is None:
                    return None, SKIP_IP_FRAGMENT
                offset, more = (frag & 0x1fff) * 8, bool(frag & 0x2000)
                source = _source_range(frame, network_at + ihl, network_at + total, offset)
                key = (frame.section_index, frame.interface_id, frame.linktype,
                       frame.data[:network_at], 4, src, dst, 6, int.from_bytes(data[4:6], 'big'))
                transport, sources, reason = fragments.accept(key, offset, more, data[ihl:total],
                    source, version=4, max_length=65535-ihl)
                if transport is None:
                    return None, reason
                return _tcp_packet(frame, transport, src, dst, network_at, None, 4,
                                   'fragment_headers_not_aggregated', sources, True, fragments.last_evidence,
                                   address_bytes=data[12:20])
            return _tcp_packet(frame, data[ihl:total], src, dst, network_at, network_at + ihl, 4, ip_checksum,
                               address_bytes=data[12:20])
        if proto == 0x86DD:
            if len(data) < 40 or data[0] >> 4 != 6:
                return None, SKIP_MALFORMED
            payload_len = int.from_bytes(data[4:6], 'big')
            if len(data) < 40 + payload_len:
                return None, SKIP_TRUNCATED
            data = data[:40 + payload_len]
            src, dst = str(ipaddress.IPv6Address(data[8:24])), str(ipaddress.IPv6Address(data[24:40]))
            next_header, at, depth, reason = _ipv6_chain(data, data[6], 40)
            if reason:
                return None, reason
            sources, fragmented = (), False
            transport_at = network_at + at
            if next_header == 44:
                if depth >= 8 or at + 8 > len(data):
                    return None, SKIP_MALFORMED
                next_header = data[at]
                bits = int.from_bytes(data[at+2:at+4], 'big')
                if data[at+1] or bits & 6:
                    return None, SKIP_MALFORMED
                offset, more = bits & 0xfff8, bool(bits & 1)
                fragment_data = data[at+8:]
                if offset or more:
                    if fragments is None:
                        return None, SKIP_IP_FRAGMENT
                    key = (frame.section_index, frame.interface_id, frame.linktype,
                           frame.data[:network_at], 6, src, dst,
                           int.from_bytes(data[at+4:at+8], 'big'))
                    # Exclude mutable length/hop-limit, compare traffic/flow,
                    # extension chain and upper protocol within one identity.
                    context = data[:4] + bytes([data[6], next_header]) + data[40:at]
                    if next_header not in (6, 0, 43, 51, 60):
                        if key in fragments.entries:
                            _data, _sources, why = fragments.accept(key, offset, more, b'', None,
                                version=6, context=context)
                            return None, why
                        return None, (SKIP_IPV6_EXTENSION if next_header in _IPV6_EXTENSION_HEADERS else SKIP_NON_TCP)
                    # RFC 8200: fragment zero contains the complete upper-layer
                    # header; later fragments are opaque until reassembly.
                    if offset == 0:
                        upper, first_at, _d, why = _ipv6_chain(fragment_data, next_header, 0, depth=depth+1)
                        if (why or upper != 6 or first_at + 20 > len(fragment_data) or
                                (fragment_data[first_at+12] >> 4) * 4 < 20 or
                                first_at + (fragment_data[first_at+12] >> 4) * 4 > len(fragment_data)):
                            _data, _sources, why = fragments.accept(key, offset, more, b'', None,
                                version=6, context=context)
                            return None, why
                    source = _source_range(frame, network_at + at + 8, network_at + len(data), offset)
                    transport, sources, reason = fragments.accept(key, offset, more, fragment_data,
                        source, version=6, context=context, max_length=65535-(at-40))
                    if transport is None:
                        return None, reason
                    fragmented = True
                    transport_at = None
                else:
                    # Atomic fragments are independent of pending assemblies.
                    transport, transport_at = fragment_data, network_at + at + 8
                next_header, skip, _depth, reason = _ipv6_chain(transport, next_header, 0, depth=depth+1)
                if reason or next_header == 44:
                    return None, reason or SKIP_IPV6_EXTENSION
                if skip:
                    clipped = []
                    for source in sources:
                        start, end = max(skip, source.payload_start), source.payload_end
                        if start < end:
                            clipped.append(clip_packet_source(source, start, end, skip))
                    sources = tuple(clipped)
                    transport = transport[skip:]
                    if transport_at is not None:
                        transport_at += skip
            else:
                transport = data[at:]
            if next_header != 6:
                return None, SKIP_NON_TCP
            return _tcp_packet(frame, transport, src, dst, network_at, transport_at, 6,
                               'not_applicable', sources, fragmented,
                               fragments.last_evidence if fragmented else None, address_bytes=data[8:40])
        return None, SKIP_NON_TCP
    except (ValueError, struct.error, IndexError):
        return None, SKIP_MALFORMED


def decode_tcp(frame: RawFrame) -> TcpPacket | None:
    return decode_tcp_with_reason(frame)[0]


def decode_tcp_with_reason(frame: RawFrame) -> tuple[TcpPacket | None, str | None]:
    """Stateless compatibility API; use TcpDecoder for bounded fragment support."""
    return _decode_tcp(frame)


class TcpDecoder:
    """Capture-scoped decoder. No raw capture bytes survive outside IP buffers.

    ingest returns one packet/disposition per frame. `fragment_pending` and
    `fragment_duplicate` are not loss; finish surfaces incomplete datagrams.
    Diagnostics are cumulative counts, including asynchronous timeout losses.
    """
    def __init__(self, fragment_limits=None):
        from .ip_reassembly import FragmentReassembler
        self.fragments = FragmentReassembler(fragment_limits)

    @property
    def diagnostics(self):
        return dict(self.fragments.diagnostics)

    def ingest(self, frame: RawFrame) -> tuple[TcpPacket | None, str | None]:
        self.fragments.advance(frame.timestamp)
        return _decode_tcp(frame, self.fragments)

    def finish(self) -> dict[str, int]:
        return self.fragments.finish()


def endpoint_key(pkt: TcpPacket) -> tuple[tuple[str,int],tuple[str,int]]:
    return tuple(sorted(((pkt.src,pkt.sport),(pkt.dst,pkt.dport))))  # type: ignore[return-value]


def sequence_offset(seq: int, base: int) -> int:
    """Signed TCP serial distance; callers must keep a window below 2**31."""
    return ((seq - base + (1 << 31)) & 0xffffffff) - (1 << 31)


@dataclass(frozen=True)
class StreamSourceRange:
    """A safe stream slice and the one actual captured slice chosen for it."""
    stream_start: int
    stream_end: int
    tcp_seq_start: int
    tcp_seq_end: int
    source: PacketSourceRange


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
    source_ranges: tuple[StreamSourceRange, ...] = ()


def reassemble_detailed(segments: list[TcpPacket]) -> ReassemblyResult:
    """Reassemble ONE direction of ONE session within a 16 MiB window.

    Equal-sequence ties retain capture order; overlaps must match exactly. Gaps
    stop assembly. Missing SYN/FIN are unknown coverage, not inferred loss.
    """
    notes: list[str] = []
    mappings: list[StreamSourceRange] = []
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
        # Only safe-prefix provenance is published. Legacy `data` may include
        # ambiguous bytes, but they must never obtain definitive source claims.
        safe_mappings = []
        for mapping in mappings:
            end = min(mapping.stream_end, len(usable))
            if mapping.stream_start < end:
                source_end = mapping.source.payload_start + end - mapping.stream_start
                source = clip_packet_source(mapping.source, mapping.source.payload_start, source_end)
                safe_mappings.append(replace(mapping, stream_end=end,
                    tcp_seq_end=(base + end) & 0xffffffff, source=source))
        return ReassemblyResult(data, usable, unsafe, tuple(dict.fromkeys(labels)), base,
                                tuple(safe_mappings))

    if any(p.fragment_evidence is not None and not p.fragment_evidence.trusted for p in segments):
        return result(unsafe=True, reason='fragment_identity_reuse')
    directions = {(p.src, p.sport, p.dst, p.dport) for p in segments}
    if len(directions) > 1:
        return result(unsafe=True, reason='mixed_directions')
    data_segs = [((p.seq + bool(p.flags & 2)) & 0xffffffff, p)
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
    offsets = [(sequence_offset(seq, anchor), packet) for seq, packet in data_segs]
    base_offset = 0 if syn_starts else min(at for at, _ in offsets)
    base = (anchor + base_offset) & 0xffffffff
    out = bytearray()
    for at, packet in sorted(offsets, key=lambda item: item[0]):
        payload = packet.payload
        start = at - base_offset
        if start < 0 or start > len(out):
            return result(bytes(out), True, 'sequence_gap')
        overlap = min(len(payload), len(out) - start)
        if overlap and out[start:start + overlap] != payload[:overlap]:
            return result(bytes(out), True, 'conflicting_overlap', bytes(out[:start]))
        if overlap:
            label = 'retransmission' if overlap == len(payload) else 'consistent_overlap'
            if label not in notes:
                notes.append(label)
        extension = payload[overlap:]
        if len(out) + len(extension) > 16 * 1024 * 1024:
            return result(bytes(out), True, 'direction_limit')
        for source in packet.source_ranges:
            source_start, source_end = max(overlap, source.payload_start), min(len(payload), source.payload_end)
            if source_start < source_end:
                stream_start, stream_end = start + source_start, start + source_end
                mappings.append(StreamSourceRange(stream_start, stream_end,
                    (base + stream_start) & 0xffffffff, (base + stream_end) & 0xffffffff,
                    clip_packet_source(source, source_start, source_end)))
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
