"""Bounded observational IP reassembly; no host-policy or completeness claims.

IPv6 overlaps discard the whole pending assembly (RFC 5722 / RFC 8200 §4.5).
Exact IPv4 duplicates are ignored; every other overlap is rejected. Completed
and rejected identities are quarantined for the capture window: ambiguous ID
reuse is not associated with a second datagram. This intentionally sacrifices
coverage when IDs are reused quickly. Expired identities can be used again.
"""
from __future__ import annotations

from collections import Counter, OrderedDict
from dataclasses import dataclass, field
import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .capture import PacketSourceRange


@dataclass(frozen=True)
class FragmentLimits:
    max_datagrams: int = 1024  # Includes completed/rejected identity tombstones.
    max_buffered_bytes: int = 8 * 1024 * 1024
    max_fragments: int = 128
    max_datagram_bytes: int = 65535
    lifetime_seconds: float = 60.0
    max_capture_frames: int = 10000

    def __post_init__(self):
        for name in ('max_datagrams', 'max_buffered_bytes', 'max_fragments',
                     'max_datagram_bytes', 'max_capture_frames'):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f'{name} must be a positive integer')
        if (not isinstance(self.lifetime_seconds, (float, int)) or
                isinstance(self.lifetime_seconds, bool) or
                not math.isfinite(self.lifetime_seconds) or self.lifetime_seconds <= 0):
            raise ValueError('lifetime_seconds must be finite and positive')
        if self.max_datagram_bytes > 65535:
            raise ValueError('max_datagram_bytes exceeds non-jumbo IP limit')


@dataclass
class FragmentEvidence:
    """Deferred trust: a later same-identity fragment invalidates emitted bytes.

    Consumers inspect this only after ingestion finishes; no raw bytes or
    network identifiers are retained in this shared status object.
    """
    trusted: bool = True
    reason: str | None = None


@dataclass
class _Assembly:
    clock: float
    ordinal: int
    context: bytes
    pieces: list[tuple[int, bytes, PacketSourceRange | None]] = field(default_factory=list)
    final: int | None = None
    buffered: int = 0
    dead: bool = False
    evidence: FragmentEvidence | None = None


class FragmentReassembler:
    def __init__(self, limits: FragmentLimits | None = None):
        self.limits = limits or FragmentLimits()
        self.entries: OrderedDict[tuple, _Assembly] = OrderedDict()
        self.diagnostics: Counter[str] = Counter()
        self.buffered_bytes = 0
        self.clock = float('-inf')
        self.ordinal = 0
        self.last_evidence: FragmentEvidence | None = None

    def advance(self, timestamp: float) -> None:
        """Monotonic timestamp watermark plus frame window handles clock reversal."""
        self.ordinal += 1
        if math.isfinite(timestamp):
            self.clock = max(self.clock, timestamp)
        # Insertion times are monotonic, so checking the oldest is sufficient.
        while self.entries:
            key, assembly = next(iter(self.entries.items()))
            if (self.clock - assembly.clock < self.limits.lifetime_seconds and
                    self.ordinal - assembly.ordinal < self.limits.max_capture_frames):
                break
            self.entries.pop(key)
            self.buffered_bytes -= assembly.buffered
            if not assembly.dead:
                self.diagnostics['fragment_timeout'] += 1

    def _reject(self, assembly: _Assembly, reason: str):
        self.buffered_bytes -= assembly.buffered
        assembly.pieces.clear()
        assembly.buffered = 0
        assembly.dead = True
        self.diagnostics[reason] += 1
        return None, (), reason

    def accept(self, key: tuple, offset: int, more: bool, payload: bytes,
               source: PacketSourceRange | None, *, version: int,
               context: bytes = b'', max_length: int = 65535):
        """Return (complete fragmentable bytes, source ranges, disposition).

        `advance` must be called once per capture frame, including nonfragments.
        Each source range is in fragmentable-payload coordinates on input/output.
        """
        self.last_evidence = None
        self.diagnostics['fragment_frames'] += 1
        self.diagnostics[f'ipv{version}_fragment_frames'] += 1
        assembly = self.entries.get(key)
        if assembly is None:
            if len(self.entries) >= self.limits.max_datagrams:
                self.diagnostics['fragment_limit'] += 1
                return None, (), 'fragment_limit'
            assembly = _Assembly(self.clock, self.ordinal, context)
            self.entries[key] = assembly
        elif assembly.dead:
            if assembly.evidence is not None:
                assembly.evidence.trusted = False
                assembly.evidence.reason = 'fragment_identity_reuse'
            self.diagnostics['fragment_identity_reuse'] += 1
            return None, (), 'fragment_identity_reuse'
        end = offset + len(payload)
        if (context != assembly.context or not payload or offset < 0 or
                end > min(self.limits.max_datagram_bytes, max_length) or
                (more and len(payload) % 8)):
            return self._reject(assembly, 'fragment_malformed')
        if assembly.final is not None and (end > assembly.final or (more and end >= assembly.final)):
            return self._reject(assembly, 'fragment_overlap')
        for start, data, _source in assembly.pieces:
            if offset < start + len(data) and start < end:
                # IPv6 deliberately uses the strict RFC 5722 overlap policy,
                # including exact duplicates; no endpoint equivalence assumed.
                if version == 4 and start == offset and data == payload and (more or assembly.final == end):
                    self.diagnostics['fragment_duplicate'] += 1
                    return None, (), 'fragment_duplicate'
                return self._reject(assembly, 'fragment_overlap')
        if not more:
            if assembly.final not in (None, end) or any(start + len(data) > end for start, data, _ in assembly.pieces):
                return self._reject(assembly, 'fragment_overlap')
            assembly.final = end
        if (len(assembly.pieces) >= self.limits.max_fragments or
                self.buffered_bytes + len(payload) > self.limits.max_buffered_bytes):
            return self._reject(assembly, 'fragment_limit')
        assembly.pieces.append((offset, payload, source))
        assembly.buffered += len(payload)
        self.buffered_bytes += len(payload)
        if assembly.final is None or assembly.buffered != assembly.final:
            return None, (), 'fragment_pending'
        ordered = sorted(assembly.pieces, key=lambda item: item[0])
        at = 0
        for start, data, _source in ordered:
            if start != at:
                return None, (), 'fragment_pending'
            at += len(data)
        data = b''.join(piece for _start, piece, _source in ordered)
        sources = tuple(source for _start, _piece, source in ordered if source is not None)
        self.buffered_bytes -= assembly.buffered
        assembly.pieces.clear()
        assembly.buffered = 0
        assembly.dead = True
        assembly.evidence = self.last_evidence = FragmentEvidence()
        self.diagnostics['fragment_reassembled'] += 1
        return data, sources, None

    def finish(self) -> dict[str, int]:
        """Close pending assemblies, returning cumulative diagnostics (idempotent)."""
        for assembly in self.entries.values():
            if not assembly.dead:
                self.diagnostics['fragment_incomplete'] += 1
        self.entries.clear()
        self.buffered_bytes = 0
        return dict(self.diagnostics)
