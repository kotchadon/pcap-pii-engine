# Engine-owner handoff (proposal, not applied)

No `engine.py`, CLI, hybrid, dashboard, reporting, ML or dependency manifest was
changed. The following changes belong to the engine owner before Sunday readiness
can include the new evidence guarantees.

## 1. Session identity before directional grouping

At the outer loop over `flow_packets.items()` in `analyze`, enumerate
`split_tcp_sessions(packets)` before forming directions. Create a unique flow ID
per epoch (e.g. `flow_0001_session_0002`). Keep endpoint metadata, records, request
FIFO pairing and incomplete flags local to that epoch. Count sessions separately
from endpoint pairs through the reporting owner's chosen schema. Bound session
count as well as four-tuple count; repeated SYNs must not bypass the flow budget.

```python
for pair_index, (endpoints, packets) in enumerate(flow_packets.items(), 1):
    for session_index, session in enumerate(split_tcp_sessions(packets), 1):
        fid = f'flow_{pair_index:04d}_session_{session_index:04d}'
        # Existing direction grouping / _pair_requests runs inside this scope.
```

Test boundary: two HTTP conversations using the same tuple and different SYN
ISNs produce two IDs and two independent request/response FIFOs. The module test
`test_changed_syn_separates_reused_tuple_and_legacy_refuses_to_join` already
proves byte separation. Same-ISN retransmitted SYN stays in one epoch. Half-close
must retain the other direction's response. Mid-session data cannot prove whether
an unobserved tuple reuse occurred; report that uncertainty instead of asserting
complete lifecycle coverage.

## 2. Parse only the safe prefix and retain limitations

Replace the legacy tuple call in each direction with:

```python
assembled = reassemble_detailed(segs)
stream = assembled.safe_prefix
# Carry assembled.unsafe and assembled.diagnostics to flow/report diagnostics.
for span in parse_http_stream_with_spans(stream):
    ...
```

Do not interpret `not assembled.unsafe` as complete capture coverage. Preserve
`initial_coverage_unknown`, `final_coverage_unknown`, `reset_observed`,
`sequence_gap`, `conflicting_overlap`, `fin_boundary_mismatch`,
`multiple_handshakes`, `mixed_directions`, and `direction_limit` distinctly where
practical. Do not count all uncertainty as a proven lost packet.

Conflict acceptance test: captured `username=alice` overlapping `bobXX` must not
expose the ambiguous suffix to detectors. Prefix before a gap may contain valid
complete earlier messages; do not discard unrelated sessions. FIN limits apply
also when a later gap or conflict caused early assembly termination.

## 3. Wrap-aware provenance

Replace `_timestamp_for_byte`'s numeric-min base and raw interval comparisons.
Pass `assembled.base_seq`; do not independently infer another base:

```python
def timestamp_for_offset(segs, assembled, offset):
    if assembled.base_seq is None or not 0 <= offset < len(assembled.safe_prefix):
        raise ValueError('offset outside usable payload')
    times = []
    for p in segs:
        start = sequence_offset((p.seq + bool(p.flags & 2)) & 0xffffffff,
                                assembled.base_seq)
        if p.payload and start <= offset < start + len(p.payload):
            times.append(p.timestamp)
    if not times:
        raise ValueError('no captured segment proves this byte')
    return min(times)  # Existing earliest-observation policy, including duplicates.
```

Provenance tests: payload at 0xfffffffd followed by payload at 0 maps byte offset
3 to the second segment's capture time; SYN payload begins at SYN sequence + 1.
Do not fall back to the handshake timestamp when no packet proves the byte.

## 4. Request-context HTTP limitations

HEAD response Content-Length describes a representation, not bytes to consume.
Successful CONNECT establishes a tunnel after response headers; 101 now stops
unconditionally, but CONNECT needs the matching request method. A future
context-aware parser adapter must pair request methods in per-session FIFO order,
retain a request across informational responses, terminate successful CONNECT,
and avoid implying close-delimited response completeness without a valid observed
end. Until supplied, label these modes unsupported; do not offer full HTTP fidelity.

## Existing limits / validation

The CLI already exposes `--max-capture-mib`, `--max-packets`, `--max-flows` and
`--max-tcp-mib`; `AnalysisLimits` carries them. Keep defaults unchanged. A 100 MiB
synthetic run exceeds both the default packet and buffered-TCP limits; use explicit
per-run overrides. The network-only benchmark is **not** a benchmark of integrated
rules/ML/reporting performance. After adopting the interface, rerun the existing
transaction/reporting tests and the full suite with the real checkpoint present.
