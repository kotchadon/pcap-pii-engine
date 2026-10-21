# Network evidence audit and implementation scope

Baseline inspected: `11d41e8c583231edd86b621d96cc037fe676108f` on main.
Dedicated branch: `feature/trace-network-evidence-v2`. PR #23 is frozen and untouched.
The handoff dated 2026-10-19 is the task specification. Existing cross-message ML
batching, field/disposition evaluation hooks, job budgets/cancellation, report
streaming and UI were treated as compatibility constraints.

| Surface | Baseline gap | Implemented change |
|---|---|---|
| PCAP/PCAPNG | Record/source metadata discarded | Packet ordinals, file/captured/wire offsets, resolution and interface/section metadata; actual-read identity and mutation rejection |
| TCP decoding | ACK and byte-source references lost; skipped packets decoded twice | Single stateful decode; transport metadata and compact source intervals retained |
| IP | Fragmented traffic and common IPv6 extensions rejected | Bounded conservative IPv4/IPv6 reconstruction and extension traversal, deferred invalidation, explicit unsupported/limit states |
| TCP stream | Safe prefix and diagnostics existed, but lacked captured-byte joins | Deterministic source intervals for the safe prefix; sequence-wrap, overlap and retransmission evidence; lifecycle observations remain uncertain |
| HTTP/1 | No request-method framing context or field sources | HEAD/CONNECT/1xx handling, timestamp-guarded method context, body boundaries and conservative transformation mappings |
| HTTP/2 | Preface detected but no decoding | Optional maintained HPACK dependency, bounded prior-knowledge plaintext subset, per-stream pairing and explicit partial/unsupported states |
| Reports/jobs | No complete source joins or evidence paging | Additive private evidence arrays and authenticated bounded ID/stream queries; combined report budget |
| Evaluation | Pre-analysis hash could differ from analyzed bytes | Acceptance additionally bound to the verified actual-read hash |
| Encryption | Not inspected | TLS/QUIC feasibility only, no implementation claim |

Independent review identified and corrected: response method inheritance by an
earlier orphan; evaluation prehash race; HTTP/2 trailers silently uninspected;
interim-only HTTP/2 transactions incorrectly appearing complete. Packet tests
also exposed late fragment identity conflicts, cross-VLAN identity collisions,
and fragment next-header changes. The fixes fail conservatively rather than
inventing a trustworthy stream.

## Compatibility changes that require explicit review

The report schema changes additively from 1.0.0 to 1.1.0. New evidence carries its
own 1.0.0 schema. Generic row observers now receive the four additional evidence
kinds; consumers must filter kinds. The existing evaluator already does this.
HEAD/CONNECT responses are now framed using supported request association;
known GET responses missing their declared bodies are correctly incomplete.
Tests which asserted lack of request context were updated to assert these
protocol distinctions. Tests mocking the old decoder were moved to the stateful
decoder seam. A fake file-stat test was replaced with a real sparse capture so
same-read integrity checks remain exercised rather than bypassed.

No frontend, classifier weights, detector thresholds, model score semantics,
training data, frozen manifest or evaluation result is changed. The controlled
synthetic fixture was regenerated locally from its committed generator because
the baseline checkout did not contain the binary; its SHA-256 matches the frozen
manifest (`16591312ec3884b5e94daeeeed153bc636031e07ac84d4a93562382135cccdea`).
No replacement model or fabricated model measurements are used.

## Standards and limits

Primary sources: [HTTP/1 framing, RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3),
[IPv6 overlap discard, RFC 5722](https://www.rfc-editor.org/rfc/rfc5722.html),
[IPv6 fragmentation, RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5),
[HTTP/2, RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html),
[HPACK, RFC 7541](https://www.rfc-editor.org/rfc/rfc7541.html),
[HPACK API](https://python-hyper.org/projects/hpack/en/latest/api.html), and
[Linux checksum offload documentation](https://docs.kernel.org/networking/checksum-offloads.html).
These inform a deliberately bounded passive subset, not a full conformance claim.
See NETWORK_EVIDENCE_CONTRACT.md for exact limitations and
NETWORK_ENCRYPTION_FEASIBILITY.md for encryption design gates.
