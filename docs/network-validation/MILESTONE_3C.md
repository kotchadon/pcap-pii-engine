# Milestone 3C: network fidelity and bounded stress validation

Date: 2026-10-14 UTC. Base: `4d311d1af64717cdbdbb63bda50dae838ccdd34a`.
Branch: `feature/network-fidelity-m3c`. This is a scoped correctness patch,
not a production-readiness certification. Main was not merged or rewritten.

## Delivered behavior

`capture.py` now uses modulo-2^32 sequence offsets, counts SYN-carried data
correctly, detects FIN-evidenced trailing gaps, and rejects packets shorter than
their declared IP length. Snaplen truncation is reported in capture diagnostics;
PCAPNG interface snaplen and padded packet lengths are checked.

New additive APIs:

- `sequence_offset(seq, base) -> int`: signed serial distance, valid within a
  window smaller than 2^31; reassembly retains the existing 16 MiB direction cap.
- `reassemble_detailed(packets) -> ReassemblyResult`: accepts ONE direction of
  ONE session. `data` preserves the legacy overlap policy; `safe_prefix` excludes
  a conflicting segment's whole overlap region and bytes beyond any observed FIN.
  `unsafe` flags demonstrated ambiguity, gaps, resets, invalid boundaries or limits.
  `diagnostics` also distinguishes unknown initial/final coverage. `base_seq`
  maps byte offset zero to TCP sequence space.
- `split_tcp_sessions(packets) -> list[list[TcpPacket]]`: accepts ONE endpoint
  pair in capture order. Changed SYN ISNs separate epochs; retransmitted SYNs
  stay together. RST or both directional FINs close an epoch. Data after closure
  starts another observed epoch. Half-close allows opposite-direction data.

Legacy `reassemble()` still returns `(data, unsafe)`. It refuses mixed directions
and distinct observed SYN ISNs, but keeps its existing conflicting-overlap bytes
for compatibility. **Engine adoption of `safe_prefix` is required before claiming
ambiguous bytes cannot reach detectors.** A false unsafe flag is not proof of a
complete capture or receiver acceptance. Missing handshake/termination cannot
be treated as zero packet loss.

`http_extract.py` now rejects empty Transfer-Encoding, malformed chunk extension
syntax, control characters and framing fields in trailers, and stops after 101.
The empty-TE rejection is a conservative support policy; TE/CL combinations are
rejected even where a tolerant implementation might recover. Unknown valid chunk
extensions are ignored after grammar validation. Existing header/body/resource
limits remain unchanged. No third-party source was copied into production code.

## Evidence matrix

Expected bytes are hand specified in tests or defined as application bytes before
segmentation by a generator that imports no project decoder/reassembler. Existing
correct behavior is retained; tests are not deleted or weakened.

| Scenario | Before / observed risk | Corrected or retained expectation | Evidence |
|---|---|---|---|
| Out-of-order payload | Existing test passed | Ordered bytes, no duplication | `test_reassembly.py`; RFC 9293 §3.4 |
| Exact retransmission | Existing test passed | One copy | Existing + wrapped-overlap regression |
| Equal partial overlap | Existing test passed | Contiguous extension only | Existing overlap test |
| Conflicting overlap | Legacy prefix included ambiguity | Detailed safe prefix stops before conflict; diagnostic | New fidelity test; Zeek inconsistency event |
| Missing middle | Existing prefix stop | Never join across hole | Existing gap tests |
| Missing initial after SYN | Existing empty prefix | Gap, no invented leading bytes | Existing initial-gap test |
| Missing final before FIN | Returned safe=False incorrectly | FIN mismatch marks unsafe | Reproduced failing test, RFC 9293 §3.4 |
| Capture starts mid-session | No distinction from full coverage | `initial_coverage_unknown` | New detailed-result test |
| RST | No lifecycle diagnostic | Reset unsafe; next data is separate epoch | New lifecycle test |
| FIN half-close / duplicate SYN | No session API | Keep opposite response; avoid false split | New session test |
| Reused tuple / changed ISN | One four-tuple bucket | Separate session lists; legacy rejects mixed epochs | New test; Wireshark port-reuse guidance |
| Sequence wrap | Empty/gapped output | Exact ABCDEF across zero | Reproduced test + overlap test |
| Data on SYN | Payload before inferred base | SYN consumes one serial number | Reproduced test, RFC 9293 §3.4 |
| Concurrent interleaved flows | Existing two-flow test passed | Independent byte hashes/counts | Generator + existing engine test |
| Truncated IPv4/IPv6 | Accepted short payload | Reject incomplete IP packet | Two reproduced failures |
| PCAP snaplen loss | No capture diagnostic | Truncated record counted; next record survives | Adversarial test |
| PCAPNG snaplen / record anomaly | IDB snaplen ignored | Bad record skipped; next record decoded | Adversarial + existing robustness tests |
| Persistent segmented HTTP | Existing parser supported | Exact boundaries and bodies | 1,728 h11 boundary comparisons |
| CL/TE conflicts / empty TE | Empty TE could expose next request | Stop ambiguous stream | Reproduced + existing HTTP tests; RFC 9112 §6.3 |
| Chunk extensions / trailers | Syntax discarded or underchecked | Validate grammar, reject ambiguity | Nine HTTP failures reproduced; RFC 9112 §7.1 |
| HTTP upgrade | Continued parsing tunnel-looking bytes | Emit 101 then stop | Reproduced upgrade test |
| Partial HTTP body | Existing rejection | No complete message | New + existing tests |
| Gzip/JSON, forms, query, deflate | Existing support | Preserve decoded fields; bounded expansion | New gzip test, existing HTTP tests, generator |
| Combined FIN/gap/conflict | Early return bypassed FIN cap in initial patch | Cap safe prefix on every exit, earliest FIN | Independent review + two regressions |
| Invalid unrelated packet | Existing engine behavior passed | Preserve other valid conversation | Existing malformed-packet test |

New tests: `test_network_fidelity_3c.py`, `test_network_adversarial_3c.py`,
`test_capture_stress_3c.py` (35 collected cases, including parameterized variants).
These counts are not an accuracy metric.

## Independent verification and limits

`compare_reassembly.py --independent --manifest ...` uses dpkt 1.9.8 to check
packet decoding and IP/TCP checksums, and h11 0.16.0 to independently consume
HTTP events and determine boundaries/bodies from the remaining stream. It checks
160 direction digests against pre-segmentation application bytes. Manifest checks
also reject omission of complete flows. Empty or damaged captures fail validation.

Actual small-capture result: 80 flows, 1,707 independent packet/checksum checks,
1,728 independent HTTP boundaries, all passed. See `results/reference-small.json`.
These references do **not** independently reproduce TCP receiver state or overlap
selection. TCP adversity expectations are specification-based tests; no TShark
Follow TCP Stream comparison was obtained. TShark was unavailable and apt failed
on prohibited setgroups/setuid operations. Scapy 2.6.1 installation succeeded,
but import attempted an unavailable netlink socket; it was not used as evidence.
No security controls were bypassed. dpkt's HTTP parser was not used as the HTTP
oracle because its published chunk parsing has narrower extension handling.

References (reviewed for specific decisions, not copied):

- [RFC 9293 §3.4](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.4):
  serial arithmetic, SYN/FIN sequence occupancy and segment ordering.
- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3) and
  [§7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1): framing precedence,
  incomplete messages, chunk extensions and trailers.
- [Wireshark TCP Analysis](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html):
  distinct SYN ISN for port reuse, prior missing segments and overlap heuristics.
- [Zeek TCP events](https://docs.zeek.org/en/current/scripts/base/bif/plugins/Zeek_TCP.events.bif.zeek.html):
  explicit content gaps and retransmission inconsistencies. Zeek was not executed.
- [dpkt HTTP source](https://dpkt.readthedocs.io/en/latest/_modules/dpkt/http.html):
  parser behavior and scope; dpkt is used only as a development reference.
- [h11 event API](https://h11.readthedocs.io/en/stable/basic-usage.html): independent
  EndOfMessage and trailing-data boundaries.

## Actual measurements

Linux, Python 3.12.14, one process, single measured pass per size; no warmup/CI
performance claim. RSS is process lifetime peak from `resource.getrusage`, with
Linux/macOS unit handling. These are not MacBook Air measurements. Generation is
excluded from timing. Reading, decoding and grouping are combined; reassembly,
HTTP parsing and field extraction have separate timers in JSON.

| Actual MiB | Packets | Sessions | HTTP messages | Wall s | Peak RSS MiB | MiB/s |
|---:|---:|---:|---:|---:|---:|---:|
| 1.120 | 1,707 | 80 | 1,728 | 0.050 | 16.50 | 22.46 |
| 10.113 | 15,333 | 720 | 15,552 | 0.610 | 30.75 | 16.57 |
| 100.184 | 151,474 | 7,120 | 153,792 | 5.425 | 172.50 | 18.47 |

All packet/flow/message counts and unique payload-byte totals matched manifests;
zero capture/reassembly diagnostics and no configured-limit failures. The 100 MiB
run used explicit 250,000-packet and 128 MiB TCP-payload budgets; production defaults
were not changed. The generator writes through one bounded batch of 16 flows.
The benchmark intentionally buffers packets by flow, like the existing engine;
it is not an incremental constant-memory analyzer. Its limits bound that retention.

100 MiB timing breakdown: read/decode/group 1.328 s; reassembly 0.595 s; HTTP parse
1.889 s; field extraction 1.546 s. Loop/timer overhead explains the remainder.
**Rules, ML, transaction pairing and report/UI construction are not timed.** Small
and medium runs preceded the final FIN-cap review correction; generated valid
traffic has no FIN mismatch. The 100 MiB run includes that correction.

200/300 MiB runs were not attempted: the required 100 MiB checkpoint completed,
and larger trials are deferred to the target machine. The generator accepts both
sizes; commands below are reproducible, not claimed measurements. Files end at a
complete 16-flow batch and can exceed the target by about one batch.

## Reproduction

From a complete checkout, install the project's normal dependencies. Optional
reference packages go in a separate environment; no production manifest changes:

```sh
python -m pip install dpkt==1.9.8 h11==0.16.0
python -m pytest tests/test_network_fidelity_3c.py tests/test_network_adversarial_3c.py tests/test_capture_stress_3c.py -q
python scripts/validation/generate_captures.py /tmp/m3c-small.pcap --size-mib 1 > /tmp/m3c-small.json
python scripts/validation/compare_reassembly.py /tmp/m3c-small.pcap --independent --manifest /tmp/m3c-small.json
python scripts/validation/generate_captures.py /tmp/m3c-100.pcap --size-mib 100 > /tmp/m3c-100.json
python scripts/validation/benchmark_capture.py /tmp/m3c-100.pcap --max-packets 250000 --max-tcp-mib 128
python scripts/validation/generate_captures.py /tmp/m3c-200.pcap --size-mib 200 > /tmp/m3c-200.json
python scripts/validation/benchmark_capture.py /tmp/m3c-200.pcap --max-capture-mib 210 --max-packets 400000 --max-flows 20000 --max-tcp-mib 220
python scripts/validation/generate_captures.py /tmp/m3c-300.pcap --size-mib 300 > /tmp/m3c-300.json
python scripts/validation/benchmark_capture.py /tmp/m3c-300.pcap --max-capture-mib 310 --max-packets 600000 --max-flows 30000 --max-tcp-mib 330
```

Use fresh output paths: the generator refuses overwrite. Seed defaults to 20261014.
Wire segmentation and flow content are deterministic for the recorded runtime;
gzip byte-for-byte hashes can differ between Python/zlib/platform versions.
The corpus contains synthetic identities under example.test, documentation IPs,
GET/POST, forms, JSON, chunked requests, gzip responses, 204s, retransmissions,
wraparound, reordered segments and non-HTTP negative traffic. It is structurally
varied synthetic load, not evidence of real-world traffic distribution or ML quality.
No real captures or large generated files are committed.

## Regression and delivery evidence

Baseline full suite: **169 passed, 3 failed** (12.90 s).
Intermediate network/HTTP regression: **107 passed** (0.31 s).
Final full suite: **204 passed, 3 failed** (13.47 s), including all 35 new cases.
`results/regression.log` preserves the actual failures. They are unchanged:

- `test_ml_bilstm.py::test_committed_checkpoint_loads_on_cpu_and_is_deterministic`
- `test_ml_metrics_report.py::test_evaluate_default_exports_no_raw_text`
- `test_ml_metrics_report.py::test_evaluate_include_text_is_explicit_opt_in`

Cause: the GitHub connector cannot materialize the binary model.pt; metadata and
all text files were fetched from the pinned base. The exact original model blob
entry remains in the Git tree, untouched and not staged as deletion. No model was
regenerated. A complete authenticated checkout must rerun the full suite before
integration; this environment does not establish an all-green baseline.

Local commits use Kocha Don and the email verified by the authenticated GitHub
profile. The remote feature branch was created at the base. Direct Git transport
has no credentials; the connector's create-commit API has no author override and
the GitHub profile name is advay. Consequently correctly named local commits
are packaged for review; publishing them/creating the PR is blocked on an
attribution-preserving transport or explicit approval for the connector's author.
No unrelated author history was rewritten.

## Remaining limits and required handoff

See `INTEGRATION.md` for exact engine changes. The existing engine still groups
by four-tuple, uses legacy conflict bytes and non-modular timestamp arithmetic.
New session/safe-prefix behavior is demonstrated at the module boundary and used
in the benchmark, not silently claimed to be integrated into reporting.

Passive inference cannot distinguish all reuse without SYN/close evidence or
assign arbitrarily delayed old packets after reuse. No ACK/window acceptance,
TCP checksum enforcement, IP fragment reassembly, IPv6 extension chain parsing,
TLS decryption, HTTP/2 or HTTP/3 support was added. HTTP HEAD response framing,
successful CONNECT tunnels and close-delimited response bodies require request
and connection context that the current parser API lacks. Unframed responses
still emit headers only, then stop; this is not full body reconstruction.
No confidence in malicious exfiltration follows from these network checks.
