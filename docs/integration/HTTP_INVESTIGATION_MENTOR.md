# HTTP investigation handoff — 23 October 2026

**25 October continuation:** see [executed demo and current acceptance](MENTOR_DEMO_COMPLETION.md).
TShark now ran; an inert static representation and source-lease fix were added.
The historical results and blockers below describe the original PR33 delivery.

Base: `a74dfcb8819758dfecb7a73a5d4b47272bb5b88e`. Branch:
`feature/trace-http-reconstruction-evidence-mentor`. No merge authorized.

## Acceptance matrix

| Requirement | Starting state | Delivered / outstanding |
|---|---|---|
| HTTP request/response reconstruction | Existing HTTP/1 FIFO association, interim responses, limited cleartext HTTP/2 | Reused parser; indexed conversation/message navigation added. Backend verified; genuine browser acceptance pending |
| Client/server, session and time | Present on findings, incomplete on message evidence | Added observed HTTP roles, endpoints, session, ordinal, timestamp and pairing basis to every HTTP evidence row |
| Packet → stream → field → finding | Existing metadata and bounded Inspector | Indexed clipped source joins; packet selection; whole-field vs transformed/unknown distinction. Independent fixture byte oracle passes |
| Side-by-side investigation | Finding details below table; manual metadata navigation | Universal inspector (see `docs/ux/DESIGN_RATIONALE.md`): pane, drawer or sheet beside the list, field/packet selection and stale-request protection. Browser journeys in `tests/test_experience_journeys.py` |
| Recoverable HTML | No body viewer; original upload deleted | Optional retained-capture, authenticated response-source reveal. Escaped text only; no preview, script execution, external resources or browser-page reconstruction |
| Identity/demographic rules | Already integrated | Reused unchanged; regression checks included |
| Wireshark demonstration | Existing synthetic fixtures, no focused walkthrough | Deterministic 11-frame fixture, generator oracle, independent dpkt/h11 verification and Wireshark steps. Wireshark/TShark execution pending |
| Explanation package | Existing general documentation | Illustrated seven-slide outline and presenter script in `HTTP_MENTOR_PRESENTATION.md` |
| Authorised HTTPS | TLS unreadable | Research boundary and local-only acceptance plan in `HTTPS_FOUNDATIONS.md`; no decryption implementation or adapter claim |

Implemented does not mean browser-demonstrated. Node behavior tests are not a
replacement for a real browser. No completion percentage is inferred from tests.

## Run the demonstration

From the repository root, using Python 3.10+ and an installed checkout:

```sh
python -m pip install -e .
mkdir -p demo-output
python examples/generate_mentor_demo.py demo-output/mentor-demo.pcap
python -m packet_pii.cli demo-output/mentor-demo.pcap -o demo-output/report.json
python -m packet_pii.dashboard --port 8765 --retain-capture-for-inspection
```

Open `http://127.0.0.1:8765`. Choose the generated capture. Rules are sufficient;
a V2 checkpoint is not required for the demonstration. Ordinary use can omit
`--retain-capture-for-inspection`; metadata navigation still works and uploads
are deleted as before, but source reveal is unavailable.

Expected fixture: **11 packets, one TCP session/flow, five HTTP messages, two
transactions and nine rule findings**. Five messages means two requests, one
interim `100` response and two final `200` responses. Counts of packets,
messages, fields and findings describe different objects, not accuracy.

Capture SHA-256:
`fa0070187d39425fc03bf15ba1700cfe1c57a20e724af03a4338c10676ed9d83`.
The adjacent `.oracle.json` records generator expectations, physical payload
offsets and stream hashes; it is not a frozen model-evaluation manifest.

## API / evidence contract

All new endpoints require the same `X-Dashboard-Token`, Host and Origin checks
as the existing job API. IDs resolve only in the selected job's private index.
TRACE remains a single local session, not a new multi-tenant permission system.

| Endpoint | Output / bounds |
|---|---|
| `GET /api/jobs/{id}/conversations?offset=0&limit=25` | Indexed transactions with actual associated messages; limit ≤100; at most100 messages/transaction, explicitly flagged partial |
| `GET /api/jobs/{id}/investigation?message_id=...&field_id=...` | Message, transaction, endpoints, field/finding pages, stream, clipped source references and packet metadata; field must belong to message |
| `field_offset`, `finding_offset`, `limit` | Separate bounded field/finding pagination; no whole report download |
| `POST /api/jobs/{id}/content` | JSON `{message_id, acknowledge_sensitive_content:true}`; retention must be enabled; response text only after full capture SHA verification |

Source intervals are half-open `[start,end)`. A field exact stream range can be
joined to several packet/file intervals. It supports the **whole field**, not
necessarily the detector's substring. Rule findings can identify candidate
fields without a unique decoded span. For escaped JSON, gzip, chunking or H2
dependencies, supporting raw ranges do not become exact decoded-text offsets.
No nearest-packet/timestamp fallback is used. Gap/cap/unknown coverage is explicit.
Timestamp sorting and HTTP/1 FIFO pairing are best-effort; HTTP roles identify
client/server where messages justify them, not merely by assuming port80.

Metadata lookup reports recorded source ranges verified during analysis, not
a fresh read of the original capture. Content recovery rehashes the entire
retained capture on the same descriptor, reads only proven source intervals,
and rejects mutation or inconsistent framing before returning text. Neither is
a cryptographic certification of capture authenticity or real-person identity.

The content path accepts one contiguous supported HTTP/1 response of at most
64 KiB captured message, declared textual media, and complete source coverage
within256 references. Existing bounded gzip/deflate and chunked decoding is
reused. Decoded text is limited to64 KiB with explicit partial status. Text
decoding can replace invalid characters. HEAD/CONNECT/request-context-dependent
framing, incomplete close-delimited bodies, unsupported encoding/binary bodies,
HTTP/2 source viewing and larger messages can be refused. H2 metadata remains
navigable. TLS and HTTP/3 content remain unavailable.

## Security and privacy changes

Default reports remain masked; new header metadata exposes only fixed allowed
header names, with values withheld. Request targets remain redacted. Content
does not enter the report or index. The server flag opts into private capture
retention (existing0700 directories/0600 files and job disk reservations);
per-reveal acknowledgement is additionally required. Raw captures expire via
timer even while idle (default3600s), and are removed on failure, cancellation,
pruning or shutdown. If expiry cannot be scheduled, the capture is deleted.

The browser inserts source exclusively with `textContent` into a `<pre>`, never
an iframe, link, executable markup or HTML preview. It clears revealed source
on hide, selection/job change or leaving the investigation tab; stale responses
cannot restore it. CSP and no-store headers remain. Opt-in source can contain
credentials: the local authorised viewer can read it, and hiding cannot erase
copies/screenshots or guarantee browser-memory erasure. No raw source export
button or telemetry is added.

## Independent verification and remaining gates

Executed with dpkt1.9.8 and h11 0.16.0: independent Ethernet/IP/TCP reading,
sequence reconstruction with consistent overlap checks, exact handshake
sequence/ACK values, two requests, three responses including interim, chunked
gzip and Unicode decoding. TRACE's selected email field resolves directly to
original file bytes from **frames5 then4** (stream order differs from capture
order). Results are in `results/http_mentor_verification.json`.

```sh
python -m pip install dpkt==1.9.8 h11==0.16.0
python scripts/validation/verify_mentor_demo.py demo-output/mentor-demo.pcap --report demo-output/report.json
```

TShark/Wireshark was unavailable here. No Wireshark execution is claimed. Run on
the review machine and compare actual output with the generator oracle:

```sh
tshark -r demo-output/mentor-demo.pcap -Y 'tcp.stream == 0' -T fields -e frame.number -e tcp.seq_raw -e tcp.ack_raw -e tcp.flags -e tcp.len
tshark -r demo-output/mentor-demo.pcap -Y http -T fields -e frame.number -e http.request.method -e http.response.code
tshark -r demo-output/mentor-demo.pcap -q -z follow,tcp,raw,0
```

Reference: [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html).
Dissector versions/reassembly preferences can change which completion frame
shows an HTTP message. Do not confuse that frame with every supporting packet.

Real browser gate (local Playwright+Chromium required):

```sh
node scripts/validation/browser_mentor_demo.cjs http://127.0.0.1:8765 demo-output/mentor-demo.pcap
```

This uploads the fictional fixture, navigates finding→field→packet→response,
checks inert HTML/no external requests, keyboard selection and small-screen
overflow. **Not executed successfully here:** Chromium was absent and its
download was invalid; the available cloud browser refused the local address.
Dynamic Node DOM-double tests executed the actual frontend module and verified
selection order, job isolation, hide/reveal races and text-only insertion.

Genuine checkpoint-dependent model tests remain blocked by absent V2 weights.
No model, threshold, training data or independent ground-truth manifest changed.
No large workload or performance claim is introduced. The original program's
capture/report/ML limits still apply; this is not the1GiB performance workstream.

## Integration with PR #32

Inspected performance head: `79995e65a4006fd680a2a00d43fc4126dda7a068`.
Only `engine.py` overlaps its production files: one import and one additive
`message_evidence.update(message_metadata(...))` call. Preserve PR32's streaming,
guards and batching; transplant these two lines at HTTP evidence publication.
No change here to capture, reassembly, http_evidence, reporting or ML internals.
New job indexes have storage/CPU cost not yet benchmarked on large captures;
review this with PR32's resource tests before deployment. Re-run the targeted
investigation, job lifecycle and HTTP evidence tests on the actual combined
commit. Textual compatibility alone is not acceptance.

## NISHANT REVIEW — FIVE-MINUTE DEMONSTRATION

1. **0:00–0:45 — Wireshark:** Open `mentor-demo.pcap`, apply `tcp.stream == 0`.
   Select frames1,2,3. Explain SYN(seq1000), SYN/ACK(seq9000,ack1001),
   ACK(seq1001,ack9001); SYN consumes one sequence number. Wireshark may display
   relative values0/1 unless raw sequence display is selected.
2. **0:45–1:30 — Exchange:** Follow → TCP Stream. Locate POST/profile and its
   `100 Continue`, then final `200` HTML response; locate GET/status and the
   second200. Explain that several packets make one HTTP message. Frame4 arrives
   before5 and6 repeats5; retransmission is not a third request.
3. **1:30–2:30 — TRACE:** Upload the same capture. Open **Findings** and select
   the Email row `a***@example.invalid`. The inspector opens beside the list
   (a drawer on narrower windows). Click **Open this request** and explain the
   Request/Response switcher and the client → server endpoints; **Back**
   returns to the finding without losing the list position.
4. **2:30–3:30 — Verify:** In the request, select the email field, then the
   frame5 and frame4 rows under *Packets for field*. Compare displayed file/frame ranges with Wireshark's packet bytes
   and the oracle. The email is split; exact whole-field support is not an
   exact rule-substring claim. Compare the capture SHA recorded by TRACE.
5. **3:30–4:20 — HTML:** Switch to the final 200 response, acknowledge
   sensitive content under *Original response* and click **Show response source**.
   Show the HTML as literal text. Its script and remote image must not execute
   or load. Hide source. Say: “This recovers a captured response body, not the
   original interactive webpage.”
6. **4:20–5:00 — Limits:** In **Traffic → Conversations**, choose the second conversation and gzip/chunked
   response field. Explain transformed supporting ranges, missing data and
   encryption. Rules found nine candidates in this fictional fixture; that is
   neither real-capture accuracy nor proof of a leak. Identify pending genuine
   browser/TShark acceptance and keep V2 scores separate from verified accuracy.
