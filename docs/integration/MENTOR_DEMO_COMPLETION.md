# Nishant assignment — executed demonstration, 25 October 2026

This continues PR33, without redesigning Claude's frontend. The complete
fictional PCAP, real reports, original HTML source, inert static representation,
packet evidence table and executed verification are in [demo_20261025](demo_20261025/).
Execution was Linux x86_64; **not an M3 measurement**. Genuine browser acceptance
remains blocked here; the API journey and TShark verification actually ran.

## Start on the MacBook

Check out the latest `feature/trace-http-reconstruction-evidence-mentor` branch.
From its repository root, run this one entry point:

```sh
bash scripts/validation/run_mentor_demo.sh --output demo-output
```

Requires Python 3.10+ and network only for first-time installation of two small
reference libraries, dpkt1.9.8 and h11 0.16.0, into `.venv-mentor`. It does not
install PyTorch, download models or contact captured URLs. It generates three
fictional captures, starts an ephemeral localhost TRACE server, uses real
authenticated upload/report/investigation/source endpoints, verifies the bytes,
and shuts the server down. The input is below64KiB with Standard scan limits.
TRACE's Standard disk reservation still requires approximately2.2GiB free disk;
the actual demo outputs are about200KiB. Failure of a required assertion exits
nonzero and removes staging output. An existing output directory is refused;
use `--output demo-output-2` for a new run. Optional missing TShark is labelled
blocked, not passed. Do not run with Python `-O`.

Then start the interactive dashboard:

```sh
PYTHONPATH=src .venv-mentor/bin/python -m packet_pii.dashboard --port 8765 --retain-capture-for-inspection
```

Open `http://127.0.0.1:8765`, upload `demo-output/mentor-demo.pcap`, select the
masked request EMAIL finding and **Inspect**. Choose frames5 and4, then the
first final200 response. Acknowledge sensitive content before revealing source;
hide it afterwards. Open `demo-output/captured-page.static.html` separately for
the offline representation. Claude can integrate the same capability into his
Inspector using the contract below; this branch does not redesign that UI.

## Actual artifacts and acceptance

| File under `demo_20261025/` | What it proves / contains |
|---|---|
| `mentor-demo.pcap`, `mentor-demo.oracle.json` | Deterministic fictional network bytes and generator expectations |
| `trace-report.json` | Real masked rules-only TRACE output:11packets,1flow,5HTTP messages,2transactions,9rule findings |
| `trace-investigation.json`, `EVIDENCE.md` | Actual selected finding→field→message→stream→original-frame/file joins |
| `captured-response.html.txt` | Actual recovered322-byte HTML body, saved as text so opening it does not execute its attack probes |
| `recovered-content.json` | Authenticated recovery result and inert projection metadata |
| `captured-page.static.html` | Viewable, lossy captured structure/text; no scripts, styles, images, links or remote requests |
| `missing-response-packet.pcap`, `incomplete-report.json` | Original frame9 removed: one stream gap, incomplete body, no complete200 response invented |
| `missing-handshake.pcap`, `midstream-report.json` | Handshake removed: no SYN inferred, connection completeness remains unknown |
| `verification.json`, `tshark-packets.tsv` | Executed independent dpkt/h11 and TShark comparisons |
| `artifact-sha256.json` | Hashes of generated artifacts, excluding this hash list itself |

Packet counts are not accuracy scores. The fixture
contains no FIN, so even its successfully recovered messages do not prove a
complete TCP connection was captured. HTTP/1 pairing is directional FIFO,
best-effort; interim100 is attached to the first request.

All offsets below are half-open. Capture SHA-256:
`fa0070187d39425fc03bf15ba1700cfe1c57a20e724af03a4338c10676ed9d83`.
Client `192.0.2.10:50123` → server `198.51.100.20:80`; session1;
`flow_0001_direction_0` → `flow_0001_msg_0001` → `flow_0001_msg_0001_field_7` → EMAIL.

| Frame in stream order | TCP sequence | Stream offsets | Original file bytes | Bytes inside frame | Actual fictional bytes |
|---|---|---|---|---|---|
| 5 | [1249,1256) | [248,255) | [713,720) | [302,309) | `alex@ex` |
| 4 | [1256,1269) | [255,268) | [304,317) | [54,67) | `ample.invalid` |

The reference verifier reads packets using dpkt, independently assembles TCP
positions, and parses HTTP using h11. It checks physical file/frame bytes,
direction, TCP sequence origin, stream offsets and recovered HTML body SHA.
It rejects plausible shifted coordinates and wrong directions. This is exact
**whole-field support**, not an invented detector-substring offset. For the
second response, gzip/chunking/JSON escaping require transformations; original
compressed source ranges do not become Unicode character positions.

## Wireshark/TShark — executed and repeatable

TShark4.2.2 actually verified raw SYN/SYN-ACK/ACK values, POST/GET,100/200/200,
frame6 retransmission, frame5 out-of-order arrival, and the selected original
payload slices. **Enable TCP out-of-order reassembly**: without it this fixture's
request methods were not shown by TShark's default preferences. In Wireshark,
Preferences→Protocols→TCP→Reassemble out-of-order segments. Apply
`tcp.stream == 0`, then Follow→TCP Stream. Dissector completion frames are not
all supporting frames. Use the packet-byte view to compare the intervals above.

On macOS with Wireshark installed:

```sh
export PATH="/Applications/Wireshark.app/Contents/MacOS:$PATH"
tshark -n -r demo-output/mentor-demo.pcap -o tcp.reassemble_out_of_order:TRUE -T fields -e frame.number -e tcp.seq_raw -e tcp.ack_raw -e tcp.flags -e http.request.method -e http.response.code -e tcp.analysis.retransmission -e tcp.analysis.out_of_order
tshark -n -r demo-output/mentor-demo.pcap -Y 'frame.number == 5 || frame.number == 4' -x
```

## Real-browser gate and V2 gate

No genuine browser journey passed here. Playwright's bundled browser download
was invalid; an official Google Chrome156 binary was then obtained, but launch
terminated with SIGSEGV in this execution environment. No screenshots or visual
acceptance are claimed. Browser JS syntax and Node behavior checks passed.

With the dashboard running, macOS can use an existing Chrome installation:

```sh
npm install --no-save --package-lock=false playwright@1.62.1
TRACE_BROWSER_EXECUTABLE="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" node scripts/validation/browser_mentor_demo.cjs http://127.0.0.1:8765 demo-output/mentor-demo.pcap demo-output/captured-page.static.html
```

The script must exit0 and print `status:passed`. It checks upload→finding→packet→
reveal→hide, no active captured HTML or remote fetches, keyboard operation,
small-screen overflow and the optional standalone static page. It targets PR33's
existing UI; Claude's redesigned DOM will need its own acceptance adapter.

V2 weights are tracked in GitHub but unavailable as local binary files: the
connector returned empty base64 content and its blob reader rejected binary
UTF-8 decoding. Rules-only verification is complete;
genuine model integration is **not tested**. On an environment with the existing
unchanged V2 ensemble and PyTorch, use the bounded command below. Do not install
or retrain a replacement model and do not change thresholds:

```sh
python3 -c "from pathlib import Path; p=Path('src/packet_pii/ml/artifacts/bilstm_v2'); assert all((p/('seed'+str(n))/'model.pt').is_file() for n in (11,12,13)), 'Genuine V2 weights missing'"
PYTHONPATH=src python3 -m packet_pii.cli demo-output/mentor-demo.pcap --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2 --ml-max-total-fields 100 --ml-max-total-characters 65536 --ml-batch-fields 8 --max-capture-mib 1 --max-report-mib 8 -o demo-output/v2-report.json
python3 -c "import json; s=json.load(open('demo-output/v2-report.json'))['summary']; assert s['ml_inference_invoked'] and s['ml_fields_evaluated']>0 and not s['ml_inference_failed']; print({k:s[k] for k in ('ml_fields_evaluated','ml_fields_skipped','ml_coverage_status')})"
```

This is an integration gate, not an accuracy evaluation or proof of full ML
coverage. Inspect skipped-field accounting. The frozen ground-truth evaluator
and V2 artifacts are unchanged.

## Backend contract for Claude

Existing authenticated `POST /api/jobs/{job}/content` remains compatible:

```json
{"message_id":"flow_0001_msg_0003","acknowledge_sensitive_content":true,"representation":"static"}
```

`representation` defaults to `source`. `static` adds `static_representation` to
the existing result: a versioned `inert_structure_text_v1` tree, with text strings
and `{tag,children}` nodes. Only allowlisted tags exist; no captured attributes,
URLs, CSS or resources survive. Render with `createElement`/`createTextNode`,
never `innerHTML`; apply the same sensitive-content reveal/hide/reset policy.
Preserve source status, projection truncation and omitted-content notices.
Limits:64KiB UTF-8 source,4096nodes,64levels. This intentionally preserves
recoverable structure/text only, not layout or interactive page behavior.
Captured dependent resources were not recovered: the fixture has no captured
image/CSS responses; none were fetched or fabricated. A future resource mapper
would need exact job-local request/response association and safe decoder limits.

The source read now leases one opened no-follow descriptor under the jobs lock,
snapshots bounded indexed metadata, then hashes/reads/decodes outside that lock.
Short checkpoints and a final check revoke expiry/deletion/replacement/mutation;
cleanup never waits for full-file hashing. No raw copies are made. The full
capture is still hashed per reveal; this fixes lock contention, not total I/O.
Default deletion, masked reporting, authentication, job isolation and atomic
report publication are preserved. Static output is unmasked captured content
and must have the same authorization as source. Only fictional exports are
committed in this demonstration directory.

## Integration boundaries

Verified remote heads on25October: main `a74dfcb8819758dfecb7a73a5d4b47272bb5b88e`,
PR32 `79995e65a4006fd680a2a00d43fc4126dda7a068`, original PR33
`876814ada91ea66b6745b213f91d59c33a4c1e7c`, PR34
`794283e12d6ad3f37bdd48efac755af490765ec4`. All three PRs remained open.
Continue PR33; do not merge automatically. New production changes are confined
to source leasing, the projection module and the existing content endpoint.
No CSS/navigation/Inspector redesign, reconstruction parser replacement, ML
changes or performance benchmark. PR34 also edits dashboard.py: preserve its
static allowlist entries (`/inspector.js` and `/investigation.js`) while adding
the six representation lines. Existing PR33 frontend versus
PR34 design conflicts still need Claude's integration; do not blindly overwrite
either. PR32 combined resource validation remains separate.

## NISHANT REVIEW — SIX-MINUTE DEMONSTRATION

1. **0:00–0:40 — Original capture:** open the fictional PCAP. “These are actual
   encoded network packets generated for a controlled test; no private traffic.”
2. **0:40–1:30 — TCP:** select frames1/2/3. Client SYN seq1000, server SYN/ACK
   seq9000 ack1001, client ACK seq1001 ack9001. SYN consumes one sequence number.
   Show both directions. Relative Wireshark numbers may show0/1 instead.
3. **1:30–2:20 — Reconstruction:** Follow TCP Stream, find POST/profile,
   100Continue/200 and GET/status/200. Explain that frame4 arrived before5;
   frame6 repeats5. TRACE orders byte positions, not arrival order, and does not
   count retransmission as a new request.
4. **2:20–3:20 — Page:** reveal the captured HTML source through TRACE. Open the
   separate inert static artifact: heading and text survive, script/image do
   not. “This is a lossy representation of captured content, not the complete
   original webpage, and it made no request for missing resources.”
5. **3:20–3:50 — PII:** select masked EMAIL `a***@example.invalid`. Explain a
   rule candidate is not proof of a real-world leak or measured model accuracy.
6. **3:50–5:10 — Verify:** show frames5 then4 and the evidence table. `alex@ex`
   plus `ample.invalid` yields the field; compare exact file/frame bytes, TCP
   sequence and SHA. Explain why capture order and reconstructed order differ.
7. **5:10–6:00 — Limits:** open the missing-response report: gap, incomplete
   body, no fabricated200. Missing handshake stays unknown. Show transformed
   gzip field. TLS is encrypted, H2 source viewing and HTTP/3 unsupported; no
   promise to recover absent packets or scripts' dynamic DOM.

## Say it simply — English and Hinglish

**English:** A packet is one captured frame. A TCP flow/session groups the
communication; each direction has an ordered byte stream. One HTTP message may
span several packets, and one packet may contain multiple messages. TRACE
extracts fields from supported messages and flags candidates. The evidence
links those fields back to the actual captured bytes.

**Hinglish:** “PCAP packets ka record hai, webpage ka screenshot nahi. Pehle
client aur server handshake karte hain. Packets ulte order mein aaye ya repeat
hue toh sequence numbers se bytes sahi order mein jodte hain. Phir HTTP request
aur response milte hain. Email do packets mein split tha: frame5 ka pehla hissa
aur frame4 ka doosra hissa. Hum original bytes dikha sakte hain. HTML recover
hua hai, lekin JavaScript nahi chalate aur missing image internet se nahi laate.
Packet missing ho toh complete page bolna galat hoga.”

**Likely questions:**

- **Full webpage recovered?** No. Exact supported HTML response source plus a
  lossy offline structure/text representation; no scripts, styling or resources.
- **Why frames5 then4?** TCP sequence order differs from capture arrival order.
- **Where exactly is the email?** Two half-open intervals in EVIDENCE.md, checked
  against dpkt, TShark payloads and original file bytes. Whole-field support.
- **Why nine findings?** Nine rule candidates in this fixture; not accuracy/F1.
- **Port80 means HTTP?** It is a convention, not proof; bytes/protocol parsing
  determine support. HTTP may use other ports; port443 commonly carries TLS.
- **Is handshake seen proof the entire connection is captured?** No; this
  fixture has no FIN and TRACE retains unknown final completeness.
- **Can HTTPS be read?** Not by this workflow. No general decryptor was added.
- **Can you prove the dashboard works in a real browser?** Not yet in this
  environment. The real HTTP API journey and TShark passed; run the Mac browser
  gate before claiming the full live UI demonstration is accepted.

Ready-to-present slides: [MENTOR_DEMO_SLIDES.md](MENTOR_DEMO_SLIDES.md).
