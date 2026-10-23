# Authorised HTTPS foundations — research boundary

This deliverable is **research and an acceptance plan only**. No TLS decryption
adapter, live HTTPS experiment, TLS1.3/QUIC reconstruction or key ingestion was
implemented in this branch. The HTTP evidence and investigator workflow take
priority. Browser acceptance remains blocked in the execution environment, and
TShark is unavailable for the required independent decryption cross-check.

| Stage | Next controlled experiment | Evidence needed before claiming success |
|---|---|---|
| A: encryption boundary | Run a test HTTPS server and client owned by the developer, using fictional request data, capture only that local test connection | Record encrypted PCAP hash; show endpoints, transport and available handshake metadata; verify HTTP values are not exposed by ordinary inspection |
| B: reference decryption | Explicitly export secrets from that controlled client and supply them to maintained Wireshark/TShark | Record tool/version, capture hash and key provenance identifier (never secret bytes), then independently recover the known fictional request/response |
| C: optional adapter | Only afterB passes, import authenticated decrypted application records in a separate PR | Declare linked/unlinked capture identity, transformation/tool identity, completeness and exact application-data spans; never invent ciphertext offsets |

For a Python test client, an explicitly configured `SSLContext.keylog_filename`
can export supported session secrets; use a private file in the isolated test
directory and a trusted test certificate. Keep certificate verification enabled.
Do not point TRACE at arbitrary existing key files, scrape credentials, upload
key logs or commit generated private keys. Compatibility depends on the client
TLS implementation; setting a generic environment variable is not proof that
the client exported usable secrets.

After recording an authorised test connection and verifying the key log locally,
the maintained reference-tool command is:

```sh
tshark -r authorised-test.pcapng -o tls.keylog_file:private-test.keys -Y http
```

That command has **not** been executed here. Decrypted text is a transformed
application record, not bytes that appeared verbatim in ciphertext packets.
Any future adapter must preserve that distinction, avoid key material in API
responses/logs/reports, and use its own bounded tests and reviewable PR.

Primary references consulted23October2026:

- [Wireshark TLS decryption documentation](https://wiki.wireshark.org/TLS/)
- [Wireshark TShark command reference](https://www.wireshark.org/docs/man-pages/tshark.html)
- [IETF RFC9850: TLS key log format](https://www.rfc-editor.org/rfc/rfc9850.html)

These references establish a supported mechanism, not a claim that this TRACE
branch can decrypt HTTPS or that a packet capture alone contains the secrets.
