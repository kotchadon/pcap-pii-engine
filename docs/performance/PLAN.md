# Large capture implementation checkpoint

Base main: 19af7a5668e4b20ebd6cff1dfc87234bb2a58615. Branch:
feature/m3-large-capture-performance. M3C and ML V2 are present. No dashboard
or hybrid implementation is present in this pinned tree; other sessions own them.

Exact user file: 115343298 bytes, SHA256
42e52f7ebb470d45e3d883ba6c800a11fce17357cf0edad417fefb8ca059c9ce.
Independent dpkt scan:361389 records,60232 endpoint pairs,90046044 payload bytes;
60231 POST starts and60231 response starts, plus segmented/negative traffic.
Baseline with explicit limits:60231 HTTP conversations,120462 messages,244046
findings;29.988s total,475.781MiB peak RSS,Linux. Report163104108bytes.
Baseline full tests:257passed,9failed(26.66s); failures require unavailable
checkpoint/train binary files. Preserve tree entries; never regenerate ML data.

Implementation:
1. Standard/Large/Stress profiles with capped validated overrides, packet/flow/
   payload limits unchanged for Standard; additional result and RSS budgets.
2. Compact retained packet tuples; release payload buffers after a full endpoint
   group is processed. No premature per-packet flow flushing. Reuse M3C session
   and safe-prefix APIs at the engine boundary, without protocol rewrites.
3. Add analyze_to_report: private bounded JSONL result spools and incremental
   final JSON encoding, same report schema, atomic output. Legacy analyze still
   returns lists. Progress events contain stages/counts, no captured text.
4. Focused tests; exact110MiB full engine benchmark and report integrity/masking
   verification; larger workloads only after measured safe completion.
5. Document M3 commands, frontend handoff and limitations; full suite once at
   final checkpoint; publish authored feature commits/PR without merging.

Author: local Kocha Don, authenticated-account email. The user's prior explicit
approval for connector author advay/kotchadon applies to publication.
