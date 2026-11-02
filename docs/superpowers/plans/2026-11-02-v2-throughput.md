# Frozen V2 forward throughput plan

> For agentic workers: use superpowers:executing-plans; execute inline, with one final independent review.

Goal: reduce full-coverage TRACE scan latency without changing frozen assets, decisions, provenance or resource guards.

Architecture: preserve PR46's bulk collation/decoder on current main; measure native forward components, then remove redundant batch-local work only when genuine comparisons justify it. No capacity, frontend or packet reconstruction edits.

Tech stack: Python, CPU PyTorch; actual M3/MPS validation is unavailable in this Linux runtime.

Spec: user’s 2026-11-02 Extreme Performance Mission and issue #45. First gate 478.6838 s; second 300 s on the identical owner's 110 MiB capture.

## Global constraints
- Main inspected: 50c3a1251995d7063f3b49a9354c71d4ff429504; PR46: 0bd72c93b6e3c3a171584e6bcb1445fbf3f65d01.
- Capacity PR52 and Inspector test PR51 already merged. Preserve their files.
- V2 bilstm-v2-d1f9e9fb9a2b, threshold .35; same tokenizer, weights, ensemble and coverage.
- No whole-dataset tensors, persistent feature cache, new workers or raised resource ceilings.
- Experimental numerical differences require measured reporting; changed threshold decisions disqualify default adoption.
- Native M3 acceptance and 150/500 MiB targets remain blocked, never inferred from Linux file size.

## Tasks and ledger
- [x] Restore current main plus PR46 on isolated branch; checksum genuine weights; profile restored baseline and compare frozen fields.
- [x] Profile CNN/LSTM, tokenization, encoding, padding and indexed pipeline on bounded synthetic inputs.
- [x] Test then implement worthwhile batch-local reuse in ml/bilstm.py; training untouched. Reject unhelpful experiments with recorded data.
- [x] Compare all frozen fields and complete indexed report identities; measure repeated isolated CPU timing/RSS.
- [x] Provide repeatable M3 acceptance workflow; run core, genuine ML, actual Chromium, mentor and Hybrid gates; draft PR, no merge.

Review focus: unknown/case/Unicode char rows, all-empty and unique batches, training gradients, per-occurrence span offsets, failed calls and cache isolation. Each retained implementation requires direct tests plus frozen reference comparison.

Ruling: execute under the supplied specification without another design approval, as explicitly requested. One Astra architecture review completed; recommended char-row dedup and conservative equal-length dense-LSTM experiments. Neither is a performance result.

Results: frozen comparison exact (4,314 fields / 4,175 spans); incremental model-only19.9%, repeated2MiB3.6%, single8MiB combined-versus-main9.3%. These do not meet the M3 performance mission. Native M3, 110/150/500MiB and15M-field acceptance remain blocked by hardware availability. Failed per-member sorting, dense regrouping, INT8 and compile experiments are documented. Final read-only Astra code review: no material findings; hardware and performance claims explicitly outside its verification.
