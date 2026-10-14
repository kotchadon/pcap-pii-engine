# M3C plan and decision ledger

Base: verified signed upstream commit4d311d1af64717cdbdbb63bda50dae838ccdd34a, exact tree403720075b7c27eafe3902312a1dabda7b01de68. Main contains PR6 input robustness and PR5 ML V1. Branch feature/network-fidelity-m3c created remotely at that exact base. Git author Kocha Don; email taken from an upstream commit whose GitHub author is kotchadon, not guessed.

The connector reads source and can mutate GitHub, but cannot download the binary checkpoint. Local git HTTPS lacks credentials. A local shallow checkout preserves the exact upstream commit/tree and marks the unavailable binary skip-worktree; its tree entry remains untouched. Baseline:169 passed,3 checkpoint-dependent failures, no tests removed/skipped/weakened. Do not regenerate ML. Direct git push/auth and custom API commit author support remain delivery limitations to resolve after reviewable work exists.

1. Reproduce TCP SYN-data/wrap, truncated IP and FIN-evidenced trailing gaps; fix capture.py; focused tests and early local commit.
2. Add detailed reassembly diagnostics + explicit session splitter in capture.py. Legacy tuple API preserved. Engine/session grouping and wrap-aware timestamp plumbing require an integration proposal, not edits to engine.py.
3. Verify HTTP framing defects: empty TE, extension/trailer grammar, upgrade stop. Add focused tests. Context-dependent HEAD/CONNECT/close framing only through additive explicit context, if needed; document unsupported paths.
4. Streaming synthetic capture generator, independent hand-specified expected byte streams, optional reference comparison and bounded network-only benchmark. Start small, medium, then100MiB; do not change global limits. Larger sizes reproducible, not required here.
5. Full suite once at final checkpoint; source-scope audit; preserve baseline ML-artifact failures honestly. Commit/push/PR only with correct identity. No merge.

Policy: <2^31 serial-distance window,16MiB reassembled direction bound. Never invent gap bytes. Capture-order lifecycle signals partition sessions; passive traces without handshake cannot prove separation. Conflicts produce diagnostics and safe-prefix boundary. Legacy callers retain their existing return shape, so richer evidence requires engine adoption.
