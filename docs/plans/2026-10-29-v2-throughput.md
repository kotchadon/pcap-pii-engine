# Frozen V2 throughput — execution plan

Base: `c17abe7f176116629d726a982f49df1f30b052bc` (tree `3c1045cb6e767ede5373ea90cf2a336bbe8b0c31`).
Branch: `perf/astra-v2-inference-throughput`. Owner's October 29 mission supersedes the October 21 audit.

1. Profile genuine V2 on bounded fictional inputs. Record uninstrumented timing separately from cProfile and torch.profiler; verify checkpoint identity. Resolve binary access through private Actions artifacts if possible.
2. Choose one measured hotspot. Add reference-equivalence/resource regression tests, observe the missing improvement, implement, and retain only with measured benefit. Preserve frozen assets, decoding, thresholds, budgets, provenance and privacy.
3. Extend the isolated benchmark for Stress, verified capture SHA and bounded configurable timeout. Run targeted and full CI validation, genuine indexed comparisons, then one final review. Publish a draft PR with evidence and an exact-M3 acceptance command; never merge.

No M3 hardware is available in this environment. Linux results cannot satisfy the M3 performance gate. The 110 MiB owner capture SHA is `42e52f7ebb470d45e3d883ba6c800a11fce17357cf0edad417fefb8ca059c9ce`.

## Ledger

- Exact source tree restored and verified; 17 binary blobs initially unavailable through text-only connector endpoints.
- Existing bucketing, tensor caps, cache, eval/inference mode and character CNN improvements are baseline features.
- User already authorizes isolated implementation, CI and draft PR; no redundant plan or branch approval requested.
- Production changes pending genuine profile. No M3 speedup, accuracy or checkpoint-dependent test result claimed.
- Genuine weights restored through a supported private Actions artifact and verified against every original Git blob SHA; binary-access blocker resolved.
- Selected and implemented only bulk collation and immutable grouped BIO predecessor selection. TDD failures observed; exact reference tensors/RNG/decoding and genuine scores verified.
- Frozen 4,314-field comparison: zero score/label/span/threshold drift. Indexed complete 2/8 MiB reports have equal full event digests; measured reductions 3.61%/8.64% respectively. No M3 target claim.
- Full local suite: 1,104 passed, 16 browser availability skips. Final safety-guard targeted suite: 24 passed. Exact-head remote CI is the final suite evidence.
- One read-only Astra review complete; explicit configured-threshold equality added. Preflight/report capture identity and digest-failure cleanup tests added and fixed.
- Report, raw bounded measurements and exact-M3 acceptance command: `docs/performance/2026-10-29-v2/README.md`. M3/MPS/110 MiB/1 GiB hardware gates remain unexecuted.
