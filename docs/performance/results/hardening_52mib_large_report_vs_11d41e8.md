# V2 inference acceleration benchmark (synthetic and frozen fictional inputs)

- Machine: Linux-6.18.44-fc-v139-x86_64-with-glibc2.39 (x86_64), 4 CPUs, Python 3.13.16, torch 2.14.1, 4 threads; convolution path: default
- Baseline: `11d41e8` 11d41e8c5832; candidate 1d861fc58e73

## Full scan: 52.0 MiB synthetic capture (sha256 a93092b1d8606ae4, seed 52), profile large

| Run | Status | Wall s | Model s | Peak RSS MiB | Evaluated | Model-inferred | Cache hits | Findings identical | Wall x | Model x |
|---|---|---|---|---|---|---|---|---|---|---|
| baseline | completed | 1149.03 | 1093.82 | 792.9 | 570424 | None | None | - | - | - |
| cache=16384 | completed | 378.62 | 247.0 | 806.8 | 570424 | 117187 | 453237 | True | 3.03 | 4.43 |

## Regression gate: PASS

Criteria: `{"rss_ratio": 1.1, "rss_slack_mib": 32.0, "wall_ratio": 1.05, "max_confidence_delta": 1e-05}`

- cache=16384: pass
