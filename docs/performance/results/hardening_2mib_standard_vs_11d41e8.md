# V2 inference acceleration benchmark (synthetic and frozen fictional inputs)

- Machine: Linux-6.18.44-fc-v139-x86_64-with-glibc2.39 (x86_64), 4 CPUs, Python 3.13.16, torch 2.14.1, 4 threads; convolution path: default
- Baseline: `11d41e8` 11d41e8c5832; candidate 1d861fc58e73

## Full scan: 2.0 MiB synthetic capture (sha256 1b3b62a55ca9c90a, seed 52), profile standard

| Run | Status | Wall s | Model s | Peak RSS MiB | Evaluated | Model-inferred | Cache hits | Findings identical | Wall x | Model x |
|---|---|---|---|---|---|---|---|---|---|---|
| baseline | completed | 45.42 | 43.04 | 689.2 | 22088 | None | None | - | - | - |
| cache=0 | completed | 24.29 | 17.74 | 647.9 | 22088 | 22088 | 0 | True | 1.87 | 2.43 |
| cache=16384 | completed | 16.05 | 9.3 | 654.3 | 22088 | 5717 | 16371 | True | 2.83 | 4.63 |

## Regression gate: PASS

Criteria: `{"rss_ratio": 1.1, "rss_slack_mib": 32.0, "wall_ratio": 1.05, "max_confidence_delta": 1e-05}`

- cache=0: pass
- cache=16384: pass
