# V2 inference acceleration benchmark (synthetic and frozen fictional inputs)

- Machine: Linux-6.18.44-fc-v139-x86_64-with-glibc2.39 (x86_64), 4 CPUs, Python 3.13.16, torch 2.14.1, 4 threads; convolution path: default
- Baseline: `origin/main` a74dfcb88197; candidate 1d861fc58e73

## Full scan: 52.0 MiB synthetic capture (sha256 a93092b1d8606ae4, seed 52), profile large

| Run | Status | Wall s | Model s | Peak RSS MiB | Evaluated | Model-inferred | Cache hits | Findings identical | Wall x | Model x |
|---|---|---|---|---|---|---|---|---|---|---|
| baseline | completed | 677.31 | 535.41 | 928.1 | 570424 | 117184 | 453240 | - | - | - |

