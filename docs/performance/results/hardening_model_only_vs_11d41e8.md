# V2 inference acceleration benchmark (synthetic and frozen fictional inputs)

- Machine: Linux-6.18.44-fc-v139-x86_64-with-glibc2.39 (x86_64), 4 CPUs, Python 3.13.16, torch 2.14.1, 4 threads; convolution path: default
- Baseline: `11d41e8` 11d41e8c5832; candidate 1d861fc58e73

## Model only: frozen_v2_val_and_challenge (4058 inputs)

| Config | Seconds | Speed-up | Peak RSS MiB | Span diffs | Inclusion diffs | Max abs score delta |
|---|---|---|---|---|---|---|
| baseline batch 64 | 6.657 | 1.00 | 615.5 | - | - | - |
| batch_64 | 3.23 | 2.06 | 626.1 | 0 | 0 | 1.8e-07 |
| batch_128 | 3.209 | 2.07 | 658.3 | 0 | 0 | 1.8e-07 |
| batch_256 | 3.724 | 1.79 | 629.4 | 0 | 0 | 1.8e-07 |
| batch_512 | 3.583 | 1.86 | 615.8 | 0 | 0 | 1.5e-07 |

## Model only: synthetic_http_fields (6000 inputs)

| Config | Seconds | Speed-up | Peak RSS MiB | Span diffs | Inclusion diffs | Max abs score delta |
|---|---|---|---|---|---|---|
| baseline batch 64 | 40.97 | 1.00 | 733.7 | - | - | - |
| batch_64 | 17.329 | 2.36 | 657.9 | 0 | 0 | 3.5e-07 |
| batch_128 | 16.581 | 2.47 | 661.7 | 0 | 0 | 3.5e-07 |
| batch_256 | 17.573 | 2.33 | 661.8 | 0 | 0 | 3.5e-07 |
| batch_512 | 15.961 | 2.57 | 667.1 | 0 | 0 | 3.5e-07 |

