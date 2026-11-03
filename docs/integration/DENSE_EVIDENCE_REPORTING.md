# Dense evidence reporting — experimental review branch (Issue #56)

This targets the confirmed original 220.194 MiB high-density fictional PCAP failure: Stress reached its 2,048 MiB decoded JSON/evidence limit.
This does not claim M3 success.

## Design

- Standard, Large and Stress budgets and ordinary JSON download formats remain unchanged.
- Dashboard scans stream their final report from the existing private SQLite row index instead of making a second plaintext spool of millions of rows. The CLI retains the original ReportSpool.
- Dense evidence is opt-in: Stress's 512 MiB capture, 2M packets, 480 MiB TCP, 4M findings and 4 GiB process memory limits, plus an increased 6 GiB decoded JSON budget.
- Dense completed reports use lossless deterministic .json.gz. Compression is a disk format, not a relaxation of the decoded-size guard. All evidence keys, original packet ranges, field IDs, access controls and value policies remain.
- The SQLite database is still limited to 2 times the decoded JSON cap plus 64 MiB. Disk reservation is based on capture + 3 times decoded report size + 64 MiB. Dense needs approximately 18.6 GiB of free disk and a 22 GiB private-job quota before scan start. Available disk is checked on the host; insufficient free space rejects before processing.
- Failures still clean up and do not publish incomplete findings.

## Run in an isolated worktree

Do not replace the running showcase checkout. After reviewing this PR,
install in a separate worktree and run:

    python -m packet_pii.dashboard --port 8766 --job-disk-mib 22528 \
        --retain-capture-for-inspection \
        --ml-checkpoint src/packet_pii/ml/artifacts/bilstm_v2 \
        --assessment-probes 0

Choose Dense evidence, Patterns + AI and 5 million eligible fields for the original dense capture, whose independent offline estimate is 2.71 million eligible fields. Verify the input SHA-256:
24a4764627c184e36f5b6c64f8fe6abebb0b46841609fef57607b17141cba072.

## SHA-bound M3 measurement (only after small-fixture CI)

Run once against the **existing original file**, from the isolated PR worktree:

    python scripts/validation/bench_performance_memory.py \
      --source-root . \
      --capture "$HOME/Downloads/TRACE_Fictional_Network_Day_220MiB.pcap" \
      --expected-sha256 24a4764627c184e36f5b6c64f8fe6abebb0b46841609fef57607b17141cba072 \
      --output "$HOME/Downloads/trace-dense-m3-receipt.json" \
      --profile dense --indexed \
      --checkpoint src/packet_pii/ml/artifacts/bilstm_v2 \
      --ml-profile capacity_5m --threads 2 --repeat 1

If the specified file is absent or its SHA differs, the runner rejects rather
than silently generating a tiny surrogate. It emits measured per-stage
times, model-only and total evaluated fields/sec, current/lifetime-peak RSS,
private index size and compressed report bytes. It hashes the completed gzip
with bounded reads; it does **not** JSON-load multiple GiB into Mac RAM.
The report is not retained by this benchmark: use the authenticated dashboard
run separately to test the full report download and deep Inspector navigation.

## Required before merge

1. Actual complete original 220MiB PCAP on MacBook Air M3 16GiB with trustworthy current/peak RSS, disk use, compressed and decoded report sizes, and stage/total timings.
2. Verify, rather than assume, the independent estimate of 495,797 packets, 4,309,651 extracted fields and 2,710,146 ML-eligible fields; examine every truly eligible field.
3. Exact original field IDs, finding IDs and source ranges with independent packet evidence verification, including deep Inspector pagination and optional authorized source reveal.
4. Full authenticated gzip download must decompress to valid complete JSON, with identical forensic content to a sufficiently-budgeted reference output.
5. All Standard/Stress existing compatibility, browser, mentor, ML and resource-limit tests remain green.
6. Repeated real 110MiB/220MiB M3 cold/warm benchmarks. No 31,250 fields/second or 500MiB performance claim is established here.

A passing small-fixture CI test is NOT proof the original 4.31M-field
capture is fixed or that large-scale inference is fast.
