# Dashboard integration handoff

This branch supplies backend APIs only. No dashboard/static or ML files are
changed. Do not infer browser-upload readiness from the CLI benchmarks.

## Backend contract

```python
from packet_pii.engine import AnalysisLimits, analyze_to_report

limits = AnalysisLimits.for_profile("large")
receipt = analyze_to_report(
    uploaded_capture_path, private_report_path,
    profile="large", limits=limits, progress=on_progress,
)
```

Use a fresh worker process per scan, initially one active worker. The core is
synchronous and its RSS guard measures process-lifetime high water. Execute it
outside the request handler; bound queued jobs, upload bytes and temporary disk
space. ML is not invoked by this API. Future hybrid integration needs separate
measurement, status and model-availability handling by its owner.

`analyze()` remains the compatible API returning full finding/flow lists. Do not
use it for large dashboard jobs. `analyze_to_report()` returns metadata, summary,
limitations, output_path and output_bytes, with arrays retained in the complete
JSON file. Do not read that whole file back into the web worker just to display
results. Provide a bounded/paged preview and a protected full-file download.
A paging index/service is frontend/backend integration work, not supplied here.

Metadata keeps `analysis_limits`' original four fields, adds `analysis_profile`,
`limits_overridden`, and `resource_budgets`. Summary adds `endpoint_pairs`;
`flows_processed` now counts separated TCP sessions. Existing report schema
version remains 1.0.0; existing finding fields and masked defaults are preserved.
File whitespace is compact in the streamed path.

## Input and progress

Expose Standard/Large/Stress as explicit choices, with effective limits displayed
before starting. Never silently retry in a larger profile after a budget failure.
Reject invalid overrides server-side via `AnalysisLimits.for_profile()`. The
upload cap must match the selected capture limit; account separately for HTTP
multipart envelope bytes. Stream upload to a private local file rather than
buffering an entire multipart body in memory. Keep existing path validation,
authentication and security restrictions in the integration layer.

Callbacks receive dictionaries with `stage` and aggregate counters only:

- `reading`: packets and endpoint_pairs, sampled every 4096 records.
- `reconstructing`: initial totals after EOF.
- `analysing`: sessions, http_messages and findings, every 128 sessions.
- `writing_report`: final summary before publication.
- `complete`: final summary after successful atomic publication.

Elapsed seconds are available in the streamed API. Do not invent a percentage
from record counts: total work is unknown during reading and varies by payload.
Callbacks are synchronous; keep them cheap. Raising before publication cancels
the job and cleans temporary files. `complete` is a non-cancellable notification;
a regular exception from that callback sets `progress_notification_failed` in
the successful receipt. Reconcile durable job state with the published output.

## Failure and privacy

AnalysisLimitError (a ValueError) means the scan did not produce a complete new
report. Other ValueError/TypeError indicate invalid configuration/input; OSError
includes unavailable disk/output paths. Show a clean failed-job state, not zero
findings or a truncated successful report. A successful report may separately
have `summary.analysis_incomplete=true` for observed capture/TCP damage; show
that warning next to findings. False does not prove unseen traffic was captured.

Reports and spool files use mode 0600. Directory permissions remain the host's
responsibility. Spools are created alongside output and closed on success,
exception or cancellation. Final output is atomically published, refuses an
existing path by default, and replaces it only with explicit overwrite. A failed
scan preserves a previous report. Avoid raw values in logs/progress/analytics.
Masked reports still contain network addresses, timestamps and partial values;
treat them as sensitive investigation material. No telemetry/upload is added.

Reserve roughly input size plus **twice the report byte budget**, plus any old
report retained during overwrite, for temporary disk usage. OS disk-full errors
fail cleanly; the budget does not reserve disk space. RSS checks are sampled,
not a hard OS memory guarantee. Apply worker resource/isolation limits suitable
for the deployment; do not claim the Mac target has been measured until the
commands in LARGE_CAPTURES.md have run there.
