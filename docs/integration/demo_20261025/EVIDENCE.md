# Actual original-byte evidence — fictional email

All ranges are half-open. Rows are in reconstructed stream order. Whole-field support; not an exact detector substring.

Capture SHA-256: `fa0070187d39425fc03bf15ba1700cfe1c57a20e724af03a4338c10676ed9d83`

Client `192.0.2.10:50123` → server `198.51.100.20:80`; session 1; `flow_0001_direction_0`; `flow_0001_msg_0001`; `flow_0001_msg_0001_field_7`; EMAIL.

| Frame | TCP sequence | Stream bytes | Capture-file bytes | Frame bytes | Actual hex | Actual fictional text |
|---|---|---|---|---|---|---|
| 5 | [1249, 1256) | [248, 255) | [713, 720) | [302, 309) | `616c6578406578` | `alex@ex` |
| 4 | [1256, 1269) | [255, 268) | [304, 317) | [54, 67) | `616d706c652e696e76616c6964` | `ample.invalid` |
