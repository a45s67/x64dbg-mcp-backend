# Plugin-sidecar IPC v1

The native plugin and Rust sidecar communicate through a current-user-only
Windows named pipe. This is an internal protocol; MCP clients use Streamable
HTTP instead.

## Framing

Each frame is a 32-bit little-endian payload length followed by one UTF-8 JSON
payload. The payload must be 1 through 1,048,576 bytes. Invalid, truncated,
oversized, trailing, or schema-invalid frames close the connection; there is no
resynchronization scan.

One request produces one response with the same `request_id`. Both peers apply
deadlines. A disconnected or timed-out mutation is recorded as unknown and is
not replayed automatically.

## Handshake

The plugin creates the pipe and launches the sidecar with a random nonce and a
single inherited stdin handle. The plugin keeps the corresponding write handle
for the child lifetime; EOF requests sidecar shutdown.

Plugin handshake:

```json
{
  "protocol_major": 1,
  "protocol_minor": 1,
  "backend": "x64dbg",
  "plugin_pid": 4242,
  "nonce": "at-least-32-unpredictable-characters"
}
```

Sidecar acknowledgement:

```json
{
  "protocol_major": 1,
  "protocol_minor": 1,
  "accepted": true,
  "error_code": null,
  "instance_id": "11111111-2222-4333-8444-555555555555"
}
```

Major versions must match; a peer accepts an equal or older minor version. The
sidecar compares the nonce in constant time and creates a new UUID v4
`instance_id` for each process. Authentication failure closes the pipe without
exposing detailed diagnostics.

## Request

```json
{
  "request_id": "83db0d7d-df01-40ac-bdfc-87bac1e60813",
  "deadline_unix_ms": 1788000000000,
  "operation_id": "7b9207c9-4e50-48d7-8fac-09cf37ccf864",
  "method": "memory.write",
  "payload": {"address":"0x140001000","data_hex":"90"}
}
```

`operation_id` is null for reads and required for mutations. The sidecar checks
and removes the public MCP `instance_id` before encoding IPC. Its operation
ledger has the same lifetime as the sidecar process.

`memory.dump` is a mutation. Its IPC payload contains the operation ID copied
from the request envelope plus the exact dump arguments:

```json
{
  "address": {"module":"sample.exe","rva":"0x1000"},
  "length": 65536,
  "path": "C:\\dumps\\sample-memory.bin",
  "overwrite": false,
  "operation_id": "7b9207c9-4e50-48d7-8fac-09cf37ccf864"
}
```

The native boundary requires 1 through 67,108,864 bytes and a drive-absolute
regular-file destination. `overwrite` is optional and defaults to false. The
plugin reads raw memory and publishes through a same-directory temporary file,
returning `path`, `bytes_written`, lowercase `sha256`, `complete`, `location`,
and `state_generation`. It must remove the temporary file on every failure and
must not expose or replace the destination before the complete contents and
SHA-256 are finalized.

`memory.read` presentation fields (`format` and `byte_order`) are sidecar-only;
the sidecar strips them before IPC and adds the requested lossless `view` to a
successful native result. The native response's `data_hex` remains unchanged.

Address fields accept an absolute hexadecimal string, an explicit absolute
object, or a module-relative object:

```json
{"address":{"absolute":"0x140001000"}}
```

```json
{"address":{"module":"sample.exe","rva":"0x1000"}}
```

The plugin resolves addresses only inside its serialized debugger executor.
Per-tool payload schemas and limits are defined by
`crates/server/src/tools.rs` and enforced again at the native boundary.

### Event payloads

`events.list` carries zero or more of `cursor`, `types`, and `limit`. The cursor
is an opaque string bound to the native event session and exact type filter; it
is not a sequence number. Its result is:

```json
{
  "session_id": "11111111-2222-4333-8444-555555555555:1",
  "items": [],
  "next_cursor": null,
  "latest_sequence": 0,
  "history_complete": true,
  "storage_error": null
}
```

`events.wait` carries optional `types` and `timeout_ms` only. Missing types mean
any supported event and missing timeout means 5,000 ms. The plugin snapshots
the current ring end while arming and may return only a matching event appended
after that point. It never searches retained history. A successful result has
`session_id`, `latest_sequence`, and `event`; timeout is `TIMEOUT`, and a change
of event session is `CANCELLED`. Event delivery says nothing about whether the
debuggee is currently paused.

An implementation may provision a secondary current-user-only named pipe by
appending `.events` to the primary pipe name. This extension is optional and
must not be assumed unless the native agent creates it. It uses the same
32-bit-little-endian length plus UTF-8 JSON framing and the same 1,048,576-byte
frame bound. The sidecar must authenticate it with the launch nonce before
accepting event frames; authentication failure closes only that connection.
Event objects use the same `session_id`, monotonically increasing `sequence`,
`timestamp_unix_ms`, `type`, and `state_generation` fields returned by the event
tools. The request/response pipe remains authoritative and available when this
optional channel is absent or disconnects.

## Response

Success:

```json
{
  "request_id": "83db0d7d-df01-40ac-bdfc-87bac1e60813",
  "state_generation": 8,
  "status": "ok",
  "result": {"bytes_written":1,"state_generation":8}
}
```

Failure:

```json
{
  "request_id": "83db0d7d-df01-40ac-bdfc-87bac1e60813",
  "state_generation": 8,
  "status": "error",
  "error": {
    "code": "BUSY",
    "message": "debugger changed during the operation",
    "retryable": true,
    "details": {}
  }
}
```

The internal `retryable` value is a native transient-error hint, not the public
MCP replay decision. The sidecar combines it with operation type and ledger
state to produce public `recoverable` and `safeToRetry` fields. Native messages
and details are bounded; OS errors and stack traces do not cross the boundary.
