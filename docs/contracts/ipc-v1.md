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
