# IPC protocol v1

The sidecar and plugin communicate over a current-user-only Windows named pipe.
This document freezes the MVP wire boundary independently of either language.

## Framing

Each frame is:

```text
uint32_le payload_length
payload_length bytes of UTF-8 JSON
```

The payload MUST be non-empty and MUST NOT exceed 1,048,576 bytes. A peer closes
the connection on a zero, oversized, truncated, trailing, invalid UTF-8, invalid
JSON, or schema-invalid frame. There is no resynchronization scan after corruption.

One request produces exactly one response with the same `request_id`. Both sides
apply absolute deadlines. A disconnected or timed-out mutation is never replayed.

## Handshake

The plugin creates the secured pipe and supplies the launch nonce to the sidecar
through the child's sole inherited stdin channel. The plugin retains the write
end for the child lifetime; EOF is the sidecar shutdown signal. The plugin's first
named-pipe frame is:

```json
{
  "protocol_major": 1,
  "protocol_minor": 0,
  "backend": "x64dbg",
  "plugin_pid": 4242,
  "nonce": "at-least-32-unpredictable-characters"
}
```

Major versions must match exactly. A peer may accept an older or equal minor
version within the same major. The receiving Rust sidecar compares the nonce in
constant time; the native plugin strictly validates the versioned acknowledgement.
Authentication failure closes the pipe without detailed logging.

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

`operation_id` is null for reads and required for mutations. `deadline_unix_ms`
is admission metadata, not permission to continue forever after the deadline.
Address-taking payloads accept a legacy canonical hexadecimal string or one of
the closed structured forms:

```json
{"address":{"absolute":"0x140001000"}}
```

```json
{"address":{"module":"sample.exe","rva":"0x1000"}}
```

The plugin resolves the latter only after the work item reaches the serialized
debugger executor. Arbitrary expression strings are not address references.

`debugger.wait_for_pause` is a read request (`operation_id: null`) whose payload
contains required integer `after_generation` and optional integer `timeout_ms`
(default 5,000; range 1-9,000). A successful result includes
`debuggee_state`, `state_generation`, `instruction_pointer`,
`active_thread_id`, and a bounded `pause_reason`. Its reason `kind` is one of
`process_created`, `system_breakpoint`, `breakpoint`, `exception`, `step`,
`user_pause`, or `unknown`.

Every successful state-sensitive read includes `state_generation` inside its
`result` (the outer IPC field is transport metadata and is not forwarded as MCP
structured content). A callback during collection returns `BUSY` with
`retryable: true`; no mixed-generation result is emitted. Pagination cursor
generation must equal the checked result generation.

## Response

Success:

```json
{
  "request_id": "83db0d7d-df01-40ac-bdfc-87bac1e60813",
  "state_generation": 8,
  "status": "ok",
  "result": {
    "address": "0x140001000",
    "location": {
      "address": "0x140001000",
      "module": "sample.exe",
      "module_base": "0x140000000",
      "rva": "0x1000",
      "state_generation": 8
    },
    "bytes_written": 1
  }
}
```

Failure uses `status: "error"` and the stable structured error envelope. Internal
OS errors and stack traces never cross this boundary.
