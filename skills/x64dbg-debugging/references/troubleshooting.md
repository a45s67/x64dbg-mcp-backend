# x64dbg MCP troubleshooting

## Endpoint and readiness

- Connection refusal usually means the matching debugger is not open, its plugin did not load, or
  that backend type is already owned by another instance. Start x64dbg/x32dbg, not the sidecar.
- `/health/live` proves only that the HTTP process exists. Authenticated `/health/ready` also
  requires the plugin IPC connection; `debugger_state: absent` is healthy and means no target is
  loaded. Retain its `instance_id` and confirm that `debugger.state` reports the same value.
- An authentication error means the client configuration and installed server config disagree.
  Re-run the backend installer and replace both manually configured Codex Authorization values
  with the newly printed shared value; never place the bearer token in a skill or prompt.
- Select x32dbg for 32-bit targets and x64dbg for 64-bit targets. The two endpoints and processes
  are independent.

## State and pagination errors

- `INVALID_DEBUGGER_STATE`: re-read `debugger.state`; do not force the operation through a raw
  debugger command.
- `BUSY`: the debugger generation changed during a read. Discard that logical snapshot and retry
  the read only after a stable pause.
- `STALE_CURSOR`: restart that list/search from the first page with the same desired filters.
- `OUTPUT_LIMIT_EXCEEDED`: narrow the query, module, page, or requested range. Do not bypass the
  bound with arbitrary command execution.
- Empty discovery output with `completeness: known_only` means x64dbg has no retained matching data
  yet; it does not prove absence from the binary.

## Timeouts and mutations

`BACKEND_RESTARTED` means the mutation names an earlier sidecar instance. Its
outcome is unknown and the replacement backend did not dispatch it. Re-read
`debugger.state`, reassess the intended action, and use a new operation UUID only
for a newly authorized decision; never copy the stale request across the boundary.

`debugger.wait_for_pause` timeout is a retryable observation failure and performs no mutation.
For launch, resume, pause, step, stop, write, and breakpoint mutations, a timeout after submission
may mean the action occurred but confirmation was lost. Preserve the original `instance_id` and `operation_id`,
inspect debugger state and observable effects, and ask for direction when repeating the intended
action could be harmful. Never switch to a new UUID merely to make the backend execute it again.

If the debugger closes or the plugin unloads, active requests should return cancellation or
unavailability. Let teardown complete before reopening the matching backend.
