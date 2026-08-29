# ADR 0017: Explicit attach/detach lifecycle and session origin

Status: Accepted before implementation on 2026-08-29.

## Context

`debuggee.launch` covers binaries the debugger creates, but dynamic work also
needs an explicitly identified process that is already running. Process
enumeration would disclose unrelated local activity and introduce an unbounded,
stale selection surface, so it is not part of this backend.

x64dbg's `attach` command accepts a PID, but all debugger command integer
constants are hexadecimal. Forwarding a JSON decimal PID as bare text can attach
to the wrong process. `CB_ATTACH` is documented and declared as a pre-attach
callback after `CB_INITDEBUG`; it is not completion. The attach command returns
control only after the system breakpoint.

The existing `debugger.stop` terminates the debuggee. Applying it to a process
that existed before this debugger attached is an unsafe default. A matching,
confirmed detach operation is required, and the backend must remember whether it
launched or attached the current session.

## Decision

Add two backend-local mutations:

```text
debuggee.attach(process_id, operation_id)
debuggee.detach(operation_id)
```

This wire and state-contract addition advances the backend package and managed
workflow skill to 0.4.0; the skill declares backend 0.4.0 as its minimum.

- `process_id` is a JSON integer from 1 through 4,294,967,295. The plugin rejects
  its own debugger host PID and its owned sidecar PID, then renders the validated
  value as `attach 0x<lowercase-hex>`; no process name, command, expression, or
  process enumeration is accepted.
- Attach requires `debuggee_state: absent`. Success requires a matching
  `CB_ATTACH` PID followed by a newer paused callback and a matching
  callback-maintained process ID. Unlike launch, attach may hand control back on
  the existing process's `CB_CREATEPROCESS` pause without a distinct later
  `CB_SYSTEMBREAKPOINT`. The result returns `session_origin:
  "attached"`, the PID, paused state, and confirmed generation.
- `CB_ATTACH` marks session origin as attached even for an attach initiated from
  the local GUI. A normal launch remains `launched`. `CB_STOPDEBUG` clears the
  origin.
- Detach is valid only for an attached active session. The fixed `detach`
  command is successful only after `CB_DETACH` and then `CB_STOPDEBUG` confirm
  absent state. It returns the detached PID, `debuggee_state: "absent"`, and the
  confirmed generation.
- `debugger.stop` is rejected for an attached session with an actionable error;
  callers must explicitly choose `debuggee.detach`. This prevents the generic
  cleanup path from terminating a pre-existing process.

`debugger.state` and readiness expose nullable `session_origin` (`launched` or
`attached`) while a session exists. This is explicit state, not inference from
whether a tool call recently succeeded.

## Errors, bounds, and lifecycle

- PID zero, non-integer, out-of-range, debugger-host PID, or owned-sidecar PID is
  rejected before command submission.
- Architecture mismatch, access denial, a disappearing PID, or other native
  attach failure may be known only as an unconfirmed mutation after queue
  admission. The original operation ID is preserved and the backend never
  retries with a new ID.
- Queue rejection before admission is retryable `BUSY`. Timeout after admission,
  unload, callback/PID mismatch, or connection loss is an unknown outcome.
- Attach and detach use existing callback condition variables and the single
  serialized executor. They create no connection or completion thread. Plugin
  unload wakes the waits and the sidecar remains owned by the debugger Job
  Object.
- The backend does not open the target process merely to preflight access and
  does not enumerate processes. x64dbg remains the authority for same-architecture
  and OS access checks.

## Rejected alternatives

- **Process list tool or attach by name.** Leaks unrelated system state, races
  process creation, and can select the wrong duplicate name.
- **Treat `CB_ATTACH` as completion.** It fires before native attachment.
- **Treat `DbgCmdExec` admission as completion.** The queued attach can still
  fail or time out.
- **Use `debugger.stop` as cleanup.** It can terminate a process the debugger did
  not create.
- **Silently detach during plugin unload.** Unload does not authorize a new
  debuggee mutation; the debugger itself retains lifecycle ownership.

## Verification

- Rust tests cover PID bounds, strict fields, mutation classification, catalog
  annotations, and both operation-ID schemas.
- Native lifecycle tests cover callback-maintained attach/detach origin and reset.
  The isolated debugger integration covers PID correlation, pre-attach ordering,
  destructive-stop rejection, detach confirmation, replay, and bounded shutdown.
- Isolated x32dbg/x64dbg integration starts an architecture-matched fixture
  independently, attaches by numeric PID, performs bounded reads, detaches,
  proves the fixture remains alive, then terminates only that test-owned fixture.
- Installed qualification uses a benign independently started Flare-On sample
  only when its lifecycle is suitable; otherwise the dual-architecture fixture
  is the mandatory stage evidence and the reason is recorded.
