# ADR 0038: Owned bounded address-trace sessions

Status: Accepted before implementation on 2026-08-31.

## Context

A trace is materially different from a single step. It keeps the debuggee
running across many callbacks, retains results beyond one HTTP request, needs a
separate cancellation path, and must terminate during plugin unload. Holding
the existing serialized executor in a loop of MCP step calls would block
status/cancel work and would give the backend, rather than x64dbg, incorrect
ownership of the debugger's stepping machinery.

x64dbg's conditional trace commands already provide into/over stepping and a
native maximum-step bound. During each trace stop, `CB_TRACEEXECUTE` supplies
the current instruction pointer and permits a plugin to set `stop`. The
upstream trace state also supports a force-break flag, but that function is not
part of the public plugin SDK. A normal debugger pause clears x64dbg's trace
state. Official behavior is described by:

- <https://help.x64dbg.com/en/latest/commands/tracing/index.html>
- <https://help.x64dbg.com/en/latest/commands/tracing/TraceOverConditional.html>
- <https://help.x64dbg.com/en/latest/introduction/ConditionalTracing.html>
- <https://github.com/x64dbg/x64dbg/blob/development/src/dbg/debugger.cpp>

`PLUG_CB_TRACEEXECUTE` contains only `cip` and `stop`. It does not provide an
immutable disassembly, register set, memory delta, or reliable branch target.
Trace-over intentionally omits instructions inside a call. The file-backed
run-trace recorder is a separate GUI/file facility and is not an appropriate
MCP result transport.

## Decision

Admit exactly four backend-local tools:

```text
trace.start(mode, max_steps, timeout_ms, instance_id, operation_id)
trace.status(trace_id)
trace.cancel(trace_id, instance_id, operation_id)
trace.results(trace_id, limit?, cursor?)
```

`mode` is the closed enum `into | over`. `max_steps` is 1-4096 and
`timeout_ms` is 100-30000. There is no caller expression, trace command, log
template, output path, party filter, or arbitrary stop condition. `trace.start`
is a mutation valid only at an actionable pause. It creates one unpredictable
trace UUID, snapshots the current IP and loaded-module spans, submits the fixed
`TraceIntoConditional 0,<max>` or `TraceOverConditional 0,<max>` command, and
waits only for callback-confirmed admission or an immediate terminal pause.
Post-submission ambiguity remains `OUTCOME_UNKNOWN` and is not restarted under
a new operation ID.

One backend owns at most one active session and retains at most its latest
terminal session. A new start is rejected while one is active and replaces the
previous terminal result only after the new command is admitted. Results retain
the initial IP plus at most one address for every observed trace step: no more
than 4097 records. Each record contains a sequence, canonical absolute address,
and module/RVA derived from the immutable start-time module snapshot when one
unique span contains it. It does not claim instruction bytes, register values,
thread identity, branch destinations, or events inside a trace-over call.

`CB_TRACEEXECUTE` performs no Bridge call, allocation, formatting, or blocking.
Under the trace mutex it appends the bounded CIP, increments the step count,
checks cancellation/deadline/capacity, and sets `stop` when required. A later
pause/step/breakpoint/exception/process callback finalizes the session. Terminal
reasons distinguish `max_steps`, `cancelled`, `timeout`, `breakpoint`,
`exception`, `user_pause`, `process_exit`, and `backend_shutdown`; an
unattributable transition is `interrupted`, never silently `completed`.

`trace.status` is a copied plugin-state read available while running or after
termination. `trace.results` is available only for a terminal session, pages at
most 256 immutable address records, and uses a trace-ID/result-fingerprint-bound
cursor. Reads never resume, pause, or query live memory.

`trace.cancel` is an instance-bound mutation for the exact active trace ID. It
sets the callback stop flag and submits one fixed `pause` through the serialized
executor so a thread blocked between trace callbacks cannot evade cancellation.
It waits for a terminal callback within the normal mutation deadline. A
terminal same-ID session returns its existing terminal state; a different or
unknown ID is a non-mutating conflict/not-found result. Cancellation never
submits another start and never invents a fresh trace ID.

An always-owned, joinable trace supervisor waits on a condition variable for
the active deadline. At expiry it marks timeout and submits the same fixed
pause operation through the debugger executor after rechecking trace identity.
It is not detached and owns no connection. Runtime shutdown first stops
admission, marks an active trace `backend_shutdown`, requests one bounded pause,
wakes and joins the supervisor, then drains the existing executor and sidecar.
All callbacks tolerate an already-terminal or destroyed session.

The x64dbg native max-step argument is a second independent bound. The plugin's
callback count/capacity and wall-clock supervisor remain authoritative because
the public contract must not depend on an expression variable or an unbounded
callback arriving eventually.

## Verification

Pure native tests cover state transitions, the 4097-record cap, cancellation,
deadline, interruption precedence, stale IDs, immutable module/RVA mapping,
cursor fingerprints, and shutdown finalization. Rust contract tests cover the
closed schemas, UUIDs, bounds, mutation annotations, malformed corpus, and a
bounded catalog.

Fresh x32dbg and x64dbg fixtures must prove into and over admission, exact
operation replay/conflict, max-step completion, result ordering/pagination,
explicit cancellation, timeout of a blocking path, interruption by an existing
breakpoint, one-active-session rejection, replacement of only a terminal
session, and debugger/plugin shutdown with active status/result requests. A
suitable Flare-On sample then qualifies a short, non-destructive address trace.

## Consequences

The backend gains a useful bounded control-flow path without exposing x64dbg
expressions, files, or arbitrary commands. It does not compete with x64dbg's
full run-trace file format and cannot answer register/memory-history questions.
The extra supervisor thread is justified only by the hard wall-clock guarantee;
it is single, joinable, condition-driven, and lifecycle-owned.
