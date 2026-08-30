# ADR 0036: Thread-scoped context reads without global selection

Status: Accepted before implementation on 2026-08-31.

## Context

The backend can list every paused thread and read a native call stack for one
exact thread, but `registers.read` and `debugger.snapshot` currently observe
only x64dbg's globally selected thread. An agent inspecting a lock wait,
exception, worker pool, or cross-thread handoff therefore cannot compare thread
contexts without changing GUI selection. A `threads.switch` mutation would add
global state, postcondition, replay, and user-interference problems to a
read-only workflow.

The public bridge has no per-thread register-dump function. Its thread list does
provide the debugger-owned handle, TID, selected index, and `ThreadCip` for each
record. In the pinned upstream implementation, the handle is captured from the
Windows create-thread debug event and `ThreadCip` is obtained from that same
handle through TitanEngine `GetContextDataEx`. The selected-thread register dump
also ultimately reads a thread-handle context. Windows `GetThreadContext` can
therefore provide the bounded control and integer subset while the debuggee is
stopped, without selecting or additionally suspending the thread.

## Decision

Extend the two existing reads rather than add duplicate tools:

```text
registers.read(names?, thread_id?)
debugger.snapshot(registers?, disassembly_count?, thread_id?)
```

`thread_id` uses the existing canonical `0x1` through `0xffffffff` schema. When
omitted, behavior remains the current selected-thread behavior. When supplied,
the executor obtains one bounded `DbgGetThreadList` snapshot, rejects malformed
native counts above 65,536, requires exactly one matching TID with a valid
debugger-owned handle, and never closes that handle.

For the selected TID, the existing `DbgGetRegDumpEx` path remains authoritative.
For another TID, the plugin calls `GetThreadContext` once with only
`CONTEXT_CONTROL | CONTEXT_INTEGER`. It exposes only the existing architecture-
matched core integer registers, portable `cip`/`csp`/`cbp`, and `eflags`; SIMD,
x87, segment, debug, and extended state remain excluded. The captured instruction
pointer must equal the same thread-list record's `ThreadCip`. A mismatch or
generation change returns retryable `BUSY`, never mixed context.

Both results add the exact observed `thread_id` and `current` boolean.
`debugger.snapshot` retains `active_thread_id` for the globally selected pause
thread and adds `thread_id` for the requested context. Its register map,
instruction-pointer location, and bounded disassembly all derive from the same
requested context. `pause_reason` remains the process stop observation and is
not relabeled as though the requested thread caused it.

A missing TID returns non-retryable `INVALID_ARGUMENT`; a present handle whose
context cannot be captured returns non-retryable `ACCESS_DENIED`; a debugger
state or generation change returns the existing structured state/BUSY errors.
No path calls `SuspendThread`, `ResumeThread`, `SetThreadContext`, x64dbg's
switch-thread command, or any GUI-selection API.

## Verification

Contract tests cover optional canonical thread IDs, additional-property
rejection, and unchanged defaults. Native policy tests cover x86/x64 conversion
of Windows integer/control contexts and register allowlists. A deterministic
fixture creates an additional worker thread. Isolated x32 and x64 integration
select a non-current TID from `threads.list`, require its listed `ThreadCip` to
match `registers.read` and `debugger.snapshot`, verify selected-thread defaults
remain identical, reject a missing TID without losing the connection, and prove
the selected thread never changes. Shutdown and a paused Flare-On read remain
mandatory.

## Consequences

Common multithreaded inspection remains read-only and composable. A future
`threads.switch` must be justified by a write or step workflow that cannot use
explicit thread addressing; this ADR does not admit it. Thread suspend/resume
also remains deferred because reading a context proves neither suspend ownership
nor safe recovery.
