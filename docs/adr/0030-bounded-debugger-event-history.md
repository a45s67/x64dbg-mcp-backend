# ADR 0030: Bounded debugger event history

Status: Accepted on 2026-08-30.

## Context

Pause reasons describe the current stop but not the bounded sequence that led
to it. Agents otherwise poll state, miss short-lived loader/thread events, or
infer chronology from unrelated generation numbers. An event facility must not
retain x64dbg callback pointers, allocate unbounded memory, block a callback,
spawn a connection thread, or become an unbounded log stream.

## Decision

Add one read-only tool available in every debugger state:

```text
events.list(after_sequence?, types?, limit?)
```

The plugin owns a fixed 256-record ring embedded in `Runtime`. A callback copies
only bounded scalar data while holding the existing state mutex, assigns a
strictly increasing sequence, and returns. It never retains callback pointers or
copies target-provided debug strings. Each record contains the event type,
sequence, debugger generation after that callback, and only applicable copied
process ID, thread ID, address, code, hit count, breakpoint type, first-chance,
or small size/flag fields.

The closed event types are `debug_initialized`, `process_created`,
`system_breakpoint`, `breakpoint`, `exception`, `paused`, `stepped`, `resumed`,
`attached`, `detached`, `stopping`, `process_exited`, `debug_stopped`,
`thread_created`, `thread_exited`, `dll_loaded`, `dll_unloaded`, `debug_string`,
and `rip`. Specific x64dbg callbacks own lifecycle/pause records. The generic
Windows debug callback contributes only thread, DLL, debug-string metadata, and
RIP records so events are not deliberately duplicated.

`after_sequence` is an optional JSON-safe nonnegative integer; only records with
a greater sequence are returned. `types` is an optional unique array of at most
19 closed enum values. `limit` defaults to 100 and is 1 through 256. The response
contains the retained oldest/latest sequences, matched items, `has_more`, a
`next_after_sequence` when items were returned, and `overflowed`. `overflowed`
is true when requested history predates the oldest retained record, or when an
unpositioned caller starts after the ring has already discarded records.

Filtering and copying happen under the state mutex into a fixed local array;
JSON rendering happens after releasing the mutex. Reading the ring never calls
a debugger API and does not require a paused debuggee. Plugin unload wakes or
cancels the ordinary bounded request path; there is no subscription or SSE
connection to drain.

## Verification

Native lifecycle tests cover empty history, exact wraparound and sequence order,
public overflow/filter metadata, and applicable exception fields. Contract tests
cover enum/array/limit/sequence bounds, duplicates, and unknown fields. Isolated
x32/x64 runs prove startup/loader filtering and continuation, structured
breakpoint events, pause/step events, stop visibility, and ordinary bounded
shutdown behavior.

## Consequences

Clients gain deterministic recent chronology without a detached listener or
unbounded output. The history is diagnostic and lossy by design; it is not a
trace engine, persistent audit log, or source of debug-string contents. A client
that sees `overflowed` must re-observe current state rather than infer the
missing interval.
