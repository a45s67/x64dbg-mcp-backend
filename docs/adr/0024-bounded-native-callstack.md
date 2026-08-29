# ADR 0024: Add bounded native call-stack reads

Status: Accepted on 2026-08-29.

## Context

Register and disassembly reads show the current instruction but do not explain
the dynamic caller chain. Reconstructing a stack externally is architecture- and
unwind-dependent, and a frame-pointer scan is not equivalent to x64dbg's native
unwinder. The pinned plugin SDK exposes `GetCallStackByThread`, returns at most 50
native `DBGCALLSTACKENTRY` records in the baseline implementation, and allocates
the returned array with `BridgeAlloc`.

## Decision

Add the read-only backend-local tool:

```text
callstack.read(thread_id?, limit?)
```

It is valid only while the debuggee is paused. `thread_id` is an optional
canonical lowercase hexadecimal string; omission selects the callback-observed
active thread. `limit` defaults to 32 and is restricted to 1-50.

The executor captures `DbgGetThreadList`, rejects native counts above 65,536,
selects exactly one current thread ID, and borrows its handle only for the
synchronous call. It invokes `DBGFUNCTIONS::GetCallStackByThread`; no handle or
native pointer is retained. The returned `entries` array is always released with
`BridgeFree`, including malformed and timeout/error paths. Negative totals,
totals above 50, null/count disagreement, noncanonical addresses, and generation
churn fail closed.

Each frame contains a zero-based `index`, canonical `stack_address`, structured
`instruction` location from native `from`, and structured `return_to` location
from native `to`. Localized native comment text is omitted. Module/RVA metadata
is added only from the same bounded module snapshot used during the generation
check.

The result contains `thread_id`, `frames`, `native_frame_count`, `truncated`,
`completeness`, and `state_generation`. `truncated` is true when the caller limit
cuts the native result or the native result reaches its hard 50-frame ceiling.
An empty native result is `completeness: "inconclusive"`, not proof that the
thread has no caller. Otherwise completeness is `native_bounded`; it never claims
a complete unwind beyond x64dbg's native ceiling.

The native implementation transiently suspends and resumes the selected thread
while collecting context. This is SDK-owned behavior, so the tool is admitted
only at a callback-confirmed paused state and only through the serialized
executor. The backend does not add another suspend/resume pair, switch the GUI
thread, or fall back silently to frame-pointer scanning. If a future fallback is
added, it must be explicitly labeled incomplete in a separate ADR.

## Errors and verification

Stable failures are `INVALID_ARGUMENT`, `INVALID_DEBUGGER_STATE`, `NOT_FOUND`,
`BUSY`, `TIMEOUT`, `OUTPUT_LIMIT_EXCEEDED`, `CANCELLED`, and `INTERNAL`. There is
no operation ID because the public tool is read-only.

Tests cover schema bounds, current/explicit thread selection, missing threads,
zero/malformed/native-limit results, allocation release, generation churn,
queued/active shutdown, x32/x64 unwind shapes, and a real sample with at least
one bounded frame. No test may equate a frame-pointer-only fixture with native
unwind success.

## Consequences

Clients obtain a compact dynamic caller chain without arbitrary commands or GUI
selection. Native unwind quality remains dependent on available unwind metadata
and x64dbg's bounded implementation; the contract exposes that limitation rather
than manufacturing certainty.
