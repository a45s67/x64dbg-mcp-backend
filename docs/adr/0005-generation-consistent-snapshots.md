# ADR 0005: generation-consistent debugger snapshots

- Status: Accepted
- Date: 2026-08-29
- Scope: Read tools and address-consuming operations

## Context

Debugger callbacks can arrive while the serialized executor is copying a Bridge
list, reading registers or memory, resolving a module-relative address, or
serializing a result. Serialization of debugger API calls prevents two MCP work
items from overlapping, but it does not stop x64dbg's callback thread. Returning
fields sampled on both sides of a callback with the callback's newer generation
would falsely describe a coherent debugger state.

Holding the callback mutex while calling synchronous Bridge APIs is unsafe: a
Bridge call may itself depend on debugger progress or callbacks. An unbounded
internal retry loop would also hide churn and violate request deadlines.

## Decision

Every state-sensitive read uses an optimistic, bounded capture protocol:

1. Under the callback-state mutex, capture the current global generation and
   required debuggee state.
2. Release the mutex and perform the bounded native read and result assembly.
3. Reacquire the mutex and require the same generation, state, and ready plugin.
4. Return the captured generation only when the check succeeds. Otherwise return
   structured `BUSY` with `retryable: true`; the backend does not retry internally.

All callback-owned PID, TID, state, pause-reason, and generation updates occur
under the same mutex, with the generation advanced before releasing it. This
makes the two capture points meaningful without holding the lock over a debugger
API.

`debugger.state` copies non-native fields under the mutex. When paused, it reads
the instruction pointer after releasing the mutex and performs the same final
generation check. `debugger.wait_for_pause` additionally verifies both its
retained pause generation and the global capture generation around IP/thread
collection.

The protocol applies to:

- state, register, expression, memory, module, thread, memory-map, breakpoint,
  address-resolution, and disassembly reads;
- every page cursor, which is minted only from a successfully checked snapshot;
- the resolution-to-consumption window for address-taking reads and mutations.

A cursor whose generation differs at admission remains `INVALID_ARGUMENT`
(`cursor is stale`). A generation change during collection is `BUSY` because the
caller supplied no stale cursor; both are deterministic and retry-safe for reads.

## Mutation boundary

Mutation completion remains callback-confirmed and is not retried. For a
mutation that consumes an address resolved earlier in its work item, the plugin
rechecks the captured generation and required state immediately before the
native write or command submission. A mismatch returns `BUSY` before mutation
submission.

## Rejected alternatives

- **Hold the state mutex across Bridge calls.** Risks callback/API deadlock and
  stalls all lifecycle transitions.
- **Return the newest generation after assembling old data.** Labels a mixed
  result as coherent.
- **Silently retry until stable.** Can multiply expensive reads and obscure
  overload; callers can retry the explicit read-only `BUSY` result.
- **Freeze the debuggee for every read.** Changes debugger state and turns reads
  into surprising mutations.

## Acceptance tests

- A callback between capture and final check invalidates the snapshot.
- Paused state never combines an IP from one generation with PID/TID from another.
- Pagination rejects both admission-stale cursors and mid-collection churn.
- Address resolution and its consuming operation share one checked generation.
- x32 and x64 integration confirms stable generations and stale-cursor behavior.
- Active snapshot work remains bounded during plugin unload.

## Validation evidence

The x32 and x64 isolated fixtures returned an embedded generation from every
state-sensitive read, matched address-result and location generations, minted a
cursor from that same generation, and rejected it after a step callback. Native
lifecycle tests also prove a captured snapshot becomes invalid after a callback.

The deployed x64 build stopped at Flare-On 11 `checksum.exe+0xa78a0`. Pause,
selected registers, 16 bytes of memory, and four disassembled instructions all
reported generation 27; both address-taking reads matched their nested location
generation. The session then stopped cleanly.
