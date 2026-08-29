# ADR 0019: Typed hardware and memory breakpoint ownership

Status: Accepted before implementation on 2026-08-29.

## Context

Software breakpoints modify code bytes and are not appropriate for every
observation. x64dbg also supports CPU debug-register breakpoints and guard-page
memory-range breakpoints, but their constraints differ materially:

- hardware breakpoints have access modes, architecture-specific sizes, natural
  alignment, and only four logical debug-register slots;
- memory breakpoints have access modes and exact ranges, affect page protection,
  and can generate many events;
- x64dbg's public script API does not expose hardware size or memory-range setup,
  so the supported native surface requires fixed debugger commands followed by
  typed bridge read-back;
- deletion commands identify the breakpoint primarily by address. Deleting by
  address without first matching the expected type and shape can remove state
  that another actor changed.

The official x64dbg contracts are
[`SetHardwareBreakpoint`](https://help.x64dbg.com/en/latest/commands/breakpoint-control/SetHardwareBreakpoint.html),
[`SetMemoryRangeBPX`](https://help.x64dbg.com/en/latest/commands/breakpoint-control/SetMemoryRangeBPX.html),
[`DeleteHardwareBreakpoint`](https://help.x64dbg.com/en/latest/commands/breakpoint-control/DeleteHardwareBreakpoint.html),
and
[`DeleteMemoryBPX`](https://help.x64dbg.com/en/latest/commands/breakpoint-control/DeleteMemoryBPX.html).

## Decision

Add four backend-local mutations:

```text
breakpoints.hardware.set(address, access, size, operation_id)
breakpoints.hardware.remove(address, access, size, operation_id)
breakpoints.memory.set(address, access, size, operation_id)
breakpoints.memory.remove(address, access, size, operation_id)
```

Keep the existing `breakpoints.set` and `breakpoints.remove` as software-only
operations. This wire addition advances the backend package and managed skill to
0.6.0.

### Hardware breakpoint contract

- `access` is exactly `execute`, `write`, or `read_write`.
- Setup at transient `process_created` or `system_breakpoint` startup pauses is
  rejected. x64dbg can reset debug registers while leaving those pauses, so the
  tool requires a later callback-confirmed pause whose debug thread is stable.
- `size` is 1, 2, or 4 on x32dbg and 1, 2, 4, or 8 on x64dbg. Execute
  breakpoints require size 1. Data breakpoint addresses must be naturally
  aligned to their size.
- Setting fails before submission if a hardware breakpoint already exists at
  the address or all four logical slots are represented in the current
  breakpoint snapshot. It never silently replaces or disables another slot.
- The executor composes only `bphws <validated-address>, <x|w|r>,
  <validated-size>`. Callers cannot supply command text or expressions.
- Confirmation uses `GetBridgeBp(bp_hardware, address, ...)` and exactly matches
  the returned type, access, size, enabled state, and slot. The response reports
  the canonical location and the matched breakpoint shape.
- Remove first requires the current breakpoint to exactly match the supplied
  access and size, then submits only `bphwc <validated-address>` and confirms
  absence of that hardware breakpoint type.

### Memory breakpoint contract

- `access` is exactly `access`, `read`, `write`, or `execute`.
- `size` is an integer from 1 through 65,536 bytes. Address addition must not
  overflow the target architecture. The complete range must fit in one current
  memory region returned by `DbgMemFindBaseAddr`; cross-region guard changes are
  rejected before submission.
- Setting fails before submission if a memory breakpoint already exists at the
  start address. The executor composes only `bpmrange <validated-address>,
  <validated-size>, <a|r|w|x>`.
- Confirmation uses `GetBridgeBp(bp_memory, address, ...)`, exact `typeEx`, and
  `MemBpSize(address)`. The response reports the canonical location, access, and
  exact size.
- Remove requires the currently observed memory breakpoint to match both access
  and size, submits only `bpmc <validated-address>`, and confirms absence of
  that memory breakpoint type.

### Listing and ownership

`breakpoints.list` remains bounded and adds type-specific fields: hardware items
include `access`, `size`, and `slot`; memory items include `access` and `size`.
Unknown native enum values are reported as `unknown` rather than guessed.

Each mutation owns one operation-ledger entry. A new operation ID encountering
an already-present or mismatched breakpoint receives a structured known error;
only replay of the original completed operation returns its prior result.

## Threading, completion, and lifecycle

All preflight, command submission, bridge observation, and generation checks run
on the existing serialized native executor. The tools create no thread. Polling
is bounded by the request deadline and plugin unload wakes/cancels pending work.

Queue rejection before admission is retryable `BUSY`. Once a command is
accepted, timeout, unload, disappearing debuggee state, or mismatched read-back
is an unknown mutation outcome. The backend does not issue an automatic delete,
replacement, or second set as compensation.

## Rejected alternatives

- **One `breakpoints.configure` action union.** Read, set, and remove semantics
  become harder for MCP annotations and agents to distinguish.
- **Optional type fields on software `breakpoints.set`.** Defaults make a
  consequential breakpoint mechanism too easy to select accidentally.
- **Address-only typed removal.** It can delete state whose access or size was
  changed outside this operation.
- **Caller-supplied command fragments.** They expand the parser and injection
  surface without adding supported behavior.
- **Automatic cleanup after mismatched confirmation.** A second mutation after
  an ambiguous first mutation is not a safe rollback.
- **Batch breakpoint creation.** Slot exhaustion and partial guard-page success
  cannot be made atomic.

## Verification

- Rust schema and contract tests cover exact fields, enums, sizes, operation
  IDs, mutation annotations, and catalog bounds.
- Native policy tests cover access mappings, architecture-specific sizes,
  alignment, range overflow, memory-region containment, and exact read-back
  matching.
- Isolated x32dbg and x64dbg integrations set, list, hit where deterministic,
  exactly remove, and replay hardware and memory breakpoint operations. They
  also exercise mismatch, occupied address, alignment, x86 size, slot, and range
  rejection without leaving debugger state behind.
- Each installed-stage qualification uses an authorized Flare-On sample only
  where the breakpoint can be reached deterministically; the dual-architecture
  fixture remains mandatory evidence for architecture and cleanup behavior.
