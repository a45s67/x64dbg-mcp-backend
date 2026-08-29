# ADR 0020: Bounded assembly preview and verified patch lifecycle

Status: Accepted before implementation on 2026-08-29.

## Context

Assembly is useful for designing a patch, but previewing bytes and changing a
debuggee have different authorization and MCP annotation semantics. A single
tool with `write_to_memory` hides that distinction. Raw memory writes also do
not provide an instruction-sized contract or prove that x64dbg's patch database
can later restore the original bytes.

x64dbg exposes a non-mutating `DBGFUNCTIONS::Assemble` API that emits at most 16
bytes for one instruction. Its `MemPatch` API reads old bytes, writes new bytes,
and records each changed byte in the patch database. `PatchGetEx`,
`PatchInRange`, and `PatchRestoreRange` expose the corresponding verification and
restore surface. The upstream `MemPatch` implementation records bytes only
after a successful memory write:
[`memory.cpp`](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/memory.cpp).

## Decision

Add three backend-local tools:

```text
assembly.preview(address, instruction)
assembly.patch(address, instruction, expected_bytes_hex, fill_nop, operation_id)
patches.restore(address, expected_patched_bytes_hex, expected_original_bytes_hex, operation_id)
```

This wire addition advances the backend package and managed skill to 0.7.0.

### Shared input and state rules

- All tools require a paused debuggee and one structured absolute or module/RVA
  address. Relative encodings are therefore assembled at the exact runtime
  address and debugger architecture.
- `instruction` is one printable ASCII instruction from 1 through 128 bytes.
  Control characters, NUL, and semicolons are rejected; callers cannot submit a
  command sequence or debugger command.
- Byte strings are canonical lowercase hexadecimal pairs. Each operation is
  limited to 1 through 16 bytes and address addition must not overflow the
  target architecture.
- Every result is correlated to one unchanged paused generation and returns the
  canonical location.

### Assembly preview

- `assembly.preview` is read-only and calls only `DBGFUNCTIONS::Assemble` into a
  fixed 16-byte buffer.
- It returns the normalized input instruction, exact `bytes_hex`, byte count,
  address/location, and generation. It never calls a memory or patch API.
- Invalid assembler syntax is a known `INVALID_ARGUMENT` result. Native error
  text is bounded before it is placed in structured details.

### Verified patch

- The backend assembles the instruction first. `expected_bytes_hex` is the
  complete original span and is a compare-before-write precondition.
- If assembled size equals the expected span, `fill_nop` must be false or has no
  effect. If assembled size is shorter, `fill_nop: true` pads only the remaining
  bytes with `0x90`; otherwise the request is rejected. An assembled instruction
  larger than the expected span is rejected.
- `PatchInRange` must report no existing patch anywhere in the span. Layering a
  new patch over existing patch metadata is rejected with `CONFLICT`.
- The executor reads the current span and requires byte-for-byte equality with
  `expected_bytes_hex`. It rejects a no-op result before mutation.
- After one `MemPatch` call, it reads memory back exactly. For every changed
  byte, `PatchGetEx` must report the expected old and requested new byte. No
  automatic restore follows an ambiguous or mismatched postcondition.
- The response returns original, assembled, and final written bytes; assembled
  and span lengths; NOP padding count; changed byte count; patch tracking; and
  generation.

### Verified restore

- Restore requires both the exact bytes expected in memory now and the exact
  original bytes expected from patch metadata. Their lengths must match and at
  least one byte must differ.
- Before mutation, memory must match `expected_patched_bytes_hex`. Every changed
  byte must have an exact `PatchGetEx` old/new record, and unchanged bytes must
  not hide a patch entry.
- The executor calls `PatchRestoreRange` once for the exact inclusive span,
  reads the original bytes back, and confirms `PatchInRange` is false.
- A preflight mismatch is a known `CONFLICT`. Any failure after the void restore
  call is an unknown mutation outcome and is never retried automatically.

## Bounds, threading, and lifecycle

All assembler, memory, patch-database, and verification calls run on the existing
serialized native executor. Buffers are fixed at 16 bytes plus a bounded native
error buffer. No tool creates a thread. Request deadlines and unload cancellation
remain bounded, and the one-slot operation ledger owns each mutation.

## Rejected alternatives

- **One tool with `write_to_memory`.** Read-only and destructive authorization,
  annotations, and audit intent become conditional on a boolean.
- **Caller-provided assembled bytes without preview.** `memory.write` already
  owns bounded raw writes; this workflow specifically binds assembler output to
  one instruction and patch tracking.
- **Multi-instruction text.** Partial assembly and per-instruction relative
  address changes complicate atomicity and bounds.
- **Patch without expected bytes.** It permits stale analysis to overwrite code.
- **Patch over an existing tracked range.** Original-byte ownership becomes
  ambiguous and safe restore cannot be proven.
- **Automatic rollback after postcondition failure.** It would be a second blind
  mutation after an unknown first outcome.
- **Address-only restore.** It trusts mutable patch state without confirming the
  bytes the caller intended to restore.

## Verification

- Rust schema/contract tests cover printable single-instruction text, exact
  fields, canonical 1-16 byte strings, required `fill_nop`, operation IDs,
  annotations, and catalog bounds.
- Native policy tests cover padding, span/overflow rules, no-op rejection, exact
  patch-record matching, and architecture-independent byte encoding.
- Isolated x32dbg and x64dbg integrations preview one instruction, reject stale
  expected bytes and an already tracked range, patch one disposable fixture
  instruction, verify read-back and patch metadata, replay without re-execution,
  restore exactly, replay restore, and leave no patch or process behind.
- Installed qualification patches and immediately restores a non-executed
  instruction in an authorized Flare-On sample, then continues the existing
  behavioral smoke test so restored code is exercised unchanged.
