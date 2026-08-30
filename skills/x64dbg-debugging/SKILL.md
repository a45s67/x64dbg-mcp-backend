---
name: x64dbg-debugging
description: Analyze and control authorized Windows binaries through the x64dbg or x32dbg MCP backend. Use for debugger lifecycle, module/RVA addressing, breakpoints, stepping, registers, memory, disassembly, and bounded discovery; do not use for static-only analysis or unsupported arbitrary debugger commands.
metadata:
  short-description: Safe x64dbg/x32dbg MCP workflows
  version: "0.16.0"
  minimum-backend-version: "0.16.0"
  mcp-protocol: "2025-06-18"
---

# x64dbg MCP debugging

Use the connected `x64dbg` server for 64-bit PE targets and `x32dbg` for 32-bit PE targets. The
debugger plugin owns its HTTP sidecar: start the matching debugger normally, and do not launch a
detached server process when the endpoint is offline.

For an explicitly authorized existing process, use `debuggee.attach(process_id, operation_id)`;
the backend never enumerates processes. Attached sessions report `session_origin: "attached"`.
Use `debuggee.detach` to preserve that pre-existing process. Never use `debugger.stop` as attached
session cleanup.

Begin with `debugger.state` and retain its `instance_id`. Respect the reported state and each tool
schema; most inspection requires `paused`. Tool names below are backend-local. A Gateway may prepend a namespace, so
select the connected backend whose published tool name ends with the documented local name.

Use `debuggee.launch` only for an authorized absolute executable path. Supply arguments as the
structured `arguments` string array; never pre-quote them or combine them into a raw command line.
The backend preserves empty strings, spaces, quotes, backslashes, commas, and Unicode and returns
only after committing the command line at the initial actionable pause.

Use `debuggee.launch_dll` only for an authorized architecture-matched DLL. It accepts no argv or
export and returns at the generated x64dbg loader's initial pause with `target_loaded: false`.
Reaching `DllMain` requires one separately authorized `debugger.resume` followed by
`debugger.wait_for_pause`; verify the loaded target module and require the pause instruction
pointer to equal its reported entry. Never treat the temporary loader as the target DLL.

Use `registers.write` for one full-width core register at a time. Preserve the original value
when the workflow requires restoration, use a fresh operation ID only for that distinct restore,
and verify the returned read-back. `debugger.step_out` stops at the current frame's return
instruction; inspect `completed` and the returned pause reason before continuing.

For cross-thread inspection, copy an exact `thread_id` from `threads.list` into
`registers.read` or `debugger.snapshot`. These are read-only context captures:
they do not switch x64dbg's selected thread. The snapshot's register map,
instruction pointer, and disassembly describe the requested thread, while
`active_thread_id` continues to identify the selected debugger thread. Compare
their state generations and retry only a retryable `BUSY` read after observing
the current pause again.

Use `debugger.run_to_address` instead of composing a temporary breakpoint,
resume, wait, and cleanup yourself. Supply a stable module/RVA when possible and
an explicit bounded timeout. Require `completed: true` before assuming the
target was reached; otherwise inspect `interruption` and `pause_reason`. The
backend removes only its exact operation-owned temporary breakpoint. Do not
blindly repeat an unknown outcome with a fresh operation ID.

Use `breakpoints.hardware.set` only after transient `process_created` and `system_breakpoint`
startup pauses. Choose one exact access and naturally aligned architecture-supported size; there
are four logical slots. Use `breakpoints.memory.set` only for an intentionally bounded guard-page
range. Typed removals require the original access and size, so inspect `breakpoints.list` rather
than guessing externally changed state.

Use `breakpoints.conditional.set` for portable register, thread-ID, or hit-count conditions. Build
one to four predicates through the closed `condition` schema; never synthesize an x64dbg expression.
Use `breakpoints.exception.set` for one exact 32-bit exception code and `first`, `second`, or `both`
chance policy. Preserve the returned `managed_id`: conditional and exception removal requires it
and refuses a foreign or renamed record. An exception-breakpoint hit is reported as an `exception`
pause with the observed code, actual exception address, and first-chance flag, not merely the
configured chance policy.

Use `assembly.preview` to obtain debugger-architecture bytes without changing memory. For an
authorized code change, read the complete original instruction span, then call `assembly.patch`
with those exact lowercase bytes and a fresh operation ID. Use `fill_nop: true` only when the
assembled instruction is shorter than that span. Restore only with `patches.restore`, supplying
both the exact patched and original bytes returned by the patch workflow. A conflict means memory
or x64dbg patch metadata changed; re-inspect it instead of forcing a write or address-only restore.

Prefer `{ "module": "sample.exe", "rva": "0x..." }` for address-taking tools. This keeps ASLR
translation native and atomic. Use `address.resolve` when the absolute runtime address or canonical
location metadata is itself useful.

Every intended mutation needs the current `instance_id` plus a fresh canonical lowercase UUID
`operation_id`. If the backend reports `BACKEND_RESTARTED`, stop and re-observe state; never send
the old mutation to the replacement instance. If submission or confirmation is ambiguous within
one instance, preserve that operation ID and inspect state; never invent a new ID to force a blind
retry. Do not infer authority to launch, write, set a breakpoint, resume, or stop from an analysis
request.

After `debugger.resume`, pass its confirmed `state_generation` to
`debugger.wait_for_pause(after_generation=...)`. Validate the returned pause reason, instruction
pointer, and generation before reading related state. Treat `symbols.search`, `functions.list`,
`strings.search`, and `references.to` as bounded `known_only` views; an empty result is not proof
of absence. When the user explicitly authorizes analysis at a concrete address, use the separate
`analysis.function` mutation with module/RVA and a fresh operation ID; it analyzes one function,
not a whole module, and an ambiguous result must not be blindly retried.

When a concrete symbol name or address is already known, prefer `symbols.resolve` over paging a
substring search. Use `functions.at` to test whether one address is inside an existing function;
it does not analyze missing code. Use `callstack.read` for a bounded native unwind and retain its
completeness label. Use `patches.list` before restore or execution when tracked patch state matters;
repeat exact filters for its snapshot-bound cursor and restart after `STALE_CURSOR`.

Use `imports.list` for module-scoped IAT slots and their current runtime targets; a resolved
provider is an observation, not the original PE descriptor DLL. Use `exports.list` for ordinals
and forwarder metadata. Both are bounded known-only views and never reconstruct imports, follow a
forwarder, download symbols, or analyze a module.

Use `events.list` for bounded callback history instead of polling or inventing a
stream. Retain `next_after_sequence` for continuation, repeat the same closed
type filter, and treat `overflowed: true` as a required resynchronization signal:
re-read current state before interpreting retained events. Event text and native
callback pointers are intentionally unavailable.

Use `sections.list` when named loaded-image boundaries matter. Its start, size,
and exclusive end are ASLR-correct SDK observations; it does not claim section
characteristics, permissions, or raw-file offsets. Use `memory.map` separately
for current page protection, and static PE analysis when on-disk metadata is
required.

Use `memory.search` for an exact loaded module or one explicit bounded runtime
range when the address is not yet known. Supply 1-64 concrete bytes as lowercase
`pattern_hex` and one `x` or `?` mask character per byte. Retain its filter- and
generation-bound cursor, allow overlapping results, and treat
`partial_unreadable` as evidence that the declared scope was not fully
observable. Do not replace this bounded search with an unrestricted process
scan or memory dump.

For state-specific sequences, breakpoint loops, compact inspection, and Go triage, read
[references/recipes.md](references/recipes.md). For connection, authentication, stale cursor,
timeout, and recovery decisions, read
[references/troubleshooting.md](references/troubleshooting.md).
