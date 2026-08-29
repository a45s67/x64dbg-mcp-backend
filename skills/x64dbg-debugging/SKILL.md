---
name: x64dbg-debugging
description: Analyze and control authorized Windows binaries through the x64dbg or x32dbg MCP backend. Use for debugger lifecycle, module/RVA addressing, breakpoints, stepping, registers, memory, disassembly, and bounded discovery; do not use for static-only analysis or unsupported arbitrary debugger commands.
metadata:
  short-description: Safe x64dbg/x32dbg MCP workflows
  version: "0.7.0"
  minimum-backend-version: "0.7.0"
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

Begin with `debugger.state`. Respect the reported state and each tool schema; most inspection
requires `paused`. Tool names below are backend-local. A Gateway may prepend a namespace, so
select the connected backend whose published tool name ends with the documented local name.

Use `registers.write` for one full-width core register at a time. Preserve the original value
when the workflow requires restoration, use a fresh operation ID only for that distinct restore,
and verify the returned read-back. `debugger.step_out` stops at the current frame's return
instruction; inspect `completed` and the returned pause reason before continuing.

Use `breakpoints.hardware.set` only after transient `process_created` and `system_breakpoint`
startup pauses. Choose one exact access and naturally aligned architecture-supported size; there
are four logical slots. Use `breakpoints.memory.set` only for an intentionally bounded guard-page
range. Typed removals require the original access and size, so inspect `breakpoints.list` rather
than guessing externally changed state.

Use `assembly.preview` to obtain debugger-architecture bytes without changing memory. For an
authorized code change, read the complete original instruction span, then call `assembly.patch`
with those exact lowercase bytes and a fresh operation ID. Use `fill_nop: true` only when the
assembled instruction is shorter than that span. Restore only with `patches.restore`, supplying
both the exact patched and original bytes returned by the patch workflow. A conflict means memory
or x64dbg patch metadata changed; re-inspect it instead of forcing a write or address-only restore.

Prefer `{ "module": "sample.exe", "rva": "0x..." }` for address-taking tools. This keeps ASLR
translation native and atomic. Use `address.resolve` when the absolute runtime address or canonical
location metadata is itself useful.

Every intended mutation needs a fresh canonical lowercase UUID `operation_id`. If submission or
confirmation is ambiguous, preserve that ID and inspect state; never invent a new ID to force a
blind retry. Do not infer authority to launch, write, set a breakpoint, resume, or stop from an
analysis request.

After `debugger.resume`, pass its confirmed `state_generation` to
`debugger.wait_for_pause(after_generation=...)`. Validate the returned pause reason, instruction
pointer, and generation before reading related state. Treat `symbols.search`, `functions.list`,
`strings.search`, and `references.to` as bounded `known_only` views; an empty result is not proof
of absence. When the user explicitly authorizes analysis at a concrete address, use the separate
`analysis.function` mutation with module/RVA and a fresh operation ID; it analyzes one function,
not a whole module, and an ambiguous result must not be blindly retried.

For state-specific sequences, breakpoint loops, compact inspection, and Go triage, read
[references/recipes.md](references/recipes.md). For connection, authentication, stale cursor,
timeout, and recovery decisions, read
[references/troubleshooting.md](references/troubleshooting.md).
