# x64dbg MCP recipes

## State routing

| Debuggee state | Useful next actions | Avoid |
|---|---|---|
| `absent` | Explicitly request typed EXE/DLL launch or PID-only `debuggee.attach` if authorized | Reads that require a target; process enumeration; starting a separate sidecar |
| `starting` | Wait for the launch mutation's callback confirmation | A second launch or speculative resume |
| `paused` | Resolve addresses; inspect; set/remove breakpoints; step or resume if authorized | Large unfiltered reads |
| `running` | Use `debugger.wait_for_pause` after a known resume generation, or explicitly pause | Register/memory/disassembly reads; polling loops |
| `stopping` / `exited` | Re-read `debugger.state` and wait for bounded teardown | Retrying stop/detach with a new operation ID |

For `session_origin: "attached"`, cleanup uses `debuggee.detach`. The backend rejects
`debugger.stop` for that origin because stop can terminate a process the debugger did not create.

Retain the `instance_id` from the initial state observation and supply it with
every mutation in the workflow. If a later state reports another value, discard
all pending mutation requests from the old instance and reassess from the new
state; operation-ledger results do not survive that boundary.

For a DLL, call `debuggee.launch_dll` and confirm its initial result names one generated
`DLLLoader32_*` or `DLLLoader64_*` module while `target_loaded` is false. Authorize and issue one
normal resume, wait from that returned generation, then list modules and verify the pause IP equals
the target DLL's entry. The tool never calls an export, supplies argv, or hides this resume.

For a temporary register change, read the original value, call `registers.write` once with one
operation ID, and restore with a different operation ID only when restoration is a separately
authorized mutation. Never batch speculative register changes.

After `debugger.step_out`, require `completed: true` before assuming the frame reached its return.
When it is false, inspect `pause_reason`, CIP, and disassembly; an existing breakpoint, exception,
or user pause interrupted the operation and replaying it cannot make further progress.

Hardware breakpoints are per debug-register context. Advance past `process_created` and
`system_breakpoint` startup pauses, then select
`execute` with size 1 or an aligned `write`/`read_write` data size supported by the backend
architecture. Memory breakpoints change guard-page behavior for an exact bounded range and can be
noisy; prefer them only when a software or hardware breakpoint cannot observe the needed access.
For either typed kind, remove with the same address, access, and size. A mismatch is a conflict to
inspect, not permission to delete by address.

For a loop that should stop on a bounded occurrence, use
`breakpoints.conditional.set` with a `hit_count` predicate and retain its returned
`managed_id`. `fast_resume` skips nonmatching hits without creating MCP pause events. Register
predicates use only the portable `cax` through `cip` names, and thread predicates use an exact ID
copied from `threads.list`. List and remove the exact managed breakpoint after the intended pause.

For exception triage, use `breakpoints.exception.set` with one canonical code and an explicit
chance. After resume, validate `pause_reason.kind == "exception"`, the observed code, actual
`first_chance`, and instruction pointer before inspecting state. Remove with the same code, chance,
and returned `managed_id`; configured `both` never means the caller may infer which chance occurred.

If the plugin reports draining, cancelled, or unavailable, stop issuing work and let debugger
shutdown finish.

## Bounded address trace

1. Confirm an actionable pause and retain the current backend instance ID.
2. Start `trace.start` with `into` to observe calls or `over` to omit their
   interiors. Keep both the step cap and timeout proportional to the question.
3. Preserve the returned trace ID. If start reports `starting` or `running`, use
   the normal pause-observation workflow or query `trace.status`; do not submit a
   second trace.
4. Accept only an explicit terminal reason. `max_steps` means normal bounded
   completion; `breakpoint`, `exception`, `user_pause`, `process_exit`, timeout,
   cancellation, and backend shutdown are distinct incomplete outcomes.
5. Page `trace.results` with the exact ID and cursor. Module/RVA fields use the
   immutable start-time module snapshot, while absolute addresses are the actual
   observed CIPs. Restart neither a stale cursor nor a mutation under a new ID.
6. If cancellation is needed, call `trace.cancel` once with the active trace ID,
   current instance ID, and one operation ID. An unknown cancellation outcome is
   state to inspect, not permission to start another trace.

The backend retains only the latest terminal trace and at most 4,097 addresses.
Use smaller traces around known code instead of treating this as whole-program
coverage or as x64dbg's file-backed run trace.

## Assembly and reversible patches

1. Resolve a module/RVA and read the entire instruction to be replaced.
2. Call `assembly.preview` at that same structured address. Preview is read-only.
3. After explicit mutation authorization, call `assembly.patch` with the exact original bytes,
   one instruction, `fill_nop`, and a fresh operation UUID.
4. Preserve the returned `patched_bytes_hex` and `original_bytes_hex`. Do not layer another patch
   over that range.
5. To undo it, call `patches.restore` with those exact strings and a different operation UUID.
6. Re-read memory before executing restored code. Treat any conflict or unknown outcome as a state
   to inspect, never as permission for a second write.

Both mutation tools are limited to 16 bytes. They reject stale memory, hidden patch records,
no-op patches, multi-command text, and unsafe address-only restore.

## Breakpoint and pause loop

When the goal is simply to continue to one address, prefer
`debugger.run_to_address` with module/RVA, the current instance ID, one fresh
operation ID, and a bounded timeout. It atomically owns and cleans its temporary
single-shot breakpoint. Check `completed`; an intervening caller breakpoint,
exception, user pause, process exit, or timeout is a valid incomplete result to
inspect, not permission to resubmit execution blindly.

Use the explicit sequence below when the breakpoint must intentionally remain
installed or when the workflow needs separate observation between operations.

1. Identify the loaded module with `modules.list`. Prefer a stable module/RVA reference.
2. If needed, inspect it with `address.resolve`; do not manually add the ASLR base.
3. With explicit mutation authority, call `breakpoints.set` using the current instance UUID and a
   new operation UUID.
4. Call `debugger.resume` using the same instance UUID and a different new operation UUID; retain
   its returned generation.
5. Call `debugger.wait_for_pause` with `after_generation` equal to the resume generation.
6. Confirm the pause kind and verify the pause address or instruction pointer matches the intended
   breakpoint. Loader/system/exception pauses may need another explicit resume cycle.
7. Collect bounded reads while the returned generation remains current. Remove the breakpoint or
   stop only when separately authorized.

Observation timeout is read-only and may be retried with the same `after_generation`. A mutation
timeout is different: its outcome may be unknown and must not be resubmitted under a new ID.

## Compact paused inspection

Start with `debugger.snapshot` for a bounded register/IP/disassembly view, or use
`registers.read` and `disassembly.read` separately when their independent controls matter. Use
small `memory.read` calls for concrete addresses. Add paginated
`modules.list`, `threads.list`, or `breakpoints.list` only when the task needs them. Keep
`memory.map` only when needed, using module/committed/executable filters plus a modest page size;
it is not part of the default compact snapshot.

All related results should retain the same `state_generation`. If a call returns `BUSY`, discard
the partial logical snapshot and collect a new one after confirming the current pause.

For a multithreaded pause, call `threads.list`, retain its current TID, and pass
one exact listed non-current `thread_id` to `registers.read` or
`debugger.snapshot`. Require the result's `thread_id` to match and `current` to
be false. In a compact snapshot, `active_thread_id` remains the selected TID,
but registers, instruction pointer, and disassembly belong to the requested
thread. Re-list threads if the operation reports `BUSY`; never switch or
suspend a thread merely to inspect this bounded context.

## Discovery

Use module-scoped literal filters and modest page limits:

- `symbols.search` for retained exports, imports, labels, and symbols;
- `functions.list` for functions already analyzed by x64dbg;
- `strings.search` for bounded ASCII/UTF-8 or UTF-16LE candidates. Supply a literal `query` and
  usually `context_bytes=32` to keep `before`/`match`/`after` compact; follow `next_cursor` with
  the exact same context setting when necessary;
- `memory.search` for machine-code signatures, binary constants, magic bytes,
  or runtime-decrypted markers. Use one module or an exact start/length scope,
  lowercase `pattern_hex`, and one `x` or `?` per byte in `mask`; follow its
  cursor only with identical filters;
- `references.to` for inbound references already in the analysis database.
- `symbols.resolve` for an exact case-sensitive name in one module or an exact runtime address;
- `functions.at` for the already-known containing function at one address.

If a known concrete address is missing from function discovery and analysis is explicitly
authorized, call `analysis.function` once with module/RVA and a fresh operation UUID. Then query
`functions.list` again. Do not treat empty discovery as permission to analyze, do not request
GUI-selection-based whole-module analysis, and preserve the operation ID after an ambiguous result.

Cursors bind the method, exact filters, module spelling, and debugger generation. Reuse the exact
arguments on the next page. Restart discovery after `STALE_CURSOR`; do not merge pages from
different generations.

## Call stacks and tracked patches

Use `callstack.read` while paused. Omit `thread_id` for the active thread or copy an exact ID from
`threads.list`; keep `limit` modest. `native_bounded` means x64dbg returned native unwind frames,
while `inconclusive` means the native API returned none—not proof that no caller exists.

Use `patches.list` to inspect x64dbg-tracked modifications as adjacent ranges. Compare
`current_matches_patch` before relying on metadata, and preserve the exact module filter when
following `next_cursor`. Its cursor binds the full patch snapshot even when debugger generation
does not change; `STALE_CURSOR` means restart enumeration and never merge the old pages.

## Go binaries

Search retained symbols for `main.main` and other `main.` names, but tolerate an empty known-only
database. Prefer a verified `main.main` module/RVA breakpoint over stepping through the PE and Go
runtime startup path. Go's register ABI varies by architecture and compiler version, so validate
argument assumptions against nearby disassembly and live registers instead of applying a fixed
calling-convention recipe.
