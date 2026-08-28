# x64dbg MCP recipes

## State routing

| Debuggee state | Useful next actions | Avoid |
|---|---|---|
| `absent` | Explicitly request `debuggee.launch` if authorized | Reads that require a target; starting a separate sidecar |
| `starting` | Wait for the launch mutation's callback confirmation | A second launch or speculative resume |
| `paused` | Resolve addresses; inspect; set/remove breakpoints; step or resume if authorized | Large unfiltered reads |
| `running` | Use `debugger.wait_for_pause` after a known resume generation, or explicitly pause | Register/memory/disassembly reads; polling loops |
| `stopping` / `exited` | Re-read `debugger.state` and wait for bounded teardown | Retrying stop with a new operation ID |

If the plugin reports draining, cancelled, or unavailable, stop issuing work and let debugger
shutdown finish.

## Breakpoint and pause loop

1. Identify the loaded module with `modules.list`. Prefer a stable module/RVA reference.
2. If needed, inspect it with `address.resolve`; do not manually add the ASLR base.
3. With explicit mutation authority, call `breakpoints.set` using a new operation UUID.
4. Call `debugger.resume` using a different new operation UUID and retain its returned generation.
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

## Discovery

Use module-scoped literal filters and modest page limits:

- `symbols.search` for retained exports, imports, labels, and symbols;
- `functions.list` for functions already analyzed by x64dbg;
- `strings.search` for bounded ASCII/UTF-8 or UTF-16LE candidates, following `next_cursor` across
  the module when necessary;
- `references.to` for inbound references already in the analysis database.

Cursors bind the method, exact filters, module spelling, and debugger generation. Reuse the exact
arguments on the next page. Restart discovery after `STALE_CURSOR`; do not merge pages from
different generations.

## Go binaries

Search retained symbols for `main.main` and other `main.` names, but tolerate an empty known-only
database. Prefer a verified `main.main` module/RVA breakpoint over stepping through the PE and Go
runtime startup path. Go's register ABI varies by architecture and compiler version, so validate
argument assumptions against nearby disassembly and live registers instead of applying a fixed
calling-convention recipe.
