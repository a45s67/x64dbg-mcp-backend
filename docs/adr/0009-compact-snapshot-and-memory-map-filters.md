# ADR 0009: Compact paused snapshot and memory-map filters

## Status

Accepted before implementation on 2026-08-29.

## Context

The checksum workflow needed separate state, register, module, and disassembly calls to answer the
common question "where is the paused thread and what is around it?" Parallel requests are safe,
but each captures independently and produces more client/tool context than one compact native
snapshot. Conversely, an unfiltered memory map mixes the target image with heaps, system images,
reserved ranges, and other allocations; pagination bounds response size but does not make the
first pages relevant.

These are read usability problems. They must not introduce implicit analysis, hidden execution,
arbitrary expressions, unbounded collection, or mixed debugger generations.

## Decision

Add one paused-state read tool:

```text
debugger.snapshot(registers?, disassembly_count?)
```

`registers` is an optional unique array of 1 through 16 names from the existing architecture-aware
register allowlist. The default is the portable set `cip`, `csp`, `cbp`, and `eflags`.
`disassembly_count` is 0 through 64 and defaults to 8. A zero count explicitly omits instruction
decoding.

The result contains the retained structured pause reason, active thread ID, instruction-pointer
location (absolute plus module/RVA when available), requested registers, bounded disassembly from
the same IP, and one `state_generation`. It intentionally excludes memory maps, full module lists,
full thread lists, and breakpoint lists. Those already have paginated tools and would make the
"compact" contract data-dependent.

The plugin captures paused state and generation under the callback mutex, then copies the register
dump, module list, and at most 64 decoded instructions on the serialized debugger executor. It
rechecks the exact paused generation before returning. Any churn yields retryable `BUSY`; no
partial snapshot is returned.

Extend `memory.map` with optional filters:

- `module`: retain regions whose half-open address range overlaps the uniquely resolved loaded
  module image;
- `committed_only`: retain `MEM_COMMIT` regions;
- `executable_only`: retain Windows executable protection classes after masking protection
  modifiers;
- `compact`: omit empty `info` and omit `allocation_base` when it equals `base`.

All flags default to false, preserving existing unfiltered output. Filtering is literal and
read-only. It does not change page protection or trigger module analysis.

## Bounds and pagination

`memory.map` rejects native counts above 65,536, checks deadline and paused generation while
scanning, and emits at most the caller's existing 1-through-256 page limit. Pagination advances by
raw native index so filtered-out records cannot repeat. New v2 cursors bind generation, exact
module spelling, all filter flags, and next raw index. A changed filter is `INVALID_ARGUMENT`; a
changed generation is `STALE_CURSOR`. Pre-filter v1 cursors are intentionally not accepted because
they cannot prove filter identity.

Address-range overlap and all address additions are overflow-checked. The native `MEMMAP.page`
allocation remains owned by the Bridge and is released with `BridgeFree` on every path inside the
same executor work item.

## Rejected alternatives

- **Return every list in `debugger.snapshot`.** Makes a compact call unpredictably large and
  duplicates paginated contracts.
- **Include memory bytes or stack walking by default.** Adds address/range policy and failure modes
  unrelated to the common paused-location snapshot.
- **Filter after pagination.** Can return mostly empty pages and makes progress depend on client
  guesswork.
- **Use x64dbg UI memory-map text.** It is a mutable UI surface with unstable formatting.
- **Reuse v1 cursors with filters.** Allows a cursor to silently change meaning.

## Verification

- Rust schema/contract tests cover exact keys, boolean types, register/disassembly bounds, catalog
  annotations, filter-bound cursor forwarding, and the 25-tool catalog.
- Native tests cover protection classification and overflow-safe range overlap as pure helpers.
- Fresh isolated x32/x64 fixtures verify compact snapshot contents/generation, module and executable
  memory filters, compact shape, cursor mismatch/staleness, connection survival, and shutdown.
- The installed stage is exercised on a Flare-On sample at a module/RVA breakpoint and records the
  output reduction and generation consistency.
