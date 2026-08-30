# ADR 0035: Closed-schema conditional software breakpoints

Status: Implemented and qualified in 0.14.0 on 2026-08-31.

## Context

A software breakpoint that stops on every hit is noisy in loops, shared
functions, and multithreaded code. x64dbg supports a general expression
language for breakpoint conditions, but accepting that language would make the
backend an arbitrary expression surface and couple clients to architecture-
specific spelling and quoting. The backend can cover the common deterministic
cases with a small typed schema and compile it internally.

x64dbg evaluates the break condition after incrementing
`$breakpointcounter`; `tid()` identifies the hitting thread, and the portable
`CAX` through `CIP` register aliases map to the current x32 or x64 register
width. Its typed breakpoint API can set and read `bpf_breakcondition`,
`bpf_fastresume`, name, command, and logging fields without interpolating a
caller string into a debugger command.

## Decision

Add two paused-state mutations:

```text
breakpoints.conditional.set(address, condition, operation_id, instance_id)
breakpoints.conditional.remove(address, managed_id, operation_id, instance_id)
```

`address` uses the existing absolute/module-RVA union. `condition` contains
`mode: all|any` and one through four predicates. A predicate is exactly one of:

- `source: register`, register `cax|cbx|ccx|cdx|csi|cdi|cbp|csp|cip`, operator
  `eq|ne|lt|le|gt|ge`, and a canonical pointer-width hexadecimal value;
- `source: thread_id`, operator `eq|ne`, and a canonical 32-bit hexadecimal
  value; or
- `source: hit_count`, operator `eq|ne|lt|le|gt|ge|multiple_of`, and an integer
  from 1 through 4,294,967,295.

No strings, memory dereferences, functions other than the fixed `tid()`, nested
conditions, caller expressions, logging, or commands on hit are accepted. The
compiler emits a canonical expression of at most 255 bytes using only fixed
tokens, lowercase portable register aliases, `0x` constants, parentheses, and
`&&` or `||`. `multiple_of` emits a nonzero modulo divisor comparison. Native
policy tests treat this compiler output as a security and compatibility
boundary.

Set rejects any existing software breakpoint at the resolved address. It
creates one named breakpoint with a fixed name derived from the set operation
UUID, waits for the command fence, then uses `BP_REF` fields to assign the
compiled condition and enable fast resume. Exact read-back must confirm the
address, enabled and active software type, name, condition, fast-resume flag,
and empty command/logging fields. The result includes the UUID as `managed_id`,
the normalized structured condition, and the compiled expression for
diagnostics.

Remove requires the address and `managed_id`, and deletes only an exact
backend-named software breakpoint. Renaming transfers it out of backend
ownership and makes removal fail closed. Condition edits do not silently
transfer ownership, but the current bounded expression is returned by
`breakpoints.list` so the caller can see the modification before removal.

`breakpoints.list` adds bounded `condition_expression`, `fast_resume`, and
`managed_id` fields to software records. The managed ID is null for ordinary
user breakpoints. Managed breakpoints remain visible x64dbg database state
after disconnect or plugin unload; explicit typed removal is the cleanup rule.
The same operation ledger, compensating-delete restrictions, unknown-outcome
handling, and no-blind-retry policy from ADR 0034 apply.

## Verification

Contract tests cover the closed predicate union, count and value bounds,
architecture-neutral names, address identity, and mutation annotations. Native
tests cover canonical compilation, maximum expression size, width rejection,
name formatting, ownership, and exact read-back. The deterministic fixture's
repeated exported function proves a `hit_count == 2` breakpoint skips the first
hit, pauses on the second on both x32 and x64, reports hit count two, replays
without executing again, lists its managed identity, and removes exactly its
owned breakpoint. Shutdown and a non-resuming Flare-On set/list/remove smoke
remain mandatory.

## Consequences

The useful high-frequency cases become portable and composable without making
MCP clients quote x64dbg expressions. More elaborate string, memory, argument,
or exception predicates remain out of scope until a concrete workflow justifies
another closed predicate type. An arbitrary expression or breakpoint-command
escape hatch is not introduced.

Fresh isolated instances `f8edad8c-0cae-4c3b-a24e-42c8e4160a87` (x64) and
`96baf49c-d4ea-4f1a-8e23-00476f796968` (x32) both skipped the first fixture hit,
paused with hit count two, recovered the managed identity through listing,
refused a foreign removal, replayed exactly, and removed the owned record.
