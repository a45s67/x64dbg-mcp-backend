# ADR 0026: Resolve retained symbols exactly

Status: Accepted on 2026-08-29.

## Context

`symbols.search` is a paginated literal discovery view. Using it to resolve one
exact name or address is awkward and can hide duplicate or missing records.
Symbol lookup must remain module-scoped, bounded, and honest about x64dbg's
retained database; it must not download symbols or trigger analysis.

## Decision

Add the read-only backend-local tool `symbols.resolve` with exactly one input
shape:

```json
{"module":"sample.exe","name":"main"}
```

```json
{"address":{"module":"sample.exe","rva":"0x1000"}}
```

Names are 1-256 bytes of valid UTF-8 without control characters and match exact
case-sensitive bytes. Module matching is exact ordinal case-insensitive. Address
input uses the existing closed structured/absolute address reference and must
resolve into one loaded module.

The executor captures a paused generation, a bounded module snapshot, and
`Script::Symbol::GetList`. It releases the list with `BridgeFree`, rejects native
counts above 65,536 and size/count disagreement, and scans with deadline checks.
It does not call symbol download, autocomplete, arbitrary expression, or an
analysis command.

The result reports `resolution` as `found`, `missing`, or `ambiguous`; `matches`
contains at most 32 exact records with `name`, closed `type`
(`function|import|export`), `manual`, and structured `location`. It also returns
`total_matches`, `matches_truncated`, `completeness: "known_only"`, and
`state_generation`. Zero matches is a successful explicit missing result. More
than one exact record is ambiguous even if the addresses are equal; records are
not silently coalesced.

All matched RVAs must fit their uniquely loaded module and pointer width. The
generation is rechecked after collection. Duplicate, out-of-module, invalid UTF-8,
or unknown native symbol-type records fail closed instead of being relabeled.

## Errors and verification

Stable failures are `INVALID_ARGUMENT`, `INVALID_DEBUGGER_STATE`, `NOT_FOUND`
for an unloaded/ambiguous module or outside-module address, `BUSY`, `TIMEOUT`,
`OUTPUT_LIMIT_EXCEEDED`, `CANCELLED`, and `INTERNAL`. Missing retained symbols
are data, not an error. The tool takes no operation ID.

Tests cover the closed input union, case policy, missing/unique/duplicate records,
32-result truncation, malformed native lists, allocation release, deadline and
generation churn, x32/x64 pointer width, shutdown, and exact resolution on a real
sample. Empty known-only output must never be presented as binary-wide absence.

## Consequences

Clients can make deterministic exact-resolution decisions while preserving the
important difference between missing retained metadata and proof that a symbol
does not exist in the executable.
