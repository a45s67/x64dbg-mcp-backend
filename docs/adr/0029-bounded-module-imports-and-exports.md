# ADR 0029: Bounded module imports and exports

Status: Accepted on 2026-08-30.

## Context

Dynamic analysis frequently needs an executable's imported capabilities, IAT
slots, exported entry points, ordinals, and forwarded exports. The existing
`symbols.search` view cannot answer these precisely: it does not expose IAT
locations, import-by-ordinal identity, export ordinals, or forwarder strings.

The pinned x64dbg SDK provides `Script::Module::GetImports` and `GetExports`.
Both return caller-owned `ListInfo` allocations. `ModuleImport` contains the IAT
RVA/VA, name, undecorated name, and ordinal sentinel, but not the original PE
import-descriptor DLL name. `ModuleExport` contains RVA/VA, ordinal, names, and
forwarder metadata.

## Decision

Admit two paused-state, read-only tools:

```text
imports.list(module, query?, limit?, cursor?)
exports.list(module, query?, limit?, cursor?)
```

`module` is required and resolves case-insensitively to exactly one loaded
module. `query` is an optional literal UTF-8 substring of at most 128 bytes.
`limit` defaults to 100 and is bounded to 1 through 256. A cursor is opaque,
tool-specific, bound to the module/query/limit filters and debugger generation,
and resumes at one native-list index. Filter changes are `INVALID_ARGUMENT`;
generation changes are `STALE_CURSOR`.

Both native lists reject a negative count, a count above 65,536, a null pointer
for a non-empty list, or an element-size mismatch before iteration. Strings use
their fixed SDK capacities, must contain a terminator, and must be valid UTF-8.
Every list is released with `BridgeFree` in the same serialized executor work
item, including error paths. Deadline and generation checks occur during
enumeration and immediately before returning a cursor.

An import item contains its name and undecorated name when present, an ordinal
only for import-by-ordinal, and a structured IAT location. For at most the
returned page, the plugin may read one architecture-width IAT pointer. A
readable nonzero pointer is returned as `resolved_target`; loaded-module/RVA
metadata is attached when uniquely known. An unreadable or unresolved slot is
explicit and is not an error. The tool does not claim an original provider DLL
because the admitted SDK record does not contain one.

An export item contains ordinal, name and undecorated name when present,
structured location, `forwarded`, and `forward_name` only when the SDK marks the
entry forwarded. Forwarder text is metadata and is never evaluated or followed
as an expression.

Both responses include `known_only`, `state_generation`, native and matched
counts, returned items, and an optional next cursor. They do not trigger symbol
downloads, module analysis, IAT reconstruction, or debugger commands.

## Verification

Contract tests cover exact schemas, unknown fields, bounds, and cursor shapes.
Native tests and isolated x32/x64 fixtures cover ownership, empty lists,
name/ordinal imports, named/ordinal/forwarded exports where present, one-item
pagination, filter binding, generation churn, pointer-width IAT reads, and
output limits. A Flare-On sample verifies useful module-scoped output without
depending on a fixed ASLR base.

## Consequences

The backend gains precise PE linkage views without exposing a raw PE parser or
duplicating generic symbol search. Original import-descriptor library names are
intentionally absent until a bounded native source is admitted. Runtime IAT
targets are observations, not proof of the original file's import mapping.
