# ADR 0031: Bounded loaded-section metadata

Status: Accepted on 2026-08-30.

## Context

`modules.list` reports image base, size, entry point, name, and path.
`memory.map` reports virtual-memory allocation and protection regions. Neither
contract identifies the named PE sections as they exist in the loaded image, so
agents must otherwise infer `.text` and data boundaries from coarser allocation
metadata or perform redundant file parsing outside the debugger.

The pinned x64dbg SDK exposes `Script::Module::SectionListFromAddr` and transfers
ownership of a `ListInfo` containing `ModuleSectionInfo { addr, size, name }` to
the caller. It does not expose section characteristics, raw-file offsets, or
on-disk sizes through this API.

## Decision

Add one paused-state, read-only backend-local tool:

```text
sections.list(module, query?, limit?, cursor?)
```

`module` is the same exact case-insensitive, uniquely loaded module selector used
by linkage and discovery tools. `query` is an optional literal section-name
substring of at most 128 UTF-8 bytes. `limit` defaults to 100 and is 1 through
256. The opaque cursor is bound to the debugger generation, module, and literal
query.

The plugin first captures the bounded module list, resolves exactly one module,
and revalidates its base and size with `Script::Module::InfoFromAddr`. It then
calls `SectionListFromAddr` on the serialized debugger executor. The native
section count must be 0 through 4,096, agree with the revalidated module's
nonnegative `sectionCount`, have exact `ListInfo` byte size and ownership shape,
and remain within the loaded module without address overflow. Every fixed section
name must be terminated and valid UTF-8. The owned list is released with
`BridgeFree` in the same work item.

Each result item contains the stable native index, nullable name, structured
runtime start location, hexadecimal size, and hexadecimal exclusive end. The
response also contains native and matched counts, an optional continuation
cursor, `completeness: "loaded_image_sections"`, and the state generation. SDK
order is preserved. The generation is rechecked after all copying/filtering and
before a cursor is returned; churn yields retryable `BUSY` and an old cursor
yields `STALE_CURSOR`.

The backend will not claim section characteristics, permissions, raw offsets,
raw sizes, hashes, or on-disk provenance because this SDK call does not provide
them. Clients may correlate a returned span with `memory.map` when current page
protection is required.

## Verification

Contract tests cover module/query/page bounds, unknown fields, and catalog
annotations. Native x32/x64 builds exercise ownership and count validation.
Fresh isolated debugger runs page the fixture sections, verify `.text` contains
the exported analysis target, bind a cursor to its literal filter, and retain
the same generation as the surrounding module snapshot. Shutdown qualification
continues to prove that no section allocation or request survives plugin unload.

## Consequences

Agents gain ASLR-correct named section boundaries without conflating PE sections
with memory regions or adding an arbitrary file parser. The view is deliberately
limited to metadata returned by the loaded debugger image and is not a substitute
for static PE-header analysis.
