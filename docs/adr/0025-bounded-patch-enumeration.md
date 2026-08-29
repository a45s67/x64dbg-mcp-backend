# ADR 0025: Enumerate tracked patches as bounded ranges

Status: Accepted on 2026-08-29.

## Context

The backend can create and restore verified patches but cannot inspect all patch
records without knowing their addresses. The SDK exposes `PatchEnum` as an
unordered collection of one-byte `DBGPATCHINFO` records. Its size probe reports
bytes, and the implementation remembers the probed record limit by calling OS
thread until the following enumeration call. Patch records can change without a
debuggee callback generation transition.

## Decision

Add the read-only backend-local tool:

```text
patches.list(module?, limit?, cursor?)
```

It is valid only while paused. `module` is an optional exact case-insensitive
loaded-module name. `limit` defaults to 100 and is restricted to 1-256. The
opaque cursor is at most 512 bytes and binds method, exact filter, debugger
generation, a fingerprint of the complete sorted patch snapshot, and range
index.

The serialized executor performs the size probe and enumeration on the same OS
thread, as required by the SDK implementation. It rejects a byte size not
divisible by `sizeof(DBGPATCHINFO)`, arithmetic overflow, or more than 65,536
records before allocation. The vector is zero-initialized. A third size probe
must equal the first; a changed count or any zero/invalid record returns retryable
`BUSY` and no page. Every record must name one uniquely loaded module, resolve
inside that module, contain different original and patched bytes, and survive the
final debugger-generation check.

Records are sorted by absolute address and adjacent records in the same module
are merged. Each returned range contains structured `start`, `length`,
`original_bytes_hex`, `patched_bytes_hex`, `current_bytes_hex`, and
`current_matches_patch`. Current bytes are read with bounded `DbgMemRead`; no
restore or write occurs. At most 65,536 current bytes are read per request.

The result contains `items`, `next_cursor`, `completeness: "tracked_only"`,
`snapshot_fingerprint`, and `state_generation`. Every page re-enumerates and
recomputes the snapshot fingerprint; a changed fingerprint or generation returns
`STALE_CURSOR` rather than merging different patch databases. A module with no
tracked records is a complete empty tracked-only result, not proof that process
memory equals the original file.

## Errors and verification

Stable failures are `INVALID_ARGUMENT`, `INVALID_DEBUGGER_STATE`, `NOT_FOUND`,
`STALE_CURSOR`, `BUSY`, `TIMEOUT`, `OUTPUT_LIMIT_EXCEEDED`, `CANCELLED`, and
`INTERNAL`. The tool is read-only and takes no operation ID.

Pure native tests cover byte/count interpretation, overflow, probe/enumeration
churn, zero-initialized tails, unordered merge behavior, cursor fingerprints,
module filtering, and 65,536-record bounds. Contract and real x32/x64 tests cover
empty, one range, disjoint ranges, current-byte mismatch, pagination, stale
cursors, shutdown, and a reversible authorized sample patch.

## Consequences

Patch inspection becomes composable with verified restore without exposing the
SDK's byte-record ordering. Pagination is tied to actual patch content instead
of debugger generation alone, so database-only changes cannot silently corrupt a
multi-page view.
