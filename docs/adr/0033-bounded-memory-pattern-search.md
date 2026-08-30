# ADR 0033: Bounded runtime memory-pattern search

Status: Accepted before implementation on 2026-08-31.

## Context

`memory.read` is precise when the caller already knows an address, and
`strings.search` discovers text in one loaded module. Reverse-engineering
workflows also need to locate machine-code signatures, binary constants, file
magic, decrypted markers, and wildcarded instruction bytes in the current
runtime image. Repeated client-side `memory.read` calls can compose that search,
but they duplicate cross-page overlap, unreadable-range handling, cursor state,
and generation checks and can accidentally grow into an unbounded loop.

A whole-process scan, x64dbg pattern command string, or server-side dump is not
acceptable. The operation must remain a read-only observation over one explicit
bounded scope and must not silently analyze code or create an artifact.

## Decision

Add one backend-local read tool:

```text
memory.search(scope, pattern_hex, mask, limit?, cursor?)
```

`scope` is exactly one of:

```json
{"module":"sample.exe"}
```

or:

```json
{"start":{"module":"sample.exe","rva":"0x1000"},"length":65536}
```

An absolute `AddressRef` is also valid for `start`.

- `pattern_hex` is 1 to 64 bytes encoded as canonical lowercase hexadecimal.
- `mask` is required, has one character per pattern byte, and contains only
  `x` for an exact byte or `?` for a wildcard byte. An all-wildcard mask is
  rejected because every candidate address would match without conveying a
  searched value.
- A module scope resolves one exact loaded module and rejects an image above
  128 MiB. A range scope has a length from 1 byte through 16 MiB and rejects
  pointer overflow. Resolution and the scan execute in the same serialized
  debugger work item.
- One request evaluates at most 1 MiB of candidate start positions and returns
  at most 256 matches. A scan window may read at most 63 additional trailing
  bytes so a 64-byte pattern can be evaluated at the window boundary.
- Native memory is read in bounded page-sized chunks with deadline checks.
  Pattern matching may cross adjacent readable chunks but never crosses an
  unreadable gap. The result reports evaluated candidate bytes and skipped
  unreadable bytes instead of treating skipped memory as zero-filled data.
- Match addresses are returned in ascending order as canonical absolute and
  module/RVA-aware locations when known. Overlapping matches are retained.
- `next_cursor` identifies the next candidate offset, not a result index. It is
  bound to debugger generation, scope, pattern, mask, and result limit. Reusing
  it with changed filters is rejected; generation churn is `STALE_CURSOR`.
- The result reports `scan_complete`, `completeness` (`complete` or
  `partial_unreadable`), `bytes_scanned`, `unreadable_bytes`,
  `state_generation`, bounded `items`, and nullable `next_cursor`. A non-null
  cursor means more of the declared scope remains even if the current page has
  no matches.

The tool is read-only and carries no `instance_id` or `operation_id`. It does
not invoke an x64dbg command, update the analysis database, write memory, create
a file, or retry a mutation.

## Native execution and ownership

The plugin uses its existing serialized debugger executor, structured address
resolver, loaded-module snapshot, `DbgMemRead`, generation tracker, and request
deadline. The scan owns only bounded vectors for one window, its readable map,
and at most 257 candidate matches (one look-ahead item to determine paging).
Every allocation is derived from the fixed window and pattern caps rather than
an unchecked SDK count or target-controlled PE field.

The generation is captured before scope resolution and checked after native
reads and matching. Debugger stop, resume, disconnect, or plugin draining wakes
or terminates the request through the existing executor and HTTP shutdown
deadlines. No worker, scan thread, snapshot cache, or server-side result store is
introduced.

## Rejected alternatives

- **Expose x64dbg's pattern command.** It reopens command syntax, output parsing,
  selection, and completion ambiguity without improving the typed result.
- **Scan all process memory.** The address space, native calls, output, and
  privacy boundary are not acceptably bounded.
- **Return a memory dump for client-side search.** This adds artifact transfer
  and path ownership that the product explicitly excludes.
- **Only document a Python loop over `memory.read`.** That remains available for
  unusual workflows, but a common search deserves one consistent overlap,
  unreadable-range, deadline, cursor, and generation contract.
- **Cache all matches before pagination.** It creates a long-lived result store
  and an allocation proportional to target contents. Cursor continuation
  rescans only from the next bounded candidate offset.

## Verification

- Rust schema and deterministic argument-corpus tests cover both scope forms,
  strict fields, canonical hex, mask length/alphabet, all-wildcard rejection,
  range and page limits, and filter-bound cursors.
- Pure native policy tests cover exact, wildcard, overlapping, chunk-boundary,
  unreadable-gap, cursor-offset, result-cap, and pointer-overflow behavior.
- Isolated x32dbg and x64dbg fixtures search module and explicit ranges, reject
  changed-filter and stale cursors, preserve the paused generation, and prove
  clean debugger/sidecar/listener shutdown.
- A suitable Flare-On sample searches a known runtime byte sequence by
  module/RVA without resuming challenge code and records ASLR-correct evidence.
- The package gate, managed skill contract, native API audit, MCP catalog, and
  public design documentation advance together before release.
