# ADR 0007: Bounded reverse-engineering discovery tools

## Status

Accepted before implementation on 2026-08-29.

## Context

The primitive debugger tools can inspect a known address, but they cannot discover retained
symbols, analyzed functions, embedded strings, or analysis-database references. This forced the
checksum workflow to obtain `main.main` and interesting constants from another disassembler.

x64dbg exposes symbol and function database lists and inbound xrefs, but no read-only API that
enumerates all strings or outgoing xrefs. Some Bridge list APIs allocate the complete native list
before the plugin can page it. Discovery therefore needs explicit native-count, scan-byte,
iteration, response, snapshot, and deadline bounds; a UI search command or reference view is not a
stable machine contract.

## Decision

The first discovery catalog adds four paused-state, read-only tools:

- `symbols.search(module, query?, limit?, cursor?)` searches x64dbg's current symbol database.
- `functions.list(module, query?, limit?, cursor?)` searches x64dbg's current analyzed-function
  database and attaches an exact-start symbol name when one exists.
- `strings.search(module, query?, min_length?, encoding?, limit?, cursor?)` incrementally scans
  readable bytes in one loaded image for bounded ASCII/UTF-8 and UTF-16LE candidates.
- `references.to(address, limit?, cursor?)` returns inbound references already present in
  x64dbg's analysis database.

`module` is required for list/scan operations. It uses the same Unicode ordinal identity and
unique loaded-module resolution as `AddressRef`. `query` is a case-insensitive literal substring,
not a regex or wildcard. `encoding` is one of `ascii_utf8`, `utf16le`, or `both`.
For `ascii_utf8`, invalid UTF-8 bytes terminate a candidate rather than poisoning adjacent valid
text, and `min_length` counts decoded Unicode scalar values. For `utf16le`, it counts UTF-16 code
units.

All results carry `state_generation` and structured absolute plus module/RVA locations. Symbols
include name, type (`function`, `import`, or `export`), and manual status. Functions include start,
end-inclusive, instruction count, manual status, and nullable name. Strings include address,
bounded text, byte length, encoding, the match's byte offset in the full candidate, and the
returned context's byte offset. Long strings return UTF-8-safe context around the literal match,
so the result does not hide a match beyond the first 512 bytes. References include source
location and type (`data`, `jump`, or `call`) plus the target location.

The tools expose `completeness: "known_only"`: they read current x64dbg analysis state and never
silently run analysis or mutate the database. An empty result does not prove that the binary has
no symbol, string, function, or reference.

## Bounds and pagination

- Request `limit` is 1 through 256 and defaults to 100. Query text is at most 256 UTF-8 bytes;
  string `min_length` is 4 through 256.
- Native symbol, function, and xref counts above 65,536 fail with
  `OUTPUT_LIMIT_EXCEEDED` after ownership is safely released. At most 65,536 native records are
  inspected in one request.
- One strings request reads at most 1 MiB of module bytes in chunks no larger than 64 KiB. A
  candidate is truncated to 512 UTF-8 bytes and marked truncated. Unreadable regions are skipped
  in bounded page increments and reported through `incomplete: true`.
- Loops check the request deadline and snapshot generation between chunks. Deadline expiry returns
  retryable `TIMEOUT`; generation churn returns retryable `BUSY`. Neither condition is retried
  internally.
- Opaque discovery cursors bind the debugger generation, method, exact supplied filters, module, and
  next native index/byte offset. A cursor used with different arguments is `INVALID_ARGUMENT`; a
  generation change is `STALE_CURSOR`.
- Native list pointers and xref arrays are always released with `BridgeFree` in the same serialized
  executor work item, including every error path.

## Rejected alternatives

- Debugger search commands and GUI reference tables have global UI side effects, unstable text
  formats, and ambiguous completion, so they are not used as an MCP data plane.
- Unbounded whole-image string extraction can monopolize the debugger thread and exceed IPC
  output limits.
- `references.from` would require a full-module instruction/database scan because this SDK exposes
  only inbound lookup. It is deferred until a precise bounded index is available.
- Automatically invoking analysis would turn these read tools into hidden mutations.

## Verification

Rust unit and contract tests cover schemas, strict argument bounds, response limits, and stable
discovery error forwarding. Native UTF-8 tests cover ordinal Unicode matching and byte offsets.
Isolated x32/x64 fixtures verify symbols, ASCII/UTF-8 and UTF-16LE strings, filter-bound and stale
cursors, snapshot generation, known-only metadata, empty database behavior, connection survival,
step/pause lifecycle, and clean shutdown. Native count rejection, allocation release, deadline,
unreadable-page, and context-truncation branches are enforced in code and remain candidates for a
future injectable Bridge seam. Each installed feature stage is additionally tested on a Flare-On
11 sample, preferring `checksum.exe` for retained Go names and embedded strings.
