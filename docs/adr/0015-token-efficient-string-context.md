# ADR 0015: Token-efficient string match context

Status: Accepted before implementation on 2026-08-29.

## Context

`strings.search` bounds every returned candidate to 512 UTF-8 bytes and keeps the
literal match visible. That is safe, but compiler/runtime string pools often join
many unrelated literals into one printable candidate. A short query can therefore
consume hundreds of unnecessary response bytes and model tokens.

Changing the scanner to split candidates heuristically would make addresses and
byte lengths inaccurate. Removing the existing `text`, `match_offset`, or
`text_offset` fields would also break clients that already use their relationship.

## Decision

Add optional `context_bytes` to `strings.search`:

- it is an integer from 0 through 128 and defaults to 64 when `query` is present;
- it is rejected when `query` is absent, because unfiltered enumeration has no
  match around which to select context;
- it limits each side of the literal match independently, never splits a UTF-8
  sequence, and does not change the candidate's address or `byte_length`;
- the returned `text` remains `before + match + after`; ordinary byte-identical
  matches remain at most 512 bytes, while Unicode case-equivalent spans have a
  defensive 1,024-byte match cap and 1,280-byte aggregate cap;
- every queried result additionally returns `before`, `match`, and `after` so a
  client need not repeat offset arithmetic or resend the full preview to a model;
- existing `match_offset`, `text_offset`, and `truncated` fields remain; and
- the opaque cursor fingerprint includes `context_bytes`, so changing it while
  paging returns `INVALID_ARGUMENT` instead of mixing representations.

When `query` is omitted, extraction retains the existing first-512-byte preview
behavior and does not emit misleading match components. Search matching remains
Windows invariant, case-insensitive, and literal rather than regex based. The
matched byte span is obtained from the same Windows NLS operation as its offset,
so Unicode case folding does not assume the query and candidate have equal UTF-8
lengths.

Because `context_bytes` changes the accepted MCP input contract, the backend
package and the independently versioned workflow skill both advance to 0.2.0;
the skill declares backend 0.2.0 as its minimum compatible version.

## Bounds and errors

- `context_bytes`: 0 through 128; default 64 only for queried searches.
- `before` and `after`: at most the requested byte count and valid UTF-8.
- `match`: valid UTF-8 with a defensive 1,024-byte cap. Windows case folding can
  match a differently encoded candidate span, so its byte length is not assumed
  to equal the 256-byte query bound.
- `text`: at most 1,280 bytes and valid UTF-8; byte-identical matches remain at
  most 512 bytes.
- Unknown fields, a non-integer value, an out-of-range value, or supplying
  `context_bytes` without `query` returns `INVALID_ARGUMENT` before native work.

## Consequences

- Default queried results become substantially smaller while preserving exact
  candidate location and size metadata.
- A caller that wants the previous large preview can request 128 bytes on each
  side; unfiltered enumeration is unchanged.
- Result objects gain fields but tool naming, mutation behavior, and Gateway
  namespace behavior do not change.

## Verification

- Rust schema/validator tests cover defaults, bounds, query coupling, strict
  fields, cursor binding, and generated malformed arguments.
- Native UTF-8 tests cover ASCII, multibyte boundary trimming, Unicode
  case-insensitive match spans, zero context, and the 512-byte aggregate bound.
- Isolated x32dbg/x64dbg integration verifies compact ASCII and UTF-16LE results,
  exact reconstruction, filter-bound cursors, and unchanged generation metadata.
- The installed Flare-On qualification compares response size and match visibility
  for the existing `checksum.exe` literals.
