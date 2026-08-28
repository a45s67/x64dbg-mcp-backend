# ADR 0006: Native UTF-8 boundary

## Status

Accepted before implementation on 2026-08-29.

## Context

The Rust HTTP server and Jansson request parser accept JSON strings as UTF-8, while x64dbg's
plugin SDK exposes much of its display text through fixed-size `char` buffers. Passing those
buffers through unchanged can emit invalid JSON and terminate the framed IPC connection. The
existing JSON helper also discarded an entire string when it encountered one control byte, and
module-relative address lookup used the locale-dependent `_stricmp` byte comparison.

The boundary must preserve valid debugger text, remain bounded, and never allow malformed native
text to corrupt transport framing. Windows module names also need deterministic Unicode-aware,
case-insensitive matching.

## Decision

- JSON received from the server remains strict UTF-8. Text sent to native APIs must also reject
  embedded control characters where the native API would otherwise truncate or reinterpret it.
- SDK fixed buffers are copied only through their declared bound and their first NUL byte.
- SDK `char` text is treated as UTF-8, matching the x64dbg Bridge convention. Valid UTF-8 is
  preserved. Each byte that cannot begin a valid UTF-8 scalar sequence is replaced with U+FFFD.
  Overlong forms, UTF-16 surrogate encodings, truncated sequences, and values above U+10FFFF are
  invalid.
- JSON escaping is performed after validation. Quotes, reverse solidus, and ASCII controls are
  escaped; a control byte never discards surrounding text.
- Module identity comparison converts valid UTF-8 to UTF-16 with
  `MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, ...)`, then uses
  `CompareStringOrdinal(..., TRUE)`. Invalid native module names remain safely printable through
  replacement but do not match an address reference.
- Conversion and escaping allocate only from already bounded request/SDK inputs and remain under
  the existing 1 MiB IPC response bound. No locale or active-code-page conversion is used.

## Consequences

Unicode executable paths and module-relative references behave consistently on x32dbg and
x64dbg. Malformed plugin SDK text is visible as replacement characters rather than causing an
invalid response or disconnect. Replacement is intentionally lossy, so malformed names cannot be
used as module identities.

## Verification

Native unit vectors cover multibyte and supplementary scalars, JSON metacharacters and controls,
overlong forms, isolated continuation bytes, surrogate encodings, and truncated sequences. The
real integration suite launches an executable with a Unicode filename and resolves its module
using a differently cased Unicode name on both architectures. The installed release is also
validated with a Flare-On sample copied to a Unicode path.

On 2026-08-29 both isolated architectures completed that suite with
`München-分析.exe`; the returned module was `münchen-分析.exe` and its uppercase
reference resolved correctly. The installed x64 release then loaded
`Flare-驗證-native-utf8/München-checksum.exe`, resolved
`{module: "MÜNCHEN-CHECKSUM.EXE", rva: "0xa78a0"}` at runtime base `0x290000`,
hit the software breakpoint at `0x3378a0` once, returned register/memory/disassembly generation
`28`, and stopped cleanly.
