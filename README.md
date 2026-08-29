# x64dbg MCP Backend

An independently usable Streamable HTTP MCP backend for x64dbg and x32dbg,
designed for direct MCP clients and the Dynamic Analysis Gateway.

The MVP consists of one statically linked Rust HTTP sidecar shared by two
architecture-specific native plugins. The plugin starts and owns the sidecar;
users normally launch only x32dbg or x64dbg. Durable decisions are recorded in:

- [`docs/adr/0001-mvp-architecture.md`](docs/adr/0001-mvp-architecture.md)
- [`docs/adr/0002-debuggee-launch.md`](docs/adr/0002-debuggee-launch.md)
- [`docs/adr/0003-structured-address-references.md`](docs/adr/0003-structured-address-references.md)
- [`docs/adr/0004-callback-pause-observation.md`](docs/adr/0004-callback-pause-observation.md)
- [`docs/adr/0005-generation-consistent-snapshots.md`](docs/adr/0005-generation-consistent-snapshots.md)
- [`docs/adr/0006-native-utf8-boundary.md`](docs/adr/0006-native-utf8-boundary.md)
- [`docs/adr/0007-bounded-discovery-tools.md`](docs/adr/0007-bounded-discovery-tools.md)
- [`docs/adr/0008-versioned-codex-workflow-skill.md`](docs/adr/0008-versioned-codex-workflow-skill.md)
- [`docs/adr/0009-compact-snapshot-and-memory-map-filters.md`](docs/adr/0009-compact-snapshot-and-memory-map-filters.md)
- [`docs/adr/0010-bounded-actionable-diagnostics.md`](docs/adr/0010-bounded-actionable-diagnostics.md)
- [`docs/adr/0011-bounded-shutdown-matrix.md`](docs/adr/0011-bounded-shutdown-matrix.md)
- [`docs/adr/0012-deterministic-robustness-corpus.md`](docs/adr/0012-deterministic-robustness-corpus.md)
- [`docs/adr/0013-idempotent-install-and-package-verification.md`](docs/adr/0013-idempotent-install-and-package-verification.md)
- [`docs/adr/0014-release-acceptance-gates.md`](docs/adr/0014-release-acceptance-gates.md)
- [`docs/adr/0015-token-efficient-string-context.md`](docs/adr/0015-token-efficient-string-context.md)
- [`docs/adr/0016-explicit-function-analysis.md`](docs/adr/0016-explicit-function-analysis.md)
- [`docs/adr/0017-attach-and-detach-lifecycle.md`](docs/adr/0017-attach-and-detach-lifecycle.md)
- [`docs/adr/0018-register-write-and-step-out.md`](docs/adr/0018-register-write-and-step-out.md)
- [`docs/adr/0019-typed-hardware-and-memory-breakpoints.md`](docs/adr/0019-typed-hardware-and-memory-breakpoints.md)
- [`docs/adr/0020-bounded-assembly-and-verified-patches.md`](docs/adr/0020-bounded-assembly-and-verified-patches.md)
- [`docs/adr/0021-native-mutation-fuzzing-and-asan.md`](docs/adr/0021-native-mutation-fuzzing-and-asan.md)
- [`docs/adr/0022-defer-fuzzing-pending-toolchain-survey.md`](docs/adr/0022-defer-fuzzing-pending-toolchain-survey.md)
- [`docs/adr/0023-backend-instance-identity.md`](docs/adr/0023-backend-instance-identity.md)
- [`docs/adr/0024-bounded-native-callstack.md`](docs/adr/0024-bounded-native-callstack.md)
- [`docs/adr/0025-bounded-patch-enumeration.md`](docs/adr/0025-bounded-patch-enumeration.md)
- [`docs/adr/0026-exact-symbol-resolution.md`](docs/adr/0026-exact-symbol-resolution.md)
- [`docs/adr/0027-known-function-at-address.md`](docs/adr/0027-known-function-at-address.md)
- [`docs/adr/0028-structured-launch-arguments.md`](docs/adr/0028-structured-launch-arguments.md)
- [`docs/adr/0029-bounded-module-imports-and-exports.md`](docs/adr/0029-bounded-module-imports-and-exports.md)
- [`docs/adr/0030-bounded-debugger-event-history.md`](docs/adr/0030-bounded-debugger-event-history.md)
- [`docs/adr/0031-bounded-loaded-section-metadata.md`](docs/adr/0031-bounded-loaded-section-metadata.md)
- [`docs/design/mvp.md`](docs/design/mvp.md)
- [`docs/development-roadmap.md`](docs/development-roadmap.md)
- [`docs/native-api-audit.md`](docs/native-api-audit.md)
- [`docs/reference-implementation-review.md`](docs/reference-implementation-review.md)
- [`docs/install.md`](docs/install.md)
- [`docs/release-readiness.md`](docs/release-readiness.md)

The Gateway owns any dotted namespace prefix. This backend therefore publishes
backend-local tool names such as `debugger.state` and `memory.read`.

Authenticated readiness, MCP initialization metadata, and `debugger.state`
publish one unpredictable `instance_id` per sidecar. Every mutation is bound to
the observed instance as well as its own `operation_id`; a replacement backend
returns `BACKEND_RESTARTED` before dispatch instead of accepting a blind retry.

Address-taking tools preserve canonical absolute strings and also accept stable
module-relative references, so clients do not need to redo ASLR arithmetic:

```json
{"address":{"module":"sample.exe","rva":"0x1000"}}
```

Use `address.resolve` to inspect the corresponding absolute address, module
base, RVA, and state generation without performing a mutation.

Execution workflows use `debugger.resume` followed by
`debugger.wait_for_pause`. The first call confirms the mutation and returns its
generation; the second waits on native debugger callbacks and reports a bounded
pause reason without sleeps or state polling.

Bounded discovery is available through `symbols.search`, `functions.list`,
`strings.search`, and `references.to`. Results are generation-consistent,
paginated, module/RVA aware, and explicitly report `completeness: "known_only"`;
the read tools never silently trigger debugger analysis.
Queried `strings.search` results default to compact UTF-8-safe context and expose
reconstructable `before`, `match`, and `after` fields; use `context_bytes` to tune
each side without returning an entire compiler/runtime string pool.
`analysis.function` is a separate, explicit mutation for one concrete address;
it uses a private command-queue fence and never depends on the user's GUI selection.
Existing processes can be attached only by an explicit numeric PID. State exposes
whether the session was launched or attached; attached sessions must use
`debuggee.detach`, so generic cleanup cannot terminate a pre-existing process.
One-register writes use the typed SDK plus exact read-back. `debugger.step_out`
returns compact pause context and an explicit `completed` flag, so an intervening
breakpoint or exception is not mistaken for reaching the return.
Typed hardware and memory breakpoint tools validate access, size, architecture,
alignment, slot/range ownership, and exact native read-back. Hardware setup
rejects transient process-created and system-breakpoint startup pauses; removals require the current shape
to match instead of deleting address-only state.
Assembly preview is read-only. Tracked code patches require exact original bytes,
are limited to one 16-byte instruction span, and restore only from verified x64dbg
patch metadata.
`patches.list` exposes those tracked bytes as verified adjacent ranges with
snapshot-bound pagination. `callstack.read` uses x64dbg's native unwind for the
current or one exact thread and labels an empty result inconclusive. Exact
`symbols.resolve` and `functions.at` queries avoid scanning pages when the
caller already knows a name or address; both remain bounded known-only reads.
`events.list` exposes a callback-derived 256-record history in every debugger
state. Sequence continuation, closed type filters, and explicit overflow
metadata replace polling without creating a streaming or unbounded log API.
`sections.list` exposes the SDK's named loaded-image spans with ASLR-correct
locations. It deliberately omits characteristics and raw-file metadata that the
native API does not provide; correlate with `memory.map` for current protection.

Codex registration also installs the versioned `x64dbg-debugging` workflow skill.
It provides state-aware, ASLR-safe, no-blind-retry recipes without placing bearer
tokens or machine-specific target data in instruction files.

Build a release with `powershell -File scripts/package.ps1`, then follow the
[installation and client setup guide](docs/install.md). The installed package
uses `server\x64dbg-mcp-server.exe`; no Rust, C++ runtime, or build tool is needed
on the target machine.

Before publishing, use `scripts/run-release-gate.ps1` for the complete locally
available package plus isolated x32dbg/x64dbg evidence. Publisher signing and a
pristine Windows VM install remain separately identified release gates.
