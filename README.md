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
- [`docs/design/mvp.md`](docs/design/mvp.md)
- [`docs/native-api-audit.md`](docs/native-api-audit.md)
- [`docs/install.md`](docs/install.md)
- [`docs/release-readiness.md`](docs/release-readiness.md)

The Gateway owns any dotted namespace prefix. This backend therefore publishes
backend-local tool names such as `debugger.state` and `memory.read`.

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
