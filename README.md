# x64dbg MCP Backend

An independently usable Streamable HTTP MCP backend for x64dbg and x32dbg,
designed for direct MCP clients and the Dynamic Analysis Gateway.

The MVP consists of one statically linked Rust HTTP sidecar shared by two
architecture-specific native plugins. The plugin starts and owns the sidecar;
users normally launch only x32dbg or x64dbg. Durable decisions are recorded in:

- [`docs/adr/0001-mvp-architecture.md`](docs/adr/0001-mvp-architecture.md)
- [`docs/adr/0002-debuggee-launch.md`](docs/adr/0002-debuggee-launch.md)
- [`docs/adr/0003-structured-address-references.md`](docs/adr/0003-structured-address-references.md)
- [`docs/design/mvp.md`](docs/design/mvp.md)
- [`docs/native-api-audit.md`](docs/native-api-audit.md)
- [`docs/install.md`](docs/install.md)

The Gateway owns any dotted namespace prefix. This backend therefore publishes
backend-local tool names such as `debugger.state` and `memory.read`.

Address-taking tools preserve canonical absolute strings and also accept stable
module-relative references, so clients do not need to redo ASLR arithmetic:

```json
{"address":{"module":"sample.exe","rva":"0x1000"}}
```

Use `address.resolve` to inspect the corresponding absolute address, module
base, RVA, and state generation without performing a mutation.

Build a release with `powershell -File scripts/package.ps1`, then follow the
[installation and client setup guide](docs/install.md). The installed package
uses `server\x64dbg-mcp-server.exe`; no Rust, C++ runtime, or build tool is needed
on the target machine.
