# x64dbg MCP Backend

Streamable HTTP MCP backend for x64dbg and x32dbg. Each architecture-specific
native plugin starts and owns one shared, statically linked Rust HTTP sidecar.
Users launch only x32dbg or x64dbg; closing the debugger shuts down its sidecar.

The server binds to localhost by default, requires a bearer token, exposes
bounded structured tools, and can be used directly by MCP clients or behind the
Dynamic Analysis Gateway. The Gateway may add its own namespace; backend tool
names remain local.

## Install

Download and extract the release ZIP, then run from its top-level directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 `
  -X64dbgRoot C:\tools\x64dbg
```

The release ZIP uses this compact binary/configuration layout:

```text
x32\x64dbg-mcp-backend.dp32
x64\x64dbg-mcp-backend.dp64
mcp\x96dbg-mcp-server.exe
mcp\x96dbg-mcp-control.exe
mcp\x96dbg-mcp-server.example.toml
install.ps1
```

The installer copies the plugins into the debugger's `x32\plugins` and
`x64\plugins` directories, then creates the server and host controller plus
separate `x64dbg-mcp-server-x32.toml` and `x64dbg-mcp-server-x64.toml` runtime
files. Server limits and timeouts use built-in defaults; the generated config
contains only the bind address, port, and bearer token. The installer
intentionally supports only this layout.

Default endpoints are `http://127.0.0.1:43132/mcp` for x32dbg and
`http://127.0.0.1:43164/mcp` for x64dbg. Use `-X32Port` and `-X64Port` for
different non-equal ports. Reinstall preserves valid ports and the shared token;
`-RotateToken` deliberately creates a new credential. The installer output
contains the token and must be treated as secret.

## Codex

The installer prints ready-to-paste values for the effective ports and token.
Open the Codex configuration:

```powershell
notepad.exe "$HOME\.codex\config.toml"
```

The generated tables have this form:

```toml
[mcp_servers.x64dbg]
url = "http://127.0.0.1:43164/mcp"
http_headers = { Authorization = "Bearer <shared installed token>" }

[mcp_servers.x32dbg]
url = "http://127.0.0.1:43132/mcp"
http_headers = { Authorization = "Bearer <shared installed token>" }
```

Restart Codex after editing the configuration. The installer never modifies
Codex configuration or environment variables itself. A separate Codex skill is
not required; MCP tool descriptions and schemas are authoritative.

## Dynamic Analysis Gateway

Register x32dbg and x64dbg as separate Streamable HTTP backends. Store the same
installed bearer token in the Gateway secret facility. MCP uses protocol
`2025-06-18`, endpoint `/mcp`, and `Authorization: Bearer <token>`. Do not retry
mutating tools blindly; preserve `instance_id` and `operation_id` semantics.

When host lifecycle support is added to the Dynamic Analysis Gateway, its
optional command belongs in each existing backend entry; it does not require a
separate configuration section. The intended flat fields are:

```toml
[x64dbg]
lifecycleCommand = 'C:\tools\x64dbg\release\mcp\x96dbg-mcp-control.exe'
lifecycleArgs = ['--backend', 'x64', '--root', 'C:\tools\x64dbg']
```

The current Gateway release does not accept these fields yet. Until its schema
and management tool are updated, invoke the controller directly.

The controller supports `status`, `start`, `stop`, and `restart`, emits one
bounded JSON result, waits for authenticated MCP readiness, and closes the
debugger through its main window. It never creates a detached shell helper or
force-terminates x64dbg. `stop` and `restart` refuse an active or unobservable
debuggee unless the caller explicitly supplies `--force`.

## Health

Liveness is public:

```powershell
Invoke-RestMethod http://127.0.0.1:43164/health/live
```

Readiness requires the installed bearer token and returns 503 until the matching
plugin is connected:

```powershell
$headers = @{ Authorization = 'Bearer <installed token>' }
Invoke-RestMethod http://127.0.0.1:43164/health/ready -Headers $headers
```

## Tools

The catalog is intentionally bounded and contains no shell execution, file
transfer, process enumeration, or arbitrary debugger-command tool.

- Lifecycle: `debugger.state`, `debuggee.launch`, `debuggee.launch_dll`,
  `debuggee.attach`, `debuggee.detach`, `debugger.stop`.
- Execution: `debugger.pause`, `debugger.resume`, `debugger.step_into`,
  `debugger.step_over`, `debugger.step_out`, `debugger.run_to_address`,
  `debugger.wait_for_pause`, `events.wait`.
- Context: `debugger.snapshot`, `events.list`, `context.arguments`,
  `process.peb`, `registers.read`, `registers.write`, `threads.list`,
  `callstack.read`, `address.resolve`.
- Memory/code: `memory.read`, `memory.write`, `memory.map`, `memory.search`,
  `disassembly.read`, `expression.evaluate`, `expressions.evaluate_batch`,
  `assembly.preview`, `assembly.patch`, `patches.list`, `patches.restore`.
- Breakpoints: `breakpoints.list`, `breakpoints.set`, `breakpoints.remove`,
  typed hardware/memory/conditional/exception set/remove, and
  `breakpoints.enable` / `breakpoints.disable`.
- Discovery: `modules.list`, `sections.list`, `symbols.search`,
  `symbols.resolve`, `functions.list`, `functions.at`, `strings.search`,
  `references.to`, `imports.list`, `exports.list`, `analysis.function`.
- Trace: `trace.start`, `trace.status`, `trace.cancel`, `trace.results`.

Use `{ "module": "sample.exe", "rva": "0x1000" }` instead of manual ASLR
arithmetic where an address schema accepts module/RVA input. Every mutation
requires the current backend `instance_id` and a fresh lowercase UUID
`operation_id`.

## Build and test

Pinned baseline:

- Visual Studio 2026 Build Tools with MSVC C++, CMake, and Ninja
- Rust stable `x86_64-pc-windows-msvc`
- x64dbg 2026.05.27

Set the debugger SDK root and build:

```powershell
$env:X64DBG_ROOT = 'C:\tools\x64dbg'
cargo test --offline --locked --workspace --all-targets
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
scripts\build-plugin.cmd x86 test
scripts\build-plugin.cmd x64 test
```

Build the release package:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\package.ps1
```

GitHub Actions uses the pinned Windows/Visual Studio runner to compile the Rust
sidecar and both native plugins. A `v*` tag publishes the minimal ZIP as a
GitHub Release asset and also retains it as a workflow artifact. The more
extensive test suites remain available for local release validation.

Run the full local release gate, optionally including the installed Flare-On
sample:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\run-release-gate.ps1 -X64dbgRoot C:\tools\x64dbg `
  -InstalledFlareSamplePath C:\Users\fish\Downloads\Flare-On11_Challenges\checksum.exe
```

The plugin/sidecar wire format is documented in
[`docs/contracts/ipc-v1.md`](docs/contracts/ipc-v1.md). Tool schemas and limits
are authoritative in `crates/server/src/tools.rs`; native dispatch is in
`plugin/src/runtime.cpp`.

## Uninstall

Close both debuggers and remove the two installed plugins plus
`mcp\x96dbg-mcp-server.exe`, `mcp\x96dbg-mcp-control.exe`,
`mcp\x64dbg-mcp-server-x32.toml`, and
`mcp\x64dbg-mcp-server-x64.toml`. Codex configuration is user-owned and must be
removed separately if no longer wanted.
