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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1 `
  -X64dbgRoot C:\tools\x64dbg
```

The installer deploys both plugins and the shared sidecar:

```text
x32\plugins\x64dbg-mcp-backend.dp32
x64\plugins\x64dbg-mcp-backend.dp64
server\x64dbg-mcp-server.exe
server\x64dbg-mcp-server-x32.toml
server\x64dbg-mcp-server-x64.toml
```

Default endpoints are `http://127.0.0.1:43132/mcp` for x32dbg and
`http://127.0.0.1:43164/mcp` for x64dbg. Use `-X32Port` and `-X64Port` for
different non-equal ports. Reinstall preserves valid ports and the shared token;
`-RotateToken` deliberately creates a new credential. The installer output
contains the token and must be treated as secret.

Verify an extracted release before installing:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\verify-package.ps1
```

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

Install the complete version-matched workflow skill from the extracted release:

```powershell
New-Item -ItemType Directory -Force "$HOME\.codex\skills\x64dbg-debugging" | Out-Null
Copy-Item -Path ".\skills\x64dbg-debugging\*" `
  -Destination "$HOME\.codex\skills\x64dbg-debugging" -Recurse -Force
```

Restart Codex after editing the configuration. The installer never modifies
Codex configuration, skills, or environment variables itself.

## Dynamic Analysis Gateway

Register x32dbg and x64dbg as separate Streamable HTTP backends. Store the same
installed bearer token in the Gateway secret facility. MCP uses protocol
`2025-06-18`, endpoint `/mcp`, and `Authorization: Bearer <token>`. Do not retry
mutating tools blindly; preserve `instance_id` and `operation_id` semantics.

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
  `debugger.wait_for_pause`.
- Context: `debugger.snapshot`, `events.list`, `registers.read`,
  `registers.write`, `threads.list`, `callstack.read`, `address.resolve`.
- Memory/code: `memory.read`, `memory.write`, `memory.map`, `memory.search`,
  `disassembly.read`, `expression.evaluate`, `assembly.preview`,
  `assembly.patch`, `patches.list`, `patches.restore`.
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

Close both debuggers and remove only the five installed files listed in the
Install section. Codex configuration and the optional skill are user-owned and
must be removed separately if no longer wanted.
