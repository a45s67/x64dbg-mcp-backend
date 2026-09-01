# x64dbg MCP Backend

Streamable HTTP MCP backend for x64dbg and x32dbg. Each native plugin starts
and owns the same statically linked Rust sidecar; users launch only the
debugger. Closing the debugger also shuts down its sidecar.

The backend binds to localhost, requires bearer authentication, and exposes a
bounded typed tool catalog. It works directly with MCP clients and behind the
Dynamic Analysis Gateway.

## Install

Download and extract the release ZIP, then run this command from its top-level
directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 `
  -X64dbgRoot C:\tools\x64dbg
```

The package contains exactly:

```text
install.ps1
mcp\x96dbg-mcp-control.exe
mcp\x96dbg-mcp-server.exe
mcp\x96dbg-mcp-server.example.toml
x32\x64dbg-mcp-backend.dp32
x64\x64dbg-mcp-backend.dp64
```

The installer copies both plugins and creates one runtime config per
architecture. Reinstallation preserves valid ports and the shared token; use
`-RotateToken` to generate a new token. Optional `-X32Port` and `-X64Port`
values must be distinct. Defaults are:

- x32dbg: `http://127.0.0.1:43132/mcp`
- x64dbg: `http://127.0.0.1:43164/mcp`

## Codex configuration

The installer prints the effective token and ready-to-paste configuration.
Open `%USERPROFILE%\.codex\config.toml` and add:

```toml
[mcp_servers.x64dbg]
url = "http://127.0.0.1:43164/mcp"
http_headers = { Authorization = "Bearer <installed token>" }

[mcp_servers.x32dbg]
url = "http://127.0.0.1:43132/mcp"
http_headers = { Authorization = "Bearer <installed token>" }
```

Restart Codex after saving. The installer does not modify Codex configuration
or environment variables, and no separate Codex skill is required.

## Dynamic Analysis Gateway

Register x32dbg and x64dbg as separate Streamable HTTP backends using MCP
protocol `2025-11-25` or `2025-06-18`, endpoint `/mcp`, and the installed bearer
token. The server echoes either supported version during initialization and
accepts it in the subsequent `MCP-Protocol-Version` header. The Gateway may add
its dotted namespace; backend tool names remain local.

An optional lifecycle command can be stored in each existing backend entry:

```toml
[x64dbg]
lifecycleCommand = 'C:\tools\x64dbg\release\mcp\x96dbg-mcp-control.exe'
lifecycleArgs = ['--backend', 'x64', '--root', 'C:\tools\x64dbg']
```

The controller is also independently usable:

```text
x96dbg-mcp-control.exe <status|start|stop|restart> --backend <x32|x64>
  [--root <x64dbg-root>] [--timeout-ms <1000..60000>] [--force]

x96dbg-mcp-control.exe scyllahide-profile --backend <x32|x64>
  --profile <existing-profile> [--root <x64dbg-root>]
```

It emits one bounded JSON object. `start` waits for authenticated readiness;
`stop` closes the exact debugger process through its main window. `stop` and
`restart` require an absent debuggee unless `--force` is explicitly supplied.
ScyllaHide profile changes require the debugger to be stopped and take effect
after the next start.

## Health

Liveness is public:

```powershell
Invoke-RestMethod http://127.0.0.1:43164/health/live
```

Readiness requires authentication and returns HTTP 503 until the matching
plugin connects:

```powershell
$headers = @{ Authorization = 'Bearer <installed token>' }
Invoke-RestMethod http://127.0.0.1:43164/health/ready -Headers $headers
```

## Result contract

Successful tool calls place exact data in `structuredContent`. Text `content`
is a bounded summary: `memory.read` previews at most 128 bytes as a hexdump,
execution and breakpoint tools summarize only the same operation's returned
observations, and discovery tools do not duplicate item arrays.

Errors contain `code`, `message`, `recoverable`, `safeToRetry`, and `details`.
`recoverable` means a state, input, configuration, or manual change can allow
progress. `safeToRetry` means the identical request may be replayed without
duplicating an unknown mutation. Never blindly replay a mutation when
`safeToRetry` is false or `details.outcome` is `unknown`.

Optional `suggestedAction` and up to four `nextActions` are bounded advisory
guidance identified by `adviceSource="x64dbg-mcp-backend"`; the server never
executes them automatically. The schema is
[`contracts/mcp/tool-error.schema.json`](contracts/mcp/tool-error.schema.json).

## Tools

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
- Breakpoints: list, set/remove, enable/disable, and typed hardware, memory,
  conditional, and exception breakpoint operations.
- Discovery: `modules.list`, `sections.list`, `symbols.search`,
  `symbols.resolve`, `functions.list`, `functions.at`, `strings.search`,
  `references.to`, `imports.list`, `exports.list`, `analysis.function`.
- Trace: `trace.start`, `trace.status`, `trace.cancel`, `trace.results`.
- Configuration: `scyllahide.profile`.

Prefer `{ "module": "sample.exe", "rva": "0x1000" }` where an address schema
accepts module-relative input. Every mutation requires the current backend
`instance_id` and a fresh lowercase UUID `operation_id`.

Tool schemas and limits are authoritative in `crates/server/src/tools.rs`.
Native implementations are in `plugin/src/runtime.cpp`.

## Build and test

Required baseline:

- Visual Studio 2026 Build Tools with MSVC C++, CMake, and Ninja
- Rust stable `x86_64-pc-windows-msvc`
- x64dbg SDK 2026.05.27

```powershell
$env:X64DBG_ROOT = 'C:\tools\x64dbg'
cargo test --offline --locked --workspace --all-targets
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
scripts\build-plugin.cmd x86 test
scripts\build-plugin.cmd x64 test
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\package.ps1
```

Run the complete local release gate with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\run-release-gate.ps1 -X64dbgRoot C:\tools\x64dbg
```

The plugin/sidecar wire contract is
[`docs/contracts/ipc-v1.md`](docs/contracts/ipc-v1.md). A pushed `v*` tag
builds and publishes the minimal ZIP through GitHub Actions.

## Uninstall

Close both debuggers, then remove:

```text
release\x32\plugins\x64dbg-mcp-backend.dp32
release\x64\plugins\x64dbg-mcp-backend.dp64
release\mcp\x96dbg-mcp-server.exe
release\mcp\x96dbg-mcp-control.exe
release\mcp\x64dbg-mcp-server-x32.toml
release\mcp\x64dbg-mcp-server-x64.toml
```

Remove the two Codex entries separately if they are no longer needed.
