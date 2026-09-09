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

Tool calls return exactly one `content` block with `type: "text"`. Its `text`
is the complete JSON-serialized payload, not a summary or preview. Decode it
with `json.loads(result["content"][0]["text"])` in Python. Success payloads keep
their existing shapes; failures contain `{ "ok": false, "error": { ... } }`.
The enclosing `isError` remains `false` for success and `true` for tool failures.

`structuredContent` has been removed. This is a breaking change for consumers
that read that field or treat `content` as a plain-language summary. There is no
legacy fallback or new `context` field. Complete arrays, memory bytes, cursors,
and nested error details are preserved within the existing response-size limit;
oversized responses fail rather than returning truncated JSON.

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
- Execution: `debugger.pause`, `debugger.resume`, `debugger.continue_exception`, `debugger.step_into`,
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
`instance_id` and a lowercase UUID `operation_id` for the logical operation.
Generate a new ID for a new operation, not for a blind retry of an ambiguous
mutation. Inspect state and retry guidance before attempting reconciliation.

Tool schemas and limits are authoritative in `crates/server/src/tools.rs`.
Native implementations are in `plugin/src/runtime.cpp`.
Tools no longer advertise `outputSchema`, which describes structured output,
not JSON embedded in text. Payload schemas remain internal contract-test
fixtures. Check completion, pagination, and read-completeness fields in decoded
`content` rather than treating `isError: false` as proof that an execution target
or exhaustive search completed.

Memory `length` and breakpoint `size` inputs are byte counts. Existing names
are preserved, with no aliases. JSON integers use decimal syntax: reading
16 bytes uses `{ "address": "0x100000", "length": 16 }`.

The [debugger behavior notes](docs/field-validation.md) cover protocol negotiation,
exception continuation, thread identity, and native pause behavior.

### Trace stopping

Trace admission requires a committed native pause with the selected thread matching
the debug-event thread. `trace.start` reports native admission, which can precede
the first completed step; cancellation may legitimately retain only the initial
point. A timeout requests stopping at its deadline. After a bounded 50 ms
cooperative opportunity, an independently supervised helper can pause a blocked
step-over through x64dbg's thread-create callback, without delivering a synthetic
exception to the debuggee. This requires remote-thread access and an unmodified
`ntdll!DbgBreakPoint`/RET sequence.

At a helper pause, do not start tracing or stepping the helper. Prearm an application
breakpoint before starting the trace, release any controlled wait via `memory.write`
if necessary, then explicitly `debugger.resume` to an application-thread debug event.
Other mutations are rejected there except `trace.cancel`, `debugger.stop` (subject
to attached-session restrictions), and ScyllaHide configuration. Read-only tools
retain their usual state requirements. An unresolved interrupt is not reported as
successful cancellation: the backend fails closed instead of admitting a new trace
or automatically resuming through an unrelated pause.

## Build and test

Required baseline:

- Visual Studio 2026 Build Tools with MSVC C++, CMake, and Ninja
- Rust stable `x86_64-pc-windows-msvc`
- x64dbg SDK 2026.05.27
- Python 3.11+ (CI uses 3.13) and `requirements-test.txt` for pytest

```powershell
$env:X64DBG_ROOT = 'C:\tools\x64dbg'
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-test.txt
cargo fmt --all -- --check
cargo test --offline --locked --workspace --all-targets
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
scripts\build-plugin.cmd x86 test
scripts\build-plugin.cmd x64 test
cargo build --offline --locked --bin x64dbg-mcp-server
.venv\Scripts\python.exe -m pytest --server-path target\debug\x64dbg-mcp-server.exe
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\package.ps1
```

Rust and C++ tests stay native. HTTP scenario assertions live in `tests/python`;
PowerShell wrappers retain Windows preparation, debugger ownership, readiness
waits, and cleanup. The shared Python MCP client validates the content-only
contract, preserves integer and Unicode data, and never retries automatically.
Scenario-specific retries are limited to explicitly safe `BUSY` state reads and
the attach scenario's read-only module snapshot, which can race attach callbacks.

Without `--server-path`, pytest runs offline harness tests and skips real HTTP
tests. Normal runs never launch a debugger. Live tests require prepared isolated
runtime trees (the full x64dbg runtime, not just the SDK), and run serially:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\prepare-integration.ps1 `
  -X64dbgRoot C:\tools\x64dbg -Destination "$PWD\artifacts\python-integration"
.venv\Scripts\python.exe -m pytest tests/python/test_live.py --run-live `
  --integration-root artifacts/python-integration `
  --server-path target/debug/x64dbg-mcp-server.exe `
  --report-directory artifacts/python-reports --junitxml artifacts/pytest-live.xml
```

Use a fresh integration destination; preparation refuses to overwrite an existing
tree. Adjust `--server-path` if Cargo uses a custom target directory. Live pytest
covers real integration/soak, attach/detach, and generic fixture smoke on x32 and
x64. Installed Flare qualification is separately opt-in via `--flare-sample` and
`--x64dbg-root`. Never run concurrent suites against the same debugger trees.

For offline Python provisioning, first download wheels with
`py -3 -m pip download -r requirements-test.txt -d artifacts/python-wheels`, then
install with `--no-index --find-links artifacts/python-wheels -r requirements-test.txt`.
Rust offline commands likewise require dependencies cached by `cargo fetch --locked`.

Run the complete local release gate with:

```powershell
$env:X64DBG_MCP_TEST_PYTHON = "$PWD\.venv\Scripts\python.exe"
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\run-release-gate.ps1 -X64dbgRoot C:\tools\x64dbg
```

The gate runs Rust, C++, Python unit/HTTP, live x32/x64, and host-control checks,
and writes JUnit plus per-scenario JSON reports. It verifies that the tested server
matches the newly packaged executable. Set `X64DBG_MCP_TEST_PYTHON` for standalone
PowerShell runners too; pytest automatically passes its interpreter to them.
CI runs Rust, native, and Python unit/HTTP tests before packaging. It does not
run live debugger tests because its SDK-only environment lacks the runtime.
Native test builds also build and discover their own current release server,
including custom Cargo target directories, rather than trusting a cached path.

To qualify a fresh package with Flare without replacing an existing installation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\run-flare-qualification.ps1 `
  -PackageRoot "$PWD\dist\x64dbg-mcp-backend-0.2.0" `
  -X64dbgRoot C:\tools\x64dbg `
  -SamplePath 'C:\samples\checksum.exe' `
  -OutputDirectory "$PWD\build\flare-qualification-new" -Iterations 3
```

Supply your newly qualified package and sample paths, and an unused output directory.
This creates a separate installed-layout runtime with only this project's plugin,
independent credentials, verified binary hashes, and per-run JSON/JUnit evidence.
Reports contain no credentials; do not publish the generated runtime/config directory.

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
