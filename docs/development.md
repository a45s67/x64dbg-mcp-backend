# Development

## Pinned baseline

- Visual Studio 2026 Build Tools, MSVC 19.51.36256 (x86/x64)
- CMake 4.3.1-msvc1 and Ninja 1.13.2
- Rust/Cargo 1.98.0, `x86_64-pc-windows-msvc`
- x64dbg 2026.05.27, commit
  `9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87`

Set the SDK location before configuring native builds:

```powershell
$env:X64DBG_ROOT = 'C:\tools\x64dbg'
```

Build either plugin from an ordinary PowerShell or Command Prompt; the wrapper
discovers Build Tools and imports the correct MSVC environment:

```cmd
scripts\build-plugin.cmd x64
scripts\build-plugin.cmd x86
scripts\build-plugin.cmd x64 test
scripts\build-plugin.cmd x86 test
```

The underlying CMake presets remain available inside matching Developer shells.
Cargo uses the x64 MSVC environment for the sidecar.

Run the server checks and build the sidecar with:

```powershell
cargo test --offline --workspace --all-targets
cargo clippy --offline --workspace --all-targets -- -D warnings
cargo build --release --locked
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\test-install.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\test-register-codex.ps1
```

Native builds also produce `x64dbg_mcp_lifecycle_test.exe`. With the `test`
argument, CTest runs executor, normal lifecycle, and injected sidecar-crash tests.
The lifecycle harness launches the real
Rust sidecar through the same secured pipe and restricted inherited-stdin nonce
channel as the plugin, waits for an authenticated IPC handshake, then verifies a
bounded graceful shutdown. Example:

```powershell
$env:X64DBG_MCP_SERVER_PATH = (Resolve-Path target\release\x64dbg-mcp-server.exe)
build\windows-x64\x64dbg_mcp_lifecycle_test.exe `
  $env:X64DBG_MCP_SERVER_PATH 43129
```

The Rust supervised-shutdown matrix covers idle, active and IPC-queued reads,
queued and active mutations, and a disconnected HTTP client. For a finite real
debugger lifecycle soak after preparing the isolated trees, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\run-integration-soak.ps1 -Backend both -Iterations 3
```

The count is restricted to 1–20. Every run uses the existing isolated integration
flow, then verifies that its owned sidecar exited and its loopback port closed. It
never kills processes by image name.

The complete locally available release gate composes packaging and both real
debugger integrations and leaves a JSON evidence report under `artifacts`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\run-release-gate.ps1 -X64dbgRoot C:\tools\x64dbg
```

See [`release-readiness.md`](release-readiness.md) for the separate publisher
signing and pristine-VM gates that cannot be asserted by a developer-machine run.

The plugin inherits these non-secret runtime settings from x64dbg:

- `X64DBG_MCP_BIND` (optional, loopback only; default `127.0.0.1`)
- `X64DBG_MCP_PORT` (required)
- `X64DBG_MCP_TOKEN` (required, at least 32 bytes)
- `X64DBG_MCP_SERVER_PATH` (optional absolute development override)

Normal installed configuration is TOML rather than inherited environment. See
[`install.md`](install.md) for generated configuration, direct Codex setup, and
Gateway transport requirements.

The per-launch IPC nonce is never placed in command-line arguments or the
environment. The plugin passes it over the sole inherited stdin pipe. Keeping the
write end open also provides sidecar ownership: closing it during `plugstop`
causes an EOF-driven graceful HTTP shutdown. A five-second process wait is
followed by forced termination only as a bounded last resort. A Windows Job
Object additionally kills the sidecar if the debugger process itself crashes.

## Safety boundary

The pinned x64dbg installation currently contains a different MCP plugin. It is
not a project dependency and MUST NOT be inspected, copied, linked, or loaded by
this project's integration tests. Tests use an isolated debugger copy containing
only the plugin under test.
