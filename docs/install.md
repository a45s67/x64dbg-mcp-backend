# Install and connect

## Release installation

Extract the release ZIP, then run PowerShell from its top-level directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1 `
  -X64dbgRoot C:\tools\x64dbg
```

The installer verifies that both x32 and x64 debugger directories exist, copies
the matching `.dp32` and `.dp64` plugins, installs the shared static sidecar, and
creates two TOML configuration files. A first install generates one
cryptographically random 48-byte bearer secret and stores it only in those
configuration files. A normal reinstall preserves the existing shared secret and
any port not explicitly supplied, so an update does not silently break registered
clients. The installer does not print the secret; do not put it in source control
or command-line arguments.

If the two installed configurations contain different tokens, installation fails
before copying files. Reconcile the files or deliberately create a new shared
credential with `-RotateToken`, then refresh Codex or Gateway registration. Use
`-WhatIf` to inspect the copy operation without writing anything.

Default endpoints are:

- x32dbg: `http://127.0.0.1:43132/mcp`
- x64dbg: `http://127.0.0.1:43164/mcp`

Use `-X32Port` and `-X64Port` to select different, non-equal ports. Start the
desired debugger normally. Its plugin launches the sidecar automatically after
plugin initialization. Closing or unloading the debugger plugin shuts down its
sidecar; there is no detached server process to start separately.

## Verify the extracted package

Before installation, verify every packaged file, required layout, version/SBOM
metadata, and the x86/x64 PE machine types offline:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\verify-package.ps1
```

This uses only built-in PowerShell/.NET and makes no network or filesystem
changes. Checksums establish integrity relative to the included manifest; they
do not replace publisher code signing.

Never install the x32 and x64 backends on the same port. The MVP permits one
debugger instance per backend type, so a second x32dbg or x64dbg instance reports
an explicit single-instance failure.

## Verify health

Liveness intentionally needs no token:

```powershell
Invoke-RestMethod http://127.0.0.1:43164/health/live
```

Readiness proves that the authenticated plugin IPC connection works:

```powershell
$headers = @{ Authorization = 'Bearer <token from server\x64dbg-mcp-server-x64.toml>' }
Invoke-RestMethod http://127.0.0.1:43164/health/ready -Headers $headers
```

The readiness endpoint returns 503 until the matching debugger and plugin are
ready. Once the plugin is connected it returns 200 even when no debuggee is
loaded; that state reports `diagnostic_code` as `NO_DEBUGGEE` and points
`next_actions` to the explicit `debuggee.launch` tool. It does not expose the
token or target path.

The MVP owns one connected debugger instance per backend type. To load a target
into that instance, call `debuggee.launch` or use the same debugger UI. Starting
a second x64dbg/x32dbg process is not a target-handoff mechanism.

## Codex direct connection

Register both installed Streamable HTTP endpoints with one command. The helper
reads and validates the installed x32/x64 configuration, stores the Authorization
header directly in the user-level Codex `config.toml`, installs the versioned
`x64dbg-debugging` workflow skill, and replaces existing managed entries with the
same names. No token environment variable is required:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\register-codex.ps1 -X64dbgRoot C:\tools\x64dbg
codex mcp list
```

The debugger installer and Codex registration are intentionally separate. For a
Gateway-only installation, run only `install.ps1`.

Restart an already-running Codex process after changing its configuration. Opening
x64dbg/x32dbg is what starts the backend; Codex connects to the selected endpoint
afterward.

The helper refuses to overwrite an existing `x64dbg-debugging` skill unless it has
this package's ownership marker. Pass `-SkipSkill` when only the MCP registrations
should be changed.

## Dynamic Analysis Gateway

Register each endpoint as a separate Streamable HTTP backend and configure the
same bearer token through the Gateway's secret facility. Use distinct backend
identities such as `x64dbg` and `x32dbg`. The backend publishes local names such as
`debugger.state`; the Gateway adds its dotted namespace. Do not pre-prefix the
tool names in this backend.

The Gateway integration must preserve these transport properties:

- HTTP POST endpoint `/mcp`, MCP protocol `2025-06-18`;
- `Authorization: Bearer <token>` on MCP and readiness requests;
- `Content-Type: application/json` and an `Accept` value allowing
  `application/json`;
- no automatic retry of tools whose `readOnlyHint` is false;
- the caller-generated `operation_id` must remain unchanged if the Gateway asks
  for the recorded result of an ambiguous mutation.

## Manual and diagnostic launch

Manual sidecar launch without `--pipe` is supported only as a disconnected MCP
server for contract diagnostics. It cannot control a debugger. Configuration is
loaded from `--config <path>`, then overlaid by `X64DBG_MCP_*` environment
variables. Tokens are deliberately not accepted as command-line flags.

The complete settings and hard caps are documented in
[`design/mvp.md`](design/mvp.md). Browser requests with an `Origin` header are
denied unless the exact origin appears in `allowed_origins`; CORS is not enabled
implicitly.

## Uninstall

Close both debuggers, then remove only these installed files:

```text
x32/plugins/x64dbg-mcp-backend.dp32
x64/plugins/x64dbg-mcp-backend.dp64
server/x64dbg-mcp-server.exe
server/x64dbg-mcp-server-x32.toml
server/x64dbg-mcp-server-x64.toml
```

The installer does not modify other plugins or x64dbg configuration.
