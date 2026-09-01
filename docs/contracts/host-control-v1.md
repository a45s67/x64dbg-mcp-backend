# Host control CLI v1

`x96dbg-mcp-control.exe` is the debugger-specific lifecycle boundary for x32dbg
and x64dbg. It is independently usable; a Gateway may invoke it as a bounded
child process but must not duplicate its Windows, path, or ScyllaHide logic.
The debugger-owned MCP sidecar never attempts to restart its own parent.

## Invocation

```text
x96dbg-mcp-control.exe <status|start|stop|restart|scyllahide-profile>
  --backend <x32|x64> [--root <x64dbg-root>] [--timeout-ms <1000..60000>]
  [--profile <name>] [--force]
```

`--root` accepts either a distribution root containing `release\x32` and
`release\x64`, or the release directory itself. When omitted, the controller
infers the release directory as the parent of its installed `mcp` directory.
Unknown, duplicate, incompatible, oversized, or control-character arguments are
rejected. The default deadline is 20 seconds.

Every invocation writes exactly one bounded UTF-8 JSON object to stdout and
never writes credentials to either output stream. Success has `status: "ok"`; failure has
`status: "error"`, a stable `code`, a bounded `message`, and `retryable`.
Credentials and full configuration contents are never emitted.

## Lifecycle semantics

- `status` reports the exact-path host process and, when reachable, MCP readiness,
  debuggee state, and backend instance identity.
- `start` creates only the selected debugger executable, then waits for its
  authenticated `/health/ready`. An already-ready exact-path host is idempotent.
- `stop` posts `WM_CLOSE` to the selected exact-path host and waits on its process
  handle. With explicit `--force`, it may terminate only that resolved exact-path
  process if no top-level window can close or graceful close exceeds the deadline.
- `restart` is `stop` followed by `start`; it waits for actual process exit and
  readiness rather than sleeping for a fixed interval.
- `stop` and `restart` require a ready backend whose debuggee state is `absent`.
  `--force` explicitly permits an active or unobservable backend and the bounded
  exact-process fallback described above.
- Successful `start` and `restart` return the new `instance_id`. A timeout never
  claims that the final outcome is known.

The controller is the caller for the entire operation. It does not spawn `cmd`,
PowerShell, a delayed helper, or an untracked connection thread.

## ScyllaHide

`scyllahide-profile --profile <name>` updates only the selected architecture's
fixed `plugins\scylla_hide.ini`. The requested section must already exist, the
debugger host must be stopped, and replacement is atomic. It does not modify
arbitrary paths or claim that a running ScyllaHide instance reloaded the file.

## Exit codes

- `0`: JSON success
- `2`: invalid CLI or configuration
- `3`: incompatible current state or missing component
- `4`: bounded timeout or unknown lifecycle outcome
- `5`: operating-system or I/O failure
