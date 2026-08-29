# ADR 0002: bounded debuggee launch through an existing debugger

- Status: Accepted
- Date: 2026-08-29
- Scope: First post-MVP session bootstrap mutation

## Context

The plugin and sidecar can be ready while no debuggee is loaded. Requiring the
operator to use the x64dbg UI prevents an MCP-only workflow and does not work
well with a headless Gateway. Starting a second x64dbg process is not a reliable
handoff mechanism for an already-running backend instance.

x64dbg publishes the `InitDebug` command for loading an executable, optional
command line, and working directory. It initializes the debug session and stops
at debugger callbacks. The backend must not expose arbitrary debugger commands
or introduce an unbounded command-line quoting surface.

## Decision

Add this backend-local mutation:

```text
debuggee.launch(path, working_directory?, operation_id)
```

- It is legal only when the plugin is ready and the debuggee state is `absent`.
- `path` must be an absolute UTF-8 Windows path to an existing regular file.
- `working_directory`, when present, must be an absolute existing directory.
  Otherwise the executable's parent directory is used.
- Both paths are canonicalized in the native plugin immediately before use.
- Input is bounded to 32,767 UTF-8 bytes per path and rejects control characters.
- The native adapter builds only the fixed `InitDebug` command. It does not
  accept an x64dbg command, script, or raw debuggee command-line string.
- Success requires a callback-confirmed, actionable pause created after this
  request; merely accepting the debugger command is not success.
- `CB_CREATEPROCESS` alone is not actionable. x64dbg can still be initializing
  its debug objects and command queue at that point. The launch remains pending
  until a later system-breakpoint, breakpoint, exception, step, or explicit
  pause callback replaces the transient `process_created` reason.
- A timeout after command acceptance is an ambiguous mutation result. The same
  canonical operation UUID may query/replay the recorded outcome, but neither
  the server nor Gateway starts the launch again blindly.
- x64dbg's documented initialization behavior includes its normal system and
  executable-entry breakpoints. A configurable `break_on_entry` flag is not
  exposed until x64dbg provides a contract the backend can enforce precisely.

## Command-line arguments (resolved by ADR 0028)

ADR 0028 adds the planned structured string array, never one raw command string.
Its x32/x64 round-trip fixtures cover quotes, trailing backslashes, Unicode,
empty arguments, commas, and whitespace.

## Security and lifecycle consequences

This operation launches code selected by the authorized caller and is therefore
marked mutating and destructive. It remains loopback/bearer protected and is
subject to the mutation deadline, concurrency bound, operation ledger, debugger
executor, plugin draining state, and sidecar ownership shutdown rules. Launching
a debuggee does not create an additional backend or detached process owner.

## Acceptance tests

- Schema and native parsing reject relative, missing, oversized, malformed, and
  state-invalid requests before `InitDebug` is queued.
- x32 and x64 fixtures confirm callback-correlated success and canonical paths.
- A slower real debuggee proves launch does not expose the transient
  `process_created` pause as command-ready.
- Timeout and disconnect tests prove that an accepted launch is never retried.
- Closing or unloading the debugger during launch leaves no sidecar, plugin
  thread, or backend-owned process.
