# Field Validation Notes

This document records failures reproduced against an isolated Windows 10 dynamic-analysis VM.
It is evidence for regression tests and release acceptance, not a substitute for the tool
contract or architecture documentation.

## Codex initialization compatibility

The released v0.1.2 server accepted only MCP protocol `2025-11-25`. A Codex host that initialized
with `2025-06-18` received JSON-RPC error `-32602` (`Unsupported protocol version`) and reported the
server as `failed (0 tools)`. The debugger plugin, bearer authentication, `/health/live`, and an
explicit `2025-11-25` raw MCP initialization were all healthy at the same time.

The server supports the common tool-only contract for both handshake-era revisions. It now accepts
and echoes `2025-06-18` or `2025-11-25` during initialization and accepts either value in the
subsequent `MCP-Protocol-Version` transport header. No tasks, elicitation, sampling, prompts, or
resources are advertised, so no revision-dependent implementation is required for the exposed
capability set.

## Cancelled HTTP request leaves a stale IPC response

A long `debugger.resume` request was cancelled by the HTTP client before the plugin completed it.
The plugin later wrote that request's response to the authenticated IPC stream. The next request
read the stale frame, reported `IPC response correlation mismatch`, and marked the plugin
disconnected even though x32dbg remained alive.

The adapter now records request IDs abandoned by future cancellation. A later call drains only a
response whose ID is in that bounded abandoned set before waiting for its own response. An unknown
correlation mismatch still fails closed. The regression test aborts the first adapter future after
the plugin reads its request, then proves that the second call receives only its correlated result.

## Attach and hardware-breakpoint lifecycle observation

Attaching to an already-running entry-spin process can return at the transient
`process_created` pause. Hardware-breakpoint mutation is intentionally rejected at that pause, and
an absolute breakpoint target that has not been mapped yet cannot be resolved. The reliable client
sequence is to keep the entry spin installed, advance the attach handshake to a later pause, set
breakpoints only after their target mapping exists, and restore the original entry bytes last.

This observation does not currently require a server contract change. Runtime acceptance must
nevertheless cover attach, resume, event polling, and a hardware breakpoint after a non-transient
pause so that a future lifecycle change does not silently regress the workflow.

## Typed exception continuation

`debugger.continue_exception` is a closed, typed mutation that is accepted only at a confirmed
exception pause. `disposition=handled` maps to x64dbg `serun` and swallows the current exception;
`disposition=not_handled` is accepted only for a first-chance exception and maps to `erun`, passing
first-chance exceptions to the debuggee. A normal `debugger.resume` must not be assumed to have
either semantic.
