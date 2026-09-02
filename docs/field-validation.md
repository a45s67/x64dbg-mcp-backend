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

An exception-paused register write followed by a separate continuation can lose the edited
registers when x64dbg restores its saved exception context. Optional `register_overrides` are
therefore applied atomically to the exact thread reported by the correlated exception callback.
The plugin obtains that native thread context, applies one to four closed full-width assignments,
writes the context once, and verifies it with a second native context read before submitting only
`serun` or `erun`. Names use the same architecture-specific policy as `registers.write`; values are
canonical lowercase hexadecimal. Arbitrary expressions and debugger commands remain unavailable.

Runtime acceptance must redirect a benign access violation to an ABI-compatible recovery export
and observe a marker written by that export before its checkpoint breakpoint. A successful command
submission or an immediate register read-back alone does not prove that x64dbg resumed with the
modified exception context.

## Exact-thread mutation and stepping

Debugger GUI selection is mutable state and is not authoritative evidence of which native thread
was read, written, or stepped. `registers.write` accepts an optional exact `thread_id`; the plugin
uses the corresponding native handle for one `GetThreadContext` / `SetThreadContext` / read-back
cycle without changing GUI selection. `debugger.step_into` and `debugger.step_over` also accept an
exact `thread_id`, synchronously select it for x64dbg's step engine, and reject a completion callback
from any other thread. Runtime acceptance writes and restores a non-selected worker register, then
steps that worker and proves the prior selected thread's instruction pointer did not move.

`DbgGetThreadId()` is not a selected-thread API: x64dbg implements it from the current debug-event
record (`GetDebugData()->dwThreadId`), while `switchthread` changes only `hActiveThread`. Selected
identity for register and call-stack reads must therefore be derived from
`DbgGetThreadList().CurrentThread` and verified against `DbgGetThreadHandle()`.

x64dbg's `StepInto()` / `StepOver()` engine has no thread-handle argument and operates on the
current debug-event thread. `thread_id` on the typed step tools is consequently a required-identity
assertion, not a request to switch the engine to an arbitrary thread. A non-event TID is rejected
before mutation. For the event TID, the backend submits the single run-state step with
`DbgCmdExecDirect` and still requires the resulting callback TID to match. Runtime acceptance proves
both rejection without a generation change and a callback-correlated exact event-thread step.

## Direct pause interruption

Submitting the textual `pause` command through x64dbg's asynchronous command queue is not a
reliable way to interrupt a debuggee whose selected thread is blocked in a kernel wait. Calling
`DebugBreakProcess` is also insufficient when the debuggee hides its PEB `BeingDebugged` byte:
`DbgUiRemoteBreakin` can exit cleanly without raising a breakpoint.

`debugger.pause` therefore admits one owned interrupt at a time and creates a remote thread directly
at the architecture-matched `ntdll!DbgBreakPoint`. The adjacent `CB_PAUSEDEBUG` and
`CB_EXCEPTION` callback orders are folded into one generation-consistent `user_pause`. Before the
owned exception is continued, the backend restores the thread that x64dbg had selected before the
interrupt and uses `serun` so the synthetic breakpoint is handled instead of delivered to the
debuggee. This preserves exact-thread reads after the short-lived interrupt thread exits. Runtime
acceptance also proves that `BeingDebugged` remains hidden throughout the pause rather than being
temporarily modified.
