# Native API and threading audit

This file is a release gate, not an informal implementation note. Every native
debugger call used by an MCP tool must appear here before the tool is enabled.

## Execution boundary

`Runtime::Worker` owns the single IPC connection but never calls a debugger API
directly. It validates and copies a bounded request, then submits it to the
32-slot `DebuggerExecutor`. That executor has exactly one owned, joinable worker,
so native access is serialized. It revalidates the callback-maintained debuggee
state immediately before each call.

The Bridge read/snapshot entry points below are synchronous plugin APIs and are
called only on the serialized executor. No pointer returned by a callback is
retained. Bridge-allocated lists are freed with `BridgeFree` inside the same work
item. Count, pointer, element-size, decoder-length, address-overflow, and output
bounds are checked before dereference or iteration.

Mutating debugger commands are never executed with `DbgCmdExecDirect` and no
caller input becomes a command. The executor submits one fixed command through
`DbgCmdExec`, x64dbg's documented asynchronous command queue, then waits for a
later registered debugger callback and a greater `state_generation`. Breakpoint
commands contain only a validated, re-formatted numeric address and are confirmed
through `DbgGetBpxTypeAt`. Timeout after submission is reported as unknown and is
never retried automatically.

## Enabled calls

| Tool | Native API | Required state | Completion and ownership |
|---|---|---|---|
| `debugger.state` | `DbgGetRegDumpEx` | paused for CIP; any otherwise | atomic callback snapshot; copied register dump |
| `registers.read` | `DbgGetRegDumpEx` | paused | copied fixed-size dump; register-name allowlist |
| `memory.read` | `DbgMemRead` | paused | caller-owned buffer, max 64 KiB |
| `memory.map` | `DbgMemMap` | paused | max 256 returned items; `BridgeFree(map.page)` |
| `modules.list` | `Script::Module::GetList` | paused | validates `ListInfo`; `BridgeFree(list.data)` |
| `threads.list` | `DbgGetThreadList` | paused | max 256 returned items; `BridgeFree(list.list)` |
| `breakpoints.list` | `DbgGetBpList` | paused/running | max 256 returned items; `BridgeFree(map.bp)` |
| `disassembly.read` | `DbgDisasmAt` | paused | max 256 instructions; size must be 1-15 |
| `expression.evaluate` | `DbgFunctions()->ValFromString` | paused | max 1024-byte expression; no command execution |
| pause/resume/step/stop | `DbgCmdExec` | operation-specific | fixed command; callback and generation confirmation |
| `memory.write` | `DbgMemWrite`, `DbgMemRead` | paused | max 4 KiB; read-back verification |
| breakpoint set/remove | `DbgCmdExec`, `DbgGetBpxTypeAt` | paused | validated address only; bounded observation loop |

## Unload invariant

`plugstop` first changes state to draining and wakes callback waiters. It closes
the sidecar ownership channel, cancels pipe I/O, joins the IPC worker, stops and
joins the executor, then waits for the sidecar process. Callbacks are unregistered
after `Runtime::Stop` returns. There are no detached threads. The five-second
forced process termination path is a last-resort containment mechanism, not the
normal sidecar shutdown path, and is covered separately from graceful EOF tests.
The sidecar is created suspended, assigned to a `KILL_ON_JOB_CLOSE` Job Object,
then resumed, so debugger process failure cannot leave it unmanaged. CTest also
injects a sidecar crash for both architectures and verifies bounded plugin stop.

Any new native API requires updating this table and adding state, bound,
allocation, timeout, and unload tests.
