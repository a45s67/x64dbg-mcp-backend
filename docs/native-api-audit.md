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

Mutating debugger commands are never executed with `DbgCmdExecDirect`. The
executor submits an allowlisted command through `DbgCmdExec`, x64dbg's documented
asynchronous command queue, then waits for either a registered debugger callback,
a directly observable bounded postcondition, or the private command-queue fence
defined by ADR 0016. Breakpoint commands contain only a validated,
re-formatted numeric address. `debuggee.launch` contains only canonical existing
paths in fixed quoted `InitDebug` positions; Windows-forbidden quotes and control
characters cannot enter the command and raw command-line arguments are not
accepted. Timeout after submission is reported as unknown and is never retried
automatically.

Structured module-relative addresses are resolved with
`Script::Module::GetList` inside the same executor work item as the consuming
native operation. The resolver validates list ownership, exact case-insensitive
module-name uniqueness, RVA bounds, and addition overflow before producing the
numeric address. It never forwards a caller expression to `DbgEval`.

Every enabled state-sensitive read follows ADR 0005: capture generation/state
under the callback mutex, release it for the bounded Bridge call and data copy,
then recheck under the mutex. Mid-read churn returns retryable `BUSY`. Page
cursors are minted only after this check. Address-taking mutations repeat the
generation/state check immediately before mutation submission; a mismatch has
not mutated anything.

## Enabled calls

| Tool | Native API | Required state | Completion and ownership |
|---|---|---|---|
| `debugger.state` | `DbgGetRegDumpEx` | paused for CIP; any otherwise | atomic callback snapshot; copied register dump |
| `debugger.snapshot` | `DbgGetRegDumpEx`, `DbgGetThreadId`, `Script::Module::GetList`, `DbgDisasmAt` | paused | one generation recheck; max 16 registers and 64 instructions; module list released with `BridgeFree` |
| `debugger.wait_for_pause` | callback snapshot, `DbgGetRegDumpEx`, `DbgGetThreadId` | active debuggee; returns paused | condition-variable wait, max 9 s; copied latest reason; generation rechecked after register capture |
| `registers.read` | `DbgGetRegDumpEx` | paused | copied fixed-size dump; register-name allowlist |
| `address.resolve` | `Script::Module::GetList` | paused | unique module/RVA or absolute lookup; `BridgeFree(list.data)` |
| `memory.read` | `DbgMemRead` | paused | caller-owned buffer, max 64 KiB |
| `memory.map` | `DbgMemMap`, optional `Script::Module::GetList` | paused | reject native count above 65,536; max 256 filtered items; filter-bound cursor; all Bridge lists released |
| `modules.list` | `Script::Module::GetList` | paused | validates `ListInfo`; `BridgeFree(list.data)` |
| `threads.list` | `DbgGetThreadList` | paused | max 256 returned items; `BridgeFree(list.list)` |
| `breakpoints.list` | `DbgGetBpList` | paused/running | max 256 returned items; `BridgeFree(map.bp)` |
| `disassembly.read` | `DbgDisasmAt` | paused | max 256 instructions; size must be 1-15 |
| `expression.evaluate` | `DbgFunctions()->ValFromString` | paused | max 1024-byte expression; no command execution |
| pause/resume/step/stop | `DbgCmdExec` | operation-specific | fixed command; callback and generation confirmation |
| `memory.write` | `DbgMemWrite`, `DbgMemRead` | paused | max 4 KiB; read-back verification |
| breakpoint set/remove | `DbgCmdExec`, `DbgGetBpxTypeAt` | paused | validated address only; bounded observation loop |
| `debuggee.launch` | `DbgCmdExec` (`InitDebug`) | absent | canonical existing executable/directory; ignores transient process-created pause and confirms a later actionable callback |
| `analysis.function` | `DbgCmdExec` (`analr`), private command fence, `Script::Function::GetInfo` | paused | one resolved function in a module no larger than 128 MiB; queue-fence plus marker and generation confirmation; no GUI selection |
| `symbols.search` | `Script::Symbol::GetList` | paused | `BridgeFree(list.data)`; rejects count above 65,536; bounded literal filtering and generation recheck |
| `functions.list` | `Script::Function::GetList`, `Script::Symbol::GetList` | paused | both lists released with `BridgeFree`; each rejects count above 65,536; bounded name join and generation recheck |
| `strings.search` | `DbgMemRead`, Windows NLS literal span | paused | caller-owned 64 KiB chunks, 4 KiB fallback, at most 1 MiB/request; deadline/generation checks, cursor-bound `context_bytes`, and UTF-8-safe before/match/after |
| `references.to` | `DbgGetXrefCountAt`, `DbgXrefGet` | paused | `BridgeFree(info.references)`; rejects count above 65,536; inbound known-only references |

Pause metadata is copied synchronously from `CB_SYSTEMBREAKPOINT`,
`CB_BREAKPOINT`, `CB_EXCEPTION`, and `CB_STEPPED`. The plugin retains no callback
pointer. A following generic `CB_PAUSEDEBUG` cannot overwrite a specific reason
for the same stop. Stop, disconnect, and unload notify the same condition
variable used by active observation requests and stop the single-slot command
fence before joining the executor.

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

ADR 0007 discovery is enabled after schema, generation/deadline, filter-bound cursor, Unicode,
ownership, and isolated dual-architecture gates passed. It never triggers
analysis. ADR 0016 separately permits only address-taking `analr` with an
internal queue fence; GUI-selection-based analysis remains forbidden.
