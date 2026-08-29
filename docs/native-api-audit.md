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
paths in fixed quoted `scriptcmd init` positions. Structured arguments are
Windows-quoted by the plugin and committed at the initial actionable pause with
`DBGFUNCTIONS::SetCmdline`, never inserted as caller command syntax. A failure
after launch submission is outcome-unknown and is never retried automatically.

`debuggee.attach` accepts only a validated numeric PID, rejects the debugger
host and owned sidecar PIDs, and renders the fixed command as hexadecimal. It
does not enumerate or pre-open processes. `debuggee.detach` contains no caller
text. Both operations use callback-maintained session origin and report a
post-admission timeout as an unknown mutation outcome.

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
| `callstack.read` | `DbgGetThreadList`, `DBGFUNCTIONS::GetCallStackByThread` | paused | exact current/supplied thread handle; native maximum 50 frames; both Bridge allocations released; empty result labeled inconclusive |
| `breakpoints.list` | `DbgGetBpList`, `MemBpSize` | paused/running | max 256 returned items; `BridgeFree(map.bp)`; typed hardware access/size/slot and memory access/size |
| `disassembly.read` | `DbgDisasmAt` | paused | max 256 instructions; size must be 1-15 |
| `expression.evaluate` | `DbgFunctions()->ValFromString` | paused | max 1024-byte expression; no command execution |
| pause/resume/step-in/step-over/stop | `DbgCmdExec` | operation-specific | fixed command; callback and generation confirmation |
| `debugger.step_out` | `DbgCmdExec` (`rtr`), `DbgGetRegDumpEx`, `DbgDisasmAt` | paused | newer paused callback, copied CIP/CSP/reason, exact generation recheck; return+CSP postcondition distinguishes completion from an intervening pause |
| `registers.write` | `Script::Register::Set`, `DbgGetRegDumpEx` | paused | one allowlisted full-width core register; before/after snapshots, exact read-back, and generation recheck; no batch |
| `memory.write` | `DbgMemWrite`, `DbgMemRead` | paused | max 4 KiB; read-back verification |
| breakpoint set/remove | `DbgCmdExec`, `DbgGetBpxTypeAt` | paused | validated address only; bounded observation loop |
| typed hardware breakpoint set/remove | fixed `bphws`/`bphwc`, `GetBridgeBp`, `DbgGetBpList` | actionable pause | enum-only command composition; x86/x64 size/alignment; four enabled slots; exact access/size/slot read-back; shape-matched remove |
| typed memory breakpoint set/remove | fixed `bpmrange`/`bpmc`, `DbgMemFindBaseAddr`, `GetBridgeBp`, `MemBpSize` | paused | 1-65536 bytes in one region; exact access/size read-back; shape-matched remove |
| `assembly.preview` | `DBGFUNCTIONS::Assemble` | paused | one printable ASCII instruction; fixed 16-byte output and 256-byte printable error bound; no memory or patch call |
| `assembly.patch` | `Assemble`, `PatchInRange`, `DbgMemRead`, `MemPatch`, `PatchGetEx` | paused | exact 1-16 byte compare-before-write; no overlapping tracked patch; one mutation call; exact memory and per-byte patch-record verification |
| `patches.restore` | `DbgMemRead`, `PatchGetEx`, `PatchRestoreRange`, `PatchInRange` | paused | exact patched/original preconditions; one inclusive range restore; exact read-back and empty patch-range confirmation |
| `patches.list` | `PatchEnum`, `DbgMemRead`, `Script::Module::GetList` | paused | same-executor-thread byte-size probe/enumeration/reprobe; max 65,536 zero-initialized records and current bytes; sorted adjacent ranges; content-fingerprint cursor; all Bridge lists released |
| `debuggee.launch` | `DbgCmdExec` (`scriptcmd init`), `DBGFUNCTIONS::SetCmdline` | absent | canonical existing executable/directory; path-only fixed command; confirms an actionable initial pause, then commits an independently Windows-quoted command line before resume; post-submit failure is outcome-unknown |
| `debuggee.attach` | `DbgCmdExec` (`attach 0x<pid>`) | absent | rejects debugger/sidecar PIDs; matching pre-attach `CB_ATTACH` PID, then a newer paused callback and current PID; no enumeration or process handle retained |
| `debuggee.detach` | `DbgCmdExec` (`detach`) | attached and paused/running | matching `CB_DETACH`, then newer `CB_STOPDEBUG`; preserves the externally owned process; generic stop is rejected |
| `analysis.function` | `DbgCmdExec` (`analr`), private command fence, `Script::Function::GetInfo` | paused | one resolved function in a module no larger than 128 MiB; queue-fence plus marker and generation confirmation; no GUI selection |
| `symbols.search` | `Script::Symbol::GetList` | paused | `BridgeFree(list.data)`; rejects count above 65,536; bounded literal filtering and generation recheck |
| `symbols.resolve` | `Script::Symbol::GetList`, `Script::Module::GetList` | paused | exact case-sensitive name or exact runtime address; max 65,536 records scanned and 32 matches returned; both lists released; missing and ambiguous are explicit success states |
| `functions.list` | `Script::Function::GetList`, `Script::Symbol::GetList` | paused | both lists released with `BridgeFree`; each rejects count above 65,536; bounded name join and generation recheck |
| `functions.at` | `Script::Function::GetInfo`, `Script::Module::GetList` | paused | one known-only containing marker; validates module ownership and inclusive range; module list released; never queues analysis |
| `imports.list` | `Script::Module::GetImports`, `DbgMemRead`, `Script::Module::GetList` | paused | exact loaded module; max 65,536 owned records; max 256 architecture-width IAT reads/page; fixed UTF-8 fields and IAT VA/RVA validated; both Bridge lists released |
| `exports.list` | `Script::Module::GetExports`, `Script::Module::GetList` | paused | exact loaded module; max 65,536 owned records; fixed UTF-8 fields and VA/RVA validated; ordinal and forwarder metadata copied; both Bridge lists released |
| `strings.search` | `DbgMemRead`, Windows NLS literal span | paused | caller-owned 64 KiB chunks, 4 KiB fallback, at most 1 MiB/request; deadline/generation checks, cursor-bound `context_bytes`, and UTF-8-safe before/match/after |
| `references.to` | `DbgGetXrefCountAt`, `DbgXrefGet` | paused | `BridgeFree(info.references)`; rejects count above 65,536; inbound known-only references |

Pause metadata is copied synchronously from `CB_SYSTEMBREAKPOINT`,
`CB_BREAKPOINT`, `CB_EXCEPTION`, and `CB_STEPPED`. The plugin retains no callback
pointer. A following generic `CB_PAUSEDEBUG` cannot overwrite a specific reason
for the same stop. `CB_ATTACH` and `CB_DETACH` copy their PID values immediately;
no callback `PROCESS_INFORMATION` pointer is retained. Session origin is cleared
by `CB_STOPDEBUG`. Stop, disconnect, and unload notify the same condition variable
used by active observation requests and stop the single-slot command fence before
joining the executor.

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

ADR 0023 adds no debugger API. The plugin stores only the sidecar-generated
canonical `instance_id` received after authenticated IPC negotiation, copies it
under the existing state mutex into `debugger.state`, and clears it during owned
shutdown. The public mutation precondition is enforced and removed by Rust
before native IPC dispatch, so it does not broaden the native parser or executor.

ADRs 0024-0027 add only paused-state reads on the existing serialized executor.
Call-stack and patch buffers follow their documented Bridge/native ownership;
patch size probe and enumeration cannot move between OS threads. Exact symbol
and function lookup never trigger analysis and preserve explicit known-only or
inconclusive completeness.

ADR 0007 discovery is enabled after schema, generation/deadline, filter-bound cursor, Unicode,
ownership, and isolated dual-architecture gates passed. It never triggers
analysis. ADR 0016 separately permits only address-taking `analr` with an
internal queue fence; GUI-selection-based analysis remains forbidden.
