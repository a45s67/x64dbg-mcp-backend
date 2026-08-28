# Field notes: Flare-On 11 `checksum.exe`

Date: 2026-08-29

Sample: `Flare-On11_Challenges/checksum.exe` (x64 Go executable)

This document records usability and API gaps observed while driving a real
reverse-engineering session through the x64dbg MCP backend. It is a backlog, not
an expansion of the current MVP contract or an automated release result. New
mutating APIs proposed here still require a threat-model ADR and contract tests.

## P0: session startup and recovery

### Add a debugger launch operation

Observed: after x64dbg and its backend were running, `debugger.state` reported
`plugin_state=ready` and `debuggee_state=absent`, but the published tools had no
way to open the sample. The operator had to open it through the debugger UI.

Suggested API:

```text
debuggee.launch(
  path,
  arguments?,
  working_directory?,
  break_on_entry?,
  operation_id
)
```

Separately, the working directory was significant to the exploratory automation
that launched x64dbg itself. Starting
`C:\tools\x64dbg\release\x64\x64dbg.exe` from an unrelated directory produced
an x64dbg process with no main window and no MCP sidecar; setting the working
directory to `release\x64` initialized both correctly. This is a test-harness
and bootstrap concern, not behavior promised by `debuggee.launch`.

Acceptance criteria:

- Canonicalize and validate the executable and working-directory paths.
- Return a callback-confirmed state rather than merely reporting process spawn.
- Report plugin/sidecar initialization failures with actionable diagnostics.
- Preserve mutation idempotency through `operation_id`.

Implemented in ADR 0002 as the first post-MVP capability. The initial contract
accepts `path`, optional `working_directory`, and `operation_id`; raw command-line
arguments and a configurable entry-break policy remain deferred until their
quoting and debugger semantics can be tested precisely. The isolated x32dbg
fixture passed the callback-confirmed launch workflow on 2026-08-29. The matching
x64 installed-backend workflow passed on the same date by launching this sample,
observing the initial system and PE-entry pauses, and reaching a relocated
`main.main` breakpoint.

### Recover after sidecar or debugger restart

Observed: closing x64dbg removed the listener at `127.0.0.1:43164`. Subsequent
calls failed at the transport layer. After x64dbg was reopened, the client did
not automatically rediscover or reconnect to the new sidecar.

Acceptance criteria:

- Distinguish backend-unavailable, authentication, and debugger-unavailable
  failures.
- Document that reconnect is a client or Gateway responsibility and provide the
  backend identity needed to do it without replaying mutations.
- Expose sidecar instance/generation identity so stale sessions are detectable.
- Document client behavior when a debugger closes during a request.

## P1: mutation ergonomics and execution control

### Describe the actual `operation_id` constraint

Observed: the readable unique value `checksum-resume-to-entry-001` was rejected
as `INVALID_ARGUMENT`. A UUID was accepted. The design document said UUID was
recommended, while the schema and runtime require a canonical lowercase UUID.

Acceptance criteria:

- Document canonical lowercase UUID as mandatory, matching the existing schema
  and runtime validation.
- Include the expected format in validation errors.
- Add contract tests for valid, invalid, reused, and ambiguous operation IDs.

### Add resume-until-pause semantics

Observed: `debugger.resume` returned `debuggee_state=running`; the caller then had
to sleep and poll `debugger.state` to discover the entry breakpoint and later
`main.main` breakpoint.

Suggested API:

```text
debugger.wait_for_pause(after_generation?, timeout_ms?)
```

Acceptance criteria:

- Keep `debugger.resume` as a separately callback-confirmed mutation, then wait
  from debugger callbacks rather than fixed sleeps.
- Return pause reason, instruction pointer, thread ID, breakpoint address/type,
  exception information, and state generation.
- Treat waiting as read-only observation so its timeout does not make the
  already-confirmed resume mutation ambiguous.

### Return richer pause reasons

Observed: initial pauses at the ntdll system breakpoint, PE entry breakpoint,
and a user breakpoint were distinguishable only by inspecting IP and the
breakpoint list.

Suggested result fields: `pause_reason`, `breakpoint`, `exception`,
`first_chance`, `thread_id`, and `state_generation`.

### Make paused snapshots internally consistent

Observed: during the initial loader pause, `debugger.state.instruction_pointer`
briefly differed from both `expression.evaluate("cip")` and `registers.read.rip`.
All three agreed after the user breakpoint at `main.main` was reached. Callers
should not have to guess whether a callback-derived state field or a synchronous
debugger-thread read is authoritative.

Acceptance criteria:

- Define the consistency boundary for a paused-state generation.
- Return the generation used by register, expression, and disassembly reads.
- Reject or clearly mark a result if execution changed while its snapshot was
  being collected.

### Preserve debugger text as UTF-8

Observed: the localized main-thread name was returned as mojibake while ASCII
module names and paths were correct. Normalize native debugger strings at the
plugin boundary and add a non-ASCII contract fixture.

## P1: module-relative analysis

### Accept module-relative addresses (implemented)

Observed: IDA used image base `0x400000`, while this x64dbg run loaded the sample
at `0xe90000`. The caller manually translated `main.main` from `0x4a78a0` to
`checksum.exe+0xa78a0`, then supplied absolute address `0xf378a0`.

Possible address forms include:

```text
checksum.exe+0xa78a0
module("checksum.exe").base+0xa78a0
```

A structured `{module, rva}` form or a separate `address.resolve` tool may be
safer and easier to validate than adding an expression grammar to every tool.

Acceptance criteria:

- Resolve unambiguously against the current module snapshot.
- Return both canonical absolute address and module/RVA.
- Reject missing or duplicate module names explicitly.
- Allow these forms anywhere an address is accepted, especially breakpoints,
  disassembly, memory reads, and expression evaluation.

Implemented in ADR 0003 with a closed `AddressRef` union, a read-only
`address.resolve` tool, and atomic native resolution for memory, breakpoint, and
disassembly tools. Arbitrary x64dbg expressions remain confined to
`expression.evaluate`. The x32 and x64 isolated fixtures passed absolute,
case-insensitive module/RVA, mutation replay, memory, disassembly, and breakpoint
coverage on 2026-08-29. The packaged installed backend then passed the
`checksum.exe` gate without client-side base arithmetic: the client supplied only
`{ "module": "CHECKSUM.EXE", "rva": "0xa78a0" }`, and resolve, memory,
disassembly, and breakpoint operations all reported the same runtime location.

## P2: reverse-engineering discovery tools

### Add symbols and functions

Observed: the sample retained Go symbols, including `main.main`, `main.a`, and
`main.b`, but x64dbg MCP exposed no symbol or function query. IDA MCP was needed
to locate the challenge logic.

Suggested read-only tools:

- `symbols.resolve(name|address)`
- `symbols.search(pattern, module?, cursor?, limit?)`
- `functions.list(module?, pattern?, cursor?, limit?)`
- `functions.at(address)`

### Add strings and cross-references

Observed: strings such as `Check sum: %d + %d =`, `FlareOn2024`, and
`REAL_FLAREON_FLAG.JPG` immediately explained the program, but MCP had no string
or xref discovery operations.

Suggested read-only tools:

- `strings.list/search(module?, pattern?, min_length?, cursor?, limit?)`
- `xrefs.to(address)` and `xrefs.from(address)`
- Include owning function and module/RVA in results.

These features should remain bounded and paginated. They may use x64dbg's
analysis database where available and clearly identify incomplete results.

## P2: output sizing and filtering

### Filter memory maps and snapshots

Observed: a single `memory.map(limit=100)` response contained a very large set of
system, reserved, heap, and image regions, obscuring the sample's sections and
causing tool output truncation.

Suggested filters:

- module or allocation base
- state/type/protection
- address range
- committed-only and executable-only flags

Also consider compact output modes that omit empty `info` fields and repeated
allocation metadata.

### Provide a compact analysis snapshot

The initial workflow required separate calls for state, modules, registers,
threads, breakpoints, memory map, and disassembly. Parallel calls worked, but the
combined result was unnecessarily large.

Suggested API:

```text
debugger.snapshot(
  registers?,
  disassembly_count?,
  include_threads?,
  include_breakpoints?,
  include_modules?
)
```

Default to a compact paused-state snapshot and keep memory maps opt-in.

## P1: ship an x64dbg workflow skill with the backend/plugin

Observed: the MCP tools expose debugger primitives, but the client had no
x64dbg-specific operating guidance comparable to the IDA MCP IDAPython skill.
This made important conventions discoverable only by trial and error: the
debugger must already own a debuggee, mutating calls require canonical UUID
operation IDs, reads generally require a paused target, and IDA image addresses
must be translated for ASLR before setting breakpoints.

Package a small versioned skill alongside the backend (or in the encompassing
Codex plugin) rather than embedding workflow prose in every tool description.
The backend remains the capability layer; the skill is the policy and recipe
layer.

Suggested skill contents:

- A state-machine table for absent, starting, running, paused, and stopped
  debuggees, including legal tools and recovery actions for each state.
- Module-relative address recipes: prefer `{module, rva}` directly on consuming
  tools; use `address.resolve` when the canonical runtime location must be
  inspected separately.
- Safe mutation rules: generate a new canonical lowercase UUID, preserve it
  across ambiguous retries, and never retry a different mutation with the same
  ID.
- A callback-oriented breakpoint loop: set breakpoint, resume, wait for pause,
  validate pause reason/IP, then capture a compact snapshot.
- Go-specific triage: use retained Go symbols when available, break at
  `main.main` rather than stepping from the PE/runtime entry point, and document
  the Go register ABI implications for arguments and return values.
- Bounded output recipes for memory maps, disassembly, strings, and snapshots.
- Troubleshooting for sidecar readiness, stale debugger generations,
  authentication failures, and target-loading/bootstrap limitations.

Acceptance criteria:

- The skill is versioned independently of the executable and names the minimum
  compatible backend protocol/version.
- Every recipe references actual published tool names and is covered by a small
  end-to-end fixture or recorded contract example.
- The skill does not silently broaden mutation authority; launch, write,
  breakpoint, resume, and stop operations remain explicit.
- Installation/registration makes the skill discoverable together with the MCP
  server without requiring users to copy private tokens into skill files.

## P2: improve transport and bootstrap diagnostics

Observed: liveness succeeded while the authenticated readiness endpoint
reported `debugger_state=absent`, accurately separating transport/plugin health
from target availability. A manual MCP POST without an explicit
`Accept: application/json` header failed with `INVALID_ACCEPT`; adding the
header fixed the request. Starting a second x64dbg process with the target path
did not transfer the target to the already-running headless instance.

Suggested improvements:

- Add the required `Accept` header to manual request examples and return the
  accepted media types in the validation error.
- Extend readiness or `debugger.state` with a short `next_actions`/diagnostic
  code for the absent-debuggee case, pointing clients to `debuggee.launch` once
  implemented or explicitly stating that UI loading is currently required.
- Document single-instance target handoff behavior and provide a supported,
  non-destructive way to load a target into an already-running debugger.

## Successful behavior worth preserving

- `debugger.state` clearly separated plugin and debuggee state.
- Entry breakpoint creation and callback-driven state updates worked.
- `breakpoints.set` correctly stopped at relocated `main.main`.
- Concurrent read-only calls for registers, modules, threads, breakpoints, and
  disassembly completed consistently while paused.
- Canonical hexadecimal addresses were consistent across results.

## Installed x64 validation record

On 2026-08-29, the packaged backend was installed into `C:\tools\x64dbg` and
`debuggee.launch` loaded the sample through the authenticated Streamable HTTP
endpoint. The observed runtime values were:

- module base `0xc20000`, PE entry `0xc83fe0`;
- `main.main` RVA `0xa78a0`, relocated address `0xcc78a0`;
- pause sequence: system breakpoint, PE entry, then the user breakpoint at
  `main.main`;
- x64 architecture, with the user breakpoint enabled and hit exactly once.

The main routine generates arithmetic prompts using the string
`Check sum: %d + %d = `. Its checksum validator XORs the candidate with the
repeating key `FlareOn2024`, Base64-encodes the result, and compares it with an
embedded 88-byte value. Reversing that transform yields the expected candidate:

```text
7fd7dd1d0e959f74c133c13abb740b9faa61ab06bd0ecd177645e93b1e3825dd
```

This run exercised launch, state, module enumeration, expression evaluation,
register reads, disassembly, memory reads, breakpoint creation, resume, and
thread/breakpoint enumeration against a real Go challenge binary. It also
confirmed that the missing wait-for-pause, module-relative addressing, symbol,
string, and cross-reference tools are practical workflow gaps rather than only
speculative backlog items.

The ADR 0003 installed-package rerun loaded the image at `0x770000` and resolved
`main.main` to `0x8178a0` directly from `{module, rva}`. It paused at the PE entry
and then at `main.main`; the structured breakpoint hit count was one. A first
monolithic PowerShell smoke runner used a 20-second HTTP timeout shorter than the
configured 30-second mutation deadline. Aborting an in-flight mutation left that
client session unable to continue safely, so the run was discarded rather than
blindly retried. Staged calls with client deadlines longer than backend mutation
deadlines completed normally. Keep test-client deadlines aligned with the
contract and implement `debugger.wait_for_pause` before replacing callback waits
with a large polling loop.

## 2026-08-29 callback-wait follow-up

ADR 0004 implements the recommendation above as a separate read-only
`debugger.wait_for_pause(after_generation, timeout_ms?)` operation. Resume,
pause, step, stop, and launch now return their callback-confirmed generation;
the wait observes only a newer retained pause and never changes mutation
identity or replay semantics.

The isolated x64 and x32 fixtures both completed resume-to-pause workflows
without sleep/state polling. Each observed a loader breakpoint with structured
address/type/hit metadata, a retryable wait timeout while stably running,
`user_pause` after explicit pause, and `step` after both step commands. The
native shutdown test also cancelled a nine-second active wait during plugin
drain in under three seconds on both architectures.

The first installed checksum smoke exposed a separate lifecycle bug:
`debuggee.launch` returned on `CB_CREATEPROCESS`, while x64dbg was still
initializing its debug objects. A resume accepted during that transient state
never became callback-confirmed before the mutation deadline. The operation was
not retried; the entire debugger session was closed.

ADR 0002 now requires launch to wait beyond `process_created` for an actionable
system/breakpoint/exception/step/user pause. After that change, a fresh installed
session resolved only `{module: "checksum.exe", rva: "0xa78a0"}`, set the
breakpoint, and reached it through resume -> callback wait. Evidence:

- resolved address `0x8178a0` from runtime module base `0x770000`;
- pause kind `breakpoint`, type `software`, hit count `1`;
- instruction pointer `0x8178a0`, active thread `0x1a4c`;
- pause generation `26`, followed by a callback-confirmed stop;
- no client-side base-plus-RVA calculation and no blind mutation retry.

## 2026-08-29 consistent-snapshot follow-up

ADR 0005 adds optimistic generation capture/recheck to all state-sensitive
reads. In the installed checksum session, the main breakpoint pause, `rip/rsp`
register snapshot, 16-byte module-relative memory read, and four-instruction
module-relative disassembly all reported generation `27`. The memory and
disassembly location metadata carried the same generation. Both isolated
architectures also rejected a memory-map cursor after a step advanced debugger
state, so stale pagination cannot silently mix snapshots.

## 2026-08-29 native UTF-8 follow-up

ADR 0006 replaces byte-wise JSON emission with bounded UTF-8 validation and
replacement, escapes controls without discarding surrounding text, and compares
module identities through Windows ordinal Unicode case folding. Embedded controls
are now rejected before expressions reach NUL-terminated native APIs.

The first Unicode integration request exposed a Windows PowerShell 5 client-body
encoding bug and was rejected by the server parser before any launch mutation was
accepted. Sending explicit UTF-8 request bytes fixed that boundary. A later run
showed response mojibake because PowerShell ignored JSON's default encoding, so all
MCP, health, and structured-error JSON responses now explicitly declare
`application/json; charset=utf-8`.

After those fixes, isolated x32dbg and x64dbg both launched
`München-分析.exe` from an `整合-utf8` directory. `modules.list` preserved the
lowercase Unicode module name, while `address.resolve` accepted its uppercased
Unicode spelling and returned the entry RVA. Both runs also completed the full
snapshot, stale-cursor, mutation-replay, callback wait/pause, stepping, stop, and
supervised-shutdown checks.

The installed-package acceptance run copied Flare-On 11 `checksum.exe` to
`Flare-驗證-native-utf8/München-checksum.exe`, then supplied only the uppercased
module identity `MÜNCHEN-CHECKSUM.EXE` and RVA `0xa78a0`. The backend resolved
runtime base `0x290000`, hit `0x3378a0` once, reported generation `28` consistently
for pause/register/memory/disassembly results, and stopped cleanly.

## 2026-08-29 bounded discovery follow-up

ADR 0007 adds four paused-state, known-only tools: `symbols.search`,
`functions.list`, `strings.search`, and inbound `references.to`. All use
generation-bound opaque cursors, bounded native ownership, Unicode literal
matching, structured module/RVA locations, and no implicit analysis mutation.
Long string candidates return UTF-8-safe context around the actual match plus
`match_offset` and `text_offset`, rather than hiding a late match by always
returning the first 512 bytes.

Fresh isolated trees containing the exact final dp32/dp64 artifacts passed the
complete real integration suite. Both architectures found three fixture
symbols, one ASCII/UTF-8 sentinel, and one UTF-16LE sentinel; both reported zero
known functions and inbound references without overstating completeness. They
also rejected filter-mismatched and stale-generation discovery cursors while
keeping the connection alive, then completed pause, step, breakpoint, stop, and
supervised sidecar shutdown checks.

The x32 run exposed a real callback-order race: x32dbg may emit
`CB_PAUSEDEBUG` before `CB_STEPPED`. Step mutations now wait for the specific
newer `step` observation instead of accepting the intermediate generic paused
state. The final x32 and x64 runs both retained `step` for step-into and
step-over.

The installed `checksum.exe` run loaded at `0x770000`, resolved
`{module: "CHECKSUM.EXE", rva: "0xa78a0"}` to `0x8178a0`, hit it once, and
reported generation `27` consistently for pause, register, memory, and
disassembly snapshots. Bounded paginated string discovery found both
`FlareOn2024` and `Check sum: %d + %d = ` on the first 1 MiB page, including
the query within returned long-string context. The current x64dbg database
reported zero retained `main.main` symbols, functions, and inbound references;
those empty results correctly remained `known_only` rather than being treated
as proof of absence. The debuggee and plugin-owned sidecar stopped cleanly.

A final review tightened candidate extraction so an invalid high byte terminates
an ASCII/UTF-8 candidate instead of causing adjacent valid text to be discarded;
UTF-16 surrogate validity and long-candidate deadline/generation checks were
tightened at the same time. The rebuilt installed artifact repeated the same
checksum workflow at generation `26`, found both literals, and shut down cleanly.

## 2026-08-29 workflow-skill follow-up

ADR 0008 packages the independently versioned `x64dbg-debugging` Codex skill.
Its entrypoint keeps only shared state, module/RVA, callback-wait, known-only,
and no-blind-retry invariants; detailed recipes and troubleshooting are loaded
from separate references. The skill contains no token, port, target path, or
sample-specific RVA.

The release gate validates UTF-8, frontmatter bounds, version metadata, resolved
references, published tool names, ownership marker, absence of token assignments,
and unfinished placeholders. The skill creator's Python validator could not run
because the available Python environment lacks PyYAML, so equivalent
repository-specific checks were added as a dependency-free PowerShell contract
instead of adding a runtime prerequisite. Registration tests covered first install, idempotent
update, `-SkipSkill`, token non-disclosure, and refusal to overwrite an unmanaged
same-named skill without writing a partial Codex config.

All four installed skill files matched their packaged SHA-256 values. Following
the packaged breakpoint recipe against the deployed backend again loaded
`checksum.exe` at `0x770000`, resolved `main.main` RVA `0xa78a0` to `0x8178a0`,
observed one software breakpoint hit, and retained generation `27` across pause,
register, memory, and disassembly results. The bounded string recipe found both
known literals, reported empty discovery databases as `known_only`, and stopped
the debuggee and sidecar cleanly without a blind mutation retry.

## 2026-08-29 compact snapshot and memory-map follow-up

ADR 0009 adds `debugger.snapshot` for the frequent paused-state question of
which thread stopped, where its instruction pointer is, and what the nearby
instructions are. The default response is deliberately fixed at four portable
registers and eight instructions. It captures one callback generation and
rechecks that exact paused generation after native register, module, and
disassembly reads. `memory.map` now supports module-overlap, committed,
executable-protection, and compact-shape filters with v2 cursors bound to every
filter and the debugger generation.

Fresh isolated x32 and x64 fixtures each returned an eight-instruction compact
snapshot and one bounded committed executable region overlapping the fixture
module. Both rejected a cursor reused with different filters as
`INVALID_ARGUMENT`, rejected the same-generation cursor after stepping as
`STALE_CURSOR`, kept the connection usable after both errors, and completed the
existing mutation-replay, callback, stop, and supervised-shutdown checks. Rust
kept 44 passing tests; each native architecture now has seven passing tests,
including pure executable-protection and overflow-safe range-overlap coverage.

The deployed `checksum.exe` acceptance run loaded the image at `0x770000`,
resolved `{module: "CHECKSUM.EXE", rva: "0xa78a0"}` to `0x8178a0`, and hit the
software breakpoint once. Pause, registers, memory, disassembly, compact
snapshot, and filtered memory map all retained generation `27`; the compact
snapshot contained eight instructions and the module-filtered committed
executable map returned one region. Both known strings were still found on the
first bounded page, then the debuggee and plugin-owned sidecar stopped cleanly.

## 2026-08-29 actionable diagnostics follow-up

ADR 0010 keeps backend readiness separate from debuggee availability while
making the absent state actionable. Authenticated readiness and
`debugger.state` now return `NO_DEBUGGEE` with exactly one non-executing action
hint naming `debuggee.launch`; once a target is active they return a null code
and an empty action list. A disconnected manual diagnostic sidecar reports
`PLUGIN_DISCONNECTED`. HTTP Accept, Content-Type, and protocol-version failures
now include only their bounded accepted values in structured `details`.

Rust contract coverage increased to 46 tests. Fresh isolated x32 and x64 runs
both observed the launch hint before the fixture mutation, verified that it was
cleared in the paused state, then completed compact snapshots, filtered memory
maps, cursor failures, mutation replay, stepping, stop, and supervised shutdown.
Each native architecture retained seven passing tests.

The deployed `checksum.exe` acceptance run followed the advertised launch action,
again loaded at `0x770000`, resolved RVA `0xa78a0` to `0x8178a0`, and hit the
software breakpoint once. All paused reads retained generation `27`, both known
strings were found on the first bounded page, and closing the debugger left no
plugin-owned sidecar running. Documentation now explicitly states that launching
a second debugger is not an MVP target-handoff mechanism.
