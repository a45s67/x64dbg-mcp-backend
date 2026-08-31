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

## 2026-08-29 bounded shutdown-matrix follow-up

ADR 0011 records the reachable HTTP-to-IPC shutdown states. The sidecar admits
bounded concurrent HTTP requests but deliberately serializes its single
authenticated IPC stream, so the matrix distinguishes one request already on
the wire from reads or mutations waiting for the IPC mutex. It also requires an
unanswered mutation to appear on IPC exactly once and forbids detached cleanup
workers or process-name-wide termination in tests.

The real-sidecar supervised suite now covers idle EOF, active read, queued read,
queued mutation, active mutation without a reply, and an HTTP client disconnect.
All six cases exited inside the shortened drain deadline. The full Rust gate
retained 46 unit and contract tests, Clippy remained warning-free, and both x32
and x64 native suites retained seven passing lifecycle/unit tests. A new opt-in
integration soak runner bounds repetition to 1--20 iterations and verifies after
every isolated debugger run that the owned sidecar exited and its loopback port
closed. One x32 plus one x64 real integration cycle passed those ownership
checks without terminating any process by image name.

After packaging and installing both architectures, the `checksum.exe` acceptance
run loaded at `0x770000`, resolved `{module: "CHECKSUM.EXE", rva: "0xa78a0"}` to
`0x8178a0`, and observed one software-breakpoint hit. Pause, registers, memory,
disassembly, compact snapshot, and filtered memory-map reads retained generation
`28`; the compact snapshot returned eight instructions and the executable module
filter returned one region. Both known strings remained discoverable on their
first bounded page, `debugger.stop` reported `absent`, and debugger closure left
the installed sidecar stopped.

## 2026-08-29 deterministic robustness follow-up

ADR 0012 adds fixed-seed, dependency-free malformed-input corpora to the normal
release gate without claiming they replace coverage-guided fuzzing. Rust now
executes 4,096 arbitrary bounded IPC frames, 4,096 generated argument shapes
distributed across all 25 tool validators, and 2,048 structured plus 2,048 raw
MCP bodies. Accepted IPC values must round-trip canonically, and every MCP body
must produce bounded protocol JSON. The native UTF-8 test in each architecture
now escapes 4,096 byte strings up to 256 bytes and checks output size, quoting,
valid UTF-8, and case-search safety.

Rust coverage increased from 46 to 49 unit/contract tests plus the six supervised
shutdown cases. Clippy rejected the first corpus implementation's potentially
truncating test-only integer casts; checked conversions now preserve x32 safety.
One parallel idle-shutdown repetition also exposed an ephemeral-port test race
between selection and sidecar bind. The harness now serializes only that startup
window, proves the HTTP listener is bound, and owns the child before the probe so
failure cleanup remains deterministic. Five consecutive parallel matrix runs,
both native seven-test suites, and fresh isolated x32/x64 integration runs then
passed; both owned sidecars exited and both loopback ports closed.

The installed `checksum.exe` acceptance run again loaded at `0x770000`, resolved
RVA `0xa78a0` to `0x8178a0`, hit the software breakpoint once, and retained
generation `27` across pause, registers, memory, disassembly, compact snapshot,
and filtered map results. Eight compact instructions, one executable module
region, and both known strings were returned within their bounds. The explicit
stop reported `absent`, with no mutation retry or remaining sidecar.

## 2026-08-29 idempotent install and package-verification follow-up

ADR 0013 separates routine binary updates from credential rotation. A first
install still generates one random 48-byte token, but a normal reinstall now
preserves a valid shared token and any port not explicitly supplied. A partial
single-config repair reuses the remaining credential. Divergent x32/x64 tokens
fail before binary copies, while `-RotateToken` is the only intentional rotation
path. Installation remains plain copy plus TOML writes and still performs no ACL,
environment, Codex, or unrelated-plugin mutation.

The disposable installer contract covers first install, idempotent binary update,
explicit ports, partial repair, mismatch failure without partial writes, explicit
rotation, equal-port rejection, secret non-disclosure, and `-WhatIf`. The shipped
offline verifier strictly checks every manifest path and SHA-256, rejects missing
or unlisted files, validates version and CycloneDX metadata, and parses PE headers
to require x86 dp32 plus x64 dp64/sidecar. The package gate verified the real
34-file release, then proved a tampered file and an unlisted file fail validation.

Reinstalling that extracted package over `C:\tools\x64dbg` reported the token as
preserved; an in-process before/after comparison confirmed equality without
printing it. Codex registration was refreshed using the same static header. The
installed `checksum.exe` acceptance run then loaded at `0x770000`, resolved RVA
`0xa78a0` to `0x8178a0`, hit the breakpoint once, and retained generation `27`
across all paused snapshots. It returned eight compact instructions, one filtered
executable region, both known strings, and an explicit stopped state with no
remaining sidecar.

## 2026-08-29 unified release-gate follow-up

ADR 0014 now separates locally reproducible release acceptance from publisher
qualification. `scripts/run-release-gate.ps1` composes the locked package gate,
isolated x32dbg/x64dbg integration, sidecar/port shutdown assertions, and an
optional installed Flare-On qualification into one JSON evidence report. Signing
and a pristine Windows VM remain explicitly `not_run` rather than being inferred
from checksums or a developer-machine integration copy.

The first composed run found that `run-integration-soak.ps1` wrote human progress
to stdout, so its otherwise successful JSON could not be parsed. Progress now uses
the verbose stream and stdout is machine-readable JSON. A direct x32/x64 rerun
confirmed two runs, both owned sidecars exited, and both loopback ports closed.

The corrected complete gate produced package SHA-256
`448c2bce40cbea5ad671ca88549dd8b3f26f1e64448d70b659c93bbe9844a9ab`.
The installed `checksum.exe` qualification resolved `CHECKSUM.EXE+0xa78a0` from
base `0x770000` to `0x8178a0`, hit the software breakpoint once, preserved state
generation 27 across registers, memory, disassembly, compact snapshot, memory-map,
and discovery reads, found both known strings on the first bounded page, stopped
the debuggee, and left no owned sidecar.

The full localized MSVC build also exposed excessive raw `/showIncludes` output.
The native build wrapper now selects the UTF-8 console code page before CMake's
localized prefix probe so CMake/Ninja can recognize and suppress the compiler's
dependency lines consistently.

## 2026-08-29 token-efficient string-context follow-up

ADR 0015 adds `context_bytes` (0 through 128, default 64 with a query) and
reconstructable `before`, `match`, and `after` fields to `strings.search` while
preserving candidate address, byte length, `text`, and offset metadata. The exact
Windows NLS match span is retained instead of assuming case-equivalent UTF-8 has
the same byte length. Context is part of the opaque cursor fingerprint and is
rejected without a query.

The wire-contract addition advances the backend package and managed skill to
0.2.0. Rust retained 49 unit/contract tests plus six supervised shutdown cases,
and both native architectures passed all seven tests. Fresh isolated x32dbg and x64dbg
trees verified zero-context ASCII/UTF-16LE matches, exact text reconstruction,
context-bound cursor rejection, connection survival, and complete sidecar/port
shutdown. The package, installer, verifier, and managed skill 0.2.0 gates passed.

After deploying the final 0.2.0 package for both plugin architectures, preserving
the installed token, and refreshing the Codex registrations, the `checksum.exe`
run loaded at base `0x380000`, resolved RVA `0xa78a0` to `0x4278a0`, hit the
software breakpoint once, and retained generation 27 across
all paused reads. With 32 bytes requested on each side, the former long Go string
pool previews shrank to 75 bytes for `FlareOn2024` and 85 bytes for
`Check sum: %d + %d = `; both exact match fields remained visible on page one.
The debuggee stopped and its owned sidecar exited.

## 2026-08-29 explicit function-analysis follow-up

ADR 0016 rejects x64dbg's GUI-selection-dependent whole-module analysis commands
as an unstable MCP contract. `analysis.function` instead accepts one structured
address and operation ID, submits only `analr <validated-address>`, and waits for
an internally correlated private command fence before checking the resulting
function marker. The target module is capped at 128 MiB, analysis remains a
visible mutation, and timeout or fence rejection is never blindly retried.

The new single-slot `CommandFence` owns no thread and its native tests cover
correlation mismatch, completion, timeout, cancellation, stop wakeup, and restart.
Rust retained 49 unit/contract tests plus six shutdown tests. Both x32 and x64
native suites passed eight tests. Fresh isolated debugger trees then analyzed an
exported fixture target by module/RVA, replayed the same operation ID without a
second mutation, observed the resulting marker through bounded `functions.list`
pagination, stopped both sidecars, and left both loopback ports closed.

The final backend and managed skill advance to 0.3.0. After deployment with the
existing token preserved, `checksum.exe` initially returned no named main
function. Explicit analysis at `CHECKSUM.EXE+0xa78a0` resolved to `0x4278a0`,
reported `already_known: false`, installed the inclusive marker
`0x4278a0..0x42806b`, and made it visible through known-only discovery. The
analysis left generation 27 unchanged, replayed byte-for-byte under the same
operation ID, exposed one inbound main reference, and ended with the debuggee
stopped and no owned sidecar.

## 2026-08-29 attach/detach lifecycle follow-up

ADR 0017 adds PID-only `debuggee.attach`, explicit `debuggee.detach`, and
callback-maintained `session_origin`. It deliberately does not enumerate local
processes. PIDs are validated as JSON integers, rendered as x64dbg hexadecimal
constants, and correlated with `CB_ATTACH`, a later paused callback, and the
current process ID. Attached sessions reject `debugger.stop`; detach requires
`CB_DETACH` followed by `CB_STOPDEBUG`, preventing generic cleanup from killing a
process the debugger did not create.

The first x64 integration exposed that this x64dbg build can hand control back on
the attached process's `process_created` pause without emitting a distinct later
system-breakpoint callback. The contract now accepts that paused callback only
after the matching pre-attach PID event; launch continues to ignore its transient
process-created pause. A 500 ms native response margin also prevents an exact
deadline race from leaving an unread late IPC response after unknown outcomes.

Fresh isolated x32 and x64 tests independently started architecture-matched
fixtures, rejected self-attach, attached by numeric PID, replayed the same
operation result, rejected destructive stop, detached, and proved each fixture
remained alive. Test cleanup then terminated only its own exact fixture PID. The
backend and workflow skill advance to 0.4.0. `checksum.exe` was not used as the
attach target because it is not a stable long-running benign lifecycle fixture.

The final package gate retained 49 Rust unit/contract tests, six supervised
shutdown tests, and eight native tests on each architecture. An integration
runner issue found during the final x32 rerun was independent of MCP: PowerShell
`Start-Process` could block while starting the 32-bit GUI before returning its
process handle. The runner now creates explicitly owned `.NET Process` instances
with `UseShellExecute=false`; both x32 and x64 then completed attach/detach in a
bounded run with no debugger, sidecar, or fixture left behind.

Package SHA-256 is
`0262abcd35c06e7c91fea9bf89be2f95e0d55e5b7b9e5c2c4a5dd4a1eecf149b`.
Deployment preserved the installed bearer token, refreshed both static Codex
registrations, and installed workflow skill 0.4.0. The installed regression run
loaded `checksum.exe` at `0x1000000`, resolved RVA `0xa78a0` to `0x10a78a0`, hit
the software breakpoint once, held generation 27 across all paused reads, replayed
the existing analysis result exactly, found both compact-context strings on page
one, stopped the launched debuggee, and left no owned sidecar.

## 2026-08-29 verified register-write and step-out follow-up

ADR 0018 adds one-register `registers.write` and callback-confirmed
`debugger.step_out`. Register writes accept only architecture-appropriate
full-width core registers and canonical hexadecimal values. The plugin uses the
typed register SDK, takes before/after register dumps, verifies exact readback,
and records the result under the operation ID. Partial, vector, segment, and
debug-register writes remain outside this stage.

Step-out submits the fixed x64dbg `rtr` command, then waits for a newer paused
callback instead of sleeping. Its result includes the pause reason, final
CIP/CSP, decoded instruction, and `completed`. Completion is true only when the
initial instruction decoded as a return and the final stack pointer satisfies
the expected postcondition. A breakpoint or exception that interrupts the
operation is a successful observation with `completed: false`, not a falsely
reported return and not a reason to retry the mutation blindly.

A focused review compared three pinned local implementations: the Zig
`x64dbg-mcp-server` fine-grained catalog, the layered C++ `x64dbg-mcp`, and the
TypeScript action-based `x64dbg_mcp`. We retained atomic backend-local tools and
adopted workflow-oriented descriptions plus strict breakpoint validation. We did
not adopt mega-action unions, arbitrary debugger-command interpolation, fixed
sleeps, batch partial mutations, or mutation contracts without replay identity.
The durable comparison is in `reference-implementation-review.md`.

Rust retained 49 unit/contract tests and six supervised-shutdown tests. Both
native architectures passed nine tests, including the new register-policy suite.
Fresh isolated x32 and x64 integrations each wrote EDI/RDI, proved exact
readback and byte-identical operation replay, restored the original value under
a fresh operation ID, and rejected an over-wide EFLAGS value. Each architecture
also proved that a breakpoint can interrupt step-out with `completed: false`,
then removed it and confirmed a normal return with `completed: true`; both
sidecars stopped cleanly.

The installed `checksum.exe` regression again resolved `CHECKSUM.EXE+0xa78a0`
to `0x10a78a0`, hit the software breakpoint at generation 27, retained stable
paused reads, replayed function analysis, and found both bounded string previews.
It then changed RDI to `0x11223344`, observed exact replay and readback, restored
the original `0x1`, stopped the debuggee, and left no owned sidecar. Step-out was
not forced through this large interactive Go main function; the deterministic
x32/x64 fixture remains the mandatory step-out qualification target.

The backend and managed skill advance to 0.5.0. Package SHA-256 is
`80290feb663e4acdd3c00b5b579f3d1209111c22b57cf3b85a6bedd51e446cde`.
Deployment preserved the installed bearer token and refreshed both static Codex
registrations.

## 2026-08-29 typed hardware and memory breakpoint follow-up

ADR 0019 keeps software breakpoints separate and adds four atomic typed tools:
hardware set/remove and memory set/remove. Hardware requests use explicit
execute/write/read-write access, architecture-supported 1/2/4/8-byte sizes,
natural alignment, and a four-slot preflight. Memory requests use explicit
access/read/write/execute semantics and an exact 1-65536 byte range contained in
one current memory region. Remove requires the same access and size observed at
the address, preventing an address-only command from deleting externally changed
state.

The native executor composes only fixed `bphws`/`bphwc` and
`bpmrange`/`bpmc` commands from validated enum and integer fields. Confirmation
uses typed bridge breakpoint records plus exact hardware size/slot or memory
range size. A mismatch after command admission remains an unknown mutation
outcome; the backend does not issue a speculative cleanup command.

Integration exposed two lifecycle/contract details. First, x64dbg can reset
hardware debug registers while leaving initial `process_created` or
`system_breakpoint` startup pauses. The backend now rejects hardware setup in
both states and requires a later callback-confirmed pause. Second, the Rust IPC
stable-code allowlist initially mapped the new `CONFLICT`, `ALREADY_EXISTS`, and
`RESOURCE_EXHAUSTED` native codes to fail-closed `INTERNAL`. Those codes are now
explicitly preserved and covered by contract tests.

Rust retained 49 unit/contract tests and six supervised-shutdown tests. Both
native architectures passed ten tests, including architecture size/alignment,
four-slot, range-containment, and read-back policy. Fresh isolated x32 and x64
runs rejected the startup pause and a misaligned data breakpoint; x32 also
rejected an 8-byte hardware request. Both runs then hit an execute hardware
breakpoint in slot 0, hit a 4-byte marker-read memory breakpoint, listed their
typed fields, rejected mismatched removals with `CONFLICT`, replayed set/remove
results exactly, removed all typed state, and stopped with no owned sidecar.
Cross-region memory ranges were rejected before command submission.

The installed 0.6.0 `checksum.exe` regression loaded at `0x1000000`, resolved
`CHECKSUM.EXE+0xa78a0` to `0x10a78a0`, and retained generation 27 across its
initial paused reads. After the prior analysis, compact-string, and reversible
RDI checks, an execute hardware breakpoint hit the next instruction at
`0x10a78a8`. It was exactly removed, then a six-byte execute memory breakpoint
hit the following instruction at `0x10a78ac`. Both set and remove operations
replayed exactly, the debuggee stopped, and the owned sidecar exited.

The backend publishes 34 tools and managed skill 0.6.0. Package SHA-256 is
`db1c20ae4d786891ea7599ffc63ea5283798694590357fdddd13942232a1d38f`.
Deployment preserved the installed bearer token and refreshed both static Codex
registrations.

## 2026-08-29 bounded assembly and verified patch follow-up

ADR 0020 separates read-only `assembly.preview` from destructive
`assembly.patch` and `patches.restore`. All three accept structured addresses and
one instruction span of at most 16 bytes. Patch requires exact current bytes and
an empty x64dbg patch range before its single `MemPatch` call; restore requires
both expected patched bytes and the original bytes recorded per changed byte.
Unknown postconditions are reported without automatic rollback or a second
mutation.

Rust retained 49 unit/contract tests and six supervised-shutdown tests. Both
native architectures now pass eleven tests, including the new patch policy
suite. Fresh isolated x32 and x64 runs previewed `int3`, rejected stale expected
bytes and an overlapping tracked range, patched and NOP-padded one fixture
instruction, replayed both mutations byte-identically, restored the exact
original bytes, and exited with both loopback ports closed.

The installed `checksum.exe` qualification resolved `CHECKSUM.EXE+0xa78a0` to
`0x10a78a0` at generation 27. Before execution it patched the following
four-byte instruction at `0x10a78a8` to `int3` plus NOP padding, confirmed exact
operation replay and x64dbg patch tracking, then restored and re-read the
original bytes. The restored instruction subsequently executed and hit the
existing hardware-breakpoint qualification at the same address; a six-byte
memory breakpoint then hit at `0x10a78ac`. The debuggee stopped, the owned
sidecar exited, and no listener remained.

The backend publishes 37 tools and the backend/managed skill advance to 0.7.0.
Deployment preserves both config-file bearer tokens and refreshes the two Codex
entries with static Authorization headers. The final offline-verified package
SHA-256 is
`1173aa212815c6dc3f39c1516e96daa8772781fc272cceef11a8d941912720c3`.

## 2026-08-29 backend instance identity and restart-safety follow-up

ADR 0023 separates sidecar correlation from both debugger generation and the
secret launch nonce. Each sidecar now creates one UUID v4, transfers it to the
plugin in IPC protocol 1.1, and exposes the same value through authenticated
readiness, MCP initialization metadata, and `debugger.state`. Every mutation
requires that observed `instance_id` plus its own operation UUID. A mismatch
returns non-retryable `BACKEND_RESTARTED` with an unknown outcome before ledger
admission or native dispatch.

Rust passes 52 unit/contract tests and seven supervised-shutdown tests. The new
restart case stops one supervised sidecar, confirms the replacement UUID differs,
sends a stale resume request, observes `BACKEND_RESTARTED`, and proves no frame
crossed the replacement plugin pipe. The x86 and x64 native suites each pass all
11 lifecycle/policy tests. Fresh isolated x32 and x64 workflows reported distinct
canonical identities, exercised the full existing catalog, closed their owned
sidecars, and released both loopback listeners. The soak harness now performs
unprivileged before/after PID ownership checks instead of depending on WMI/CIM.

The installed 0.8.0 `checksum.exe` qualification used instance
`90c494c4-1690-48f2-9d9c-dd8e6240d1f9`, resolved `CHECKSUM.EXE+0xa78a0` to
`0x4478a0` from relocated base `0x3a0000`, and retained generation 26 across its
paused register, memory, and disassembly snapshots. Register write/restore,
verified patch/restore, hardware and memory breakpoints, analysis, resume, and
stop all used the same instance precondition while same-operation replay remained
byte-identical. The debuggee stopped, the debugger and sidecar exited, and port
43164 closed.

The backend still publishes 37 tools; this safety stage changes mutation inputs
rather than adding tools. The backend and managed skill advance to 0.8.0. The
offline-verified package SHA-256 is
`fd8f1c8da3c916a55d6c0ebdbb9d5f4f2df7ec4cda7e23e8097be3c5c5b886f1`.

## 2026-08-30 bounded read-only analysis ergonomics follow-up

ADRs 0024-0027 admit four atomic paused-state reads. `callstack.read` selects
the current or one exact thread handle and uses x64dbg's native unwind with a
50-frame ceiling. `patches.list` interprets the native byte-size probe on the
same serialized executor thread as enumeration, re-probes for churn, validates
at most 65,536 zero-initialized records, merges adjacent bytes, reads current
memory, and binds pagination to the complete patch snapshot fingerprint.
`symbols.resolve` performs exact module/name or address matching with explicit
found, missing, and ambiguous results. `functions.at` reports only an existing
containing function and never queues analysis.

The Rust sidecar passes 52 unit/contract tests and seven supervised-shutdown
tests. Both native architectures pass all 11 lifecycle/policy tests. This stage
also found that CMake's Release configuration defined `NDEBUG` for compact
assert-based native policy tests; the test targets now explicitly keep those
assertions active. Fresh isolated x64 and x32 workflows returned respectively
five and four native frames, selected the same thread explicitly with a
one-frame output bound, resolved the fixture symbol by exact name and address,
reported an explicit missing symbol, and returned the function produced by the
separate analysis mutation. Each workflow created two disjoint reversible patch
ranges, followed a `v3` one-item cursor, restored one range without changing the
debugger generation, and received `STALE_CURSOR` when reusing the old
content-bound cursor. Both then restored all bytes, stopped, and left no owned
debugger or sidecar process.

The installed 0.9.0 `checksum.exe` qualification used instance
`e63105a5-ac9c-428b-97f9-a2ed8568cb45`, resolved
`CHECKSUM.EXE+0xa78a0` to `0x4478a0` from relocated base `0x3a0000`, and
retained generation 27. Native unwind returned three frames for thread
`0x1a84`. Exact `main.main` resolution returned the successful known-only
`missing` state because this debug session retained no matching symbol; after
the explicit analysis mutation, `functions.at` returned the known range
`0x4478a0` through `0x44806b`. The installed patch list verified the reversible
four-byte patch at `0x4478a8` before exact restore. Existing register,
hardware/memory breakpoint, discovery, stop, and no-blind-retry qualifications
also passed, and the debugger-owned sidecar exited.

The backend now publishes 41 tools and the backend/managed skill advance to
0.9.0. Installation preserved both bearer-token config files, installed package
binaries match their source hashes, and Codex registration was refreshed with
static Authorization headers. The offline-verified 49-file package SHA-256 is
`418a53bf79039ad11dd04cef9a9a981f9f32dbe2ce3635c4889377a393fca218`.

## 2026-08-30 structured launch-argument qualification

ADR 0028 admits a bounded `arguments` array on `debuggee.launch`: at most 32
strings, 256 UTF-8 bytes each, and 512 input bytes in aggregate. A pure native
policy suite covers Windows quoting and command bounds. During real x64
qualification, nesting the quoted Windows command line inside x64dbg's `init`
command reproduced x64dbg's own embedded-quote collapse. The final design
therefore sends a path-only fixed `scriptcmd init`, waits for the actionable
initial pause, and uses `DBGFUNCTIONS::SetCmdline` to commit the complete quoted
command line before any backend-issued resume. A post-launch commit failure is
outcome-unknown and cannot be blindly resubmitted.

Fresh isolated x64 instance `2c4d45d1-895e-4fa3-bc89-49450c272ac1` and x32
instance `91165b48-dd99-4509-9777-405e4e9d88d7` both observed the exact seven
requested values: empty, plain, space-containing, embedded-quote,
trailing-backslash, comma, and non-ASCII arguments. Both replayed the original
launch result without a second process, rejected a changed array under the same
operation ID with `OPERATION_ID_CONFLICT`, completed the existing analysis and
mutation suite, stopped the fixture, and closed the debugger-owned sidecar.

This stage also corrected `scripts/build-plugin.cmd`: the parenthesized batch
block had expanded `%errorlevel%` before CTest ran, so a failing native test
could return exit code zero. It now tests CTest's exit status after execution.

The packaged and installed 0.10.0 Flare-On qualification used instance
`aec9bf00-8cd8-4943-bfad-a8c69c6bfebd`. It again resolved
`CHECKSUM.EXE+0xa78a0` to `0x4478a0` from relocated base `0x3a0000`, retained
generation 27 across state reads, returned three native stack frames, found the
known function through `0x44806b`, verified the reversible four-byte patch, and
completed register, hardware/memory breakpoint, discovery, stop, and clean
sidecar-shutdown checks.

The offline verifier accepted 50 packaged files. Installed dp32, dp64, and
sidecar hashes exactly match the package. The archive SHA-256 is
`6c87bc16e352908a3d74d80fb9864cc5f8ab3963fdb024092d5003d4bc9b8d6a`.
Codex MCP registration retains static Authorization headers and the managed
skill now requires backend 0.10.0.

## 2026-08-30 bounded import/export qualification

ADR 0029 admits module-scoped `imports.list` and `exports.list` because the
pinned SDK records add IAT locations, import ordinals, export ordinals, and
forwarders that generic symbol search cannot provide. The tools cap native
lists at 65,536 records, page at 256 items, bind literal filters and debugger
generation into opaque cursors, validate fixed UTF-8 fields and VA/RVA pairs,
and release every Bridge allocation on the serialized executor. Import provider
DLLs are reported only from current readable IAT targets; the SDK does not expose
the original descriptor library, so the backend does not invent it.

Isolated x64 instance `e4ddbf7d-4c6e-46ec-95c7-e6552d767c49` returned 72
fixture imports; isolated x32 instance `81a98d2e-b8e6-4f50-8214-79b944762c46`
returned 69. Both followed a one-item filter-bound cursor, resolved the `Sleep`
IAT record, returned four `mcp_fixture` exports, and preserved
`AcquireSRWLockExclusive` as forwarder `NTDLL.RtlAcquireSRWLockExclusive`.
Both completed all pre-existing lifecycle/mutation checks and clean shutdown.

## 2026-08-30 bounded debugger-event history qualification

ADR 0030 admits `events.list` in every debugger state. The native plugin copies
only bounded scalar metadata from a closed set of specific and generic debugger
callbacks into a 256-record ring protected by the existing state mutex. It never
retains callback pointers, debug strings, OS handles, or an event-serving thread.
Responses copy at most 256 matching records before JSON rendering and expose the
oldest/latest sequence, continuation sequence, `has_more`, and an explicit
`overflowed` signal when a caller has fallen behind the retained range.

Rust passes 52 unit/contract tests and seven supervised-shutdown tests. Both
native architectures pass all 12 tests; the lifecycle harness injects exactly
300 resume callbacks and verifies that the retained 256 records are the newest
strictly ordered sequence range, while the public response reports overflow and
filter continuation. Fresh isolated x64 instance
`c3ad8716-9c02-4abf-9a69-e76d582a6852` and x32 instance
`8b971a75-a3c6-4b47-8ef2-47a9c543403c` each began with an empty history, returned
`process_created` as a one-item filtered first page, continued through 12 later
startup matches, verified structured breakpoint plus pause and step events,
completed the existing analysis/mutation workflow, and exposed callback-confirmed
`debug_stopped` at sequence 46 after debuggee teardown. Both debugger-owned
sidecars then exited cleanly.

## 2026-08-30 bounded loaded-section qualification

ADR 0031 admits `sections.list` because loaded PE section names and spans are not
equivalent to module image bounds or virtual-memory regions. The tool resolves
one exact loaded module, revalidates its base/size/count, owns and releases the
SDK section list on the serialized executor, rejects more than 4,096 records,
validates every fixed UTF-8 name and in-module span, pages at 256, and binds the
module, literal name filter, and debugger generation into its cursor. It reports
only native index, nullable name, structured start, size, and exclusive end; the
SDK supplies no characteristics or raw-file fields, so none are inferred.

Rust passes 52 unit/contract tests and seven supervised-shutdown tests; both
native architectures pass all 12 tests. Fresh isolated x64 instance
`dcd0918b-c707-494f-98c2-dedd1c3ed270` returned 7 fixture sections, while x32
instance `e411c07b-7a74-4f4b-95ae-c669adbca9d1` returned 6. Both followed a
one-item cursor, rejected reuse with a changed `.text` filter, preserved the
paused generation, and proved that the relocated fixture entry and exported
analysis target were inside the SDK-reported `.text` span. Both then completed
the complete existing event/analysis/mutation workflow and clean shutdown.

The 0.11.0 package gate then passed installer, managed-skill, static-header Codex
registration, Rust, Clippy, seven supervised-shutdown, and both 12-test native
matrices. The offline verifier accepted 53 manifest files. Installed dp32, dp64,
and sidecar hashes exactly match the package, and both Codex entries retain their
config-file token as a static Authorization header. Installed Flare-On instance
`f141eb23-7ea1-4300-8870-461c1d4542ba` resolved
`CHECKSUM.EXE+0xa78a0` to `0x9b78a0` from relocated base `0x910000`, retained
generation 27, returned three native frames, verified the known function through
`0x9b806b`, restored its four-byte patch and register, exercised typed hardware
and memory breakpoints, stopped the sample, and closed the debugger-owned
sidecar. The backend now publishes 45 tools and the managed skill requires
0.11.0. The archive SHA-256 is
`0f27c54fe50e6a994040745d83dad367139be5ce3b46e8f2151c7724b7d82fb0`.

## 2026-08-30 owned bounded run-to qualification

ADR 0032 admits `debugger.run_to_address` as the only Stage 5 controlled
mutation. It resolves a structured address in the paused generation, installs a
uniquely named single-shot software breakpoint derived from the operation UUID,
requires exact typed read-back behind a command-queue fence, and then waits on
callbacks. Intervening pauses and bounded timeout are explicit incomplete
results. Cleanup removes only the exact owned record; ambiguous cleanup is an
unknown outcome and is never retried.

The first real integration attempt revealed a test-fixture defect rather than a
backend defect: release-link identical-code folding assigned the two identical
exported interrupter/target functions the same address. The fixture now emits
distinct machine code, preventing a pre-existing caller breakpoint from also
being the target. A focused native policy test separately fixes the generated
breakpoint name, command text, address, single-shot flag, and exact-name
ownership rules.

Fresh isolated x64 instance `8aaf514a-295f-40ed-a800-290bf39c0189` and x32
instance `86366882-9289-4da3-927b-8c45c0441520` both preserved an intervening
caller breakpoint while cleaning the temporary target, reached the target on a
second run, replayed the recorded result exactly, rejected changed arguments
under the same operation ID, and paused plus cleaned an unreachable target at a
250 ms timeout. Both completed the full prior tool workflow and shut down their
owned sidecars. The remaining conditional/exception, thread-control, and trace
candidates remain unadmitted for the reasons recorded in the development
roadmap.

The installed 0.12.0 qualification used instance
`ceefd6fd-8dc0-416d-8ae5-9f828113c445`. It resolved
`CHECKSUM.EXE+0xa78a0` to `0x8578a0` from relocated base `0x7b0000`, retained
generation 27 across the paused snapshot, returned three native stack frames,
verified the known function through `0x85806b`, and completed the reversible
register, patch, hardware-breakpoint, and memory-breakpoint checks. From the
memory-breakpoint pause it then ran to the next decoded instruction at
`0x8578b2`, replayed the recorded result exactly, and confirmed its temporary
software breakpoint was cleaned. The debuggee stopped and the debugger-owned
sidecar exited.

The definitive 0.12.0 release gate repeated the complete packaged x32/x64
workflows, confirmed all owned sidecars exited and both loopback ports closed,
then repeated the installed checksum workflow as instance
`67460aff-e14f-4369-be87-9dee119208f0`. Run-to again completed at `0x8578b2`
with exact replay and confirmed cleanup. The offline-verified archive SHA-256 is
`142131cc4bee339c5f660cbce5d3582e4071b6b06383c67ee836afb4cb185935`.
Publisher signing and pristine-VM qualification remain intentionally not run.

## 0.14.0 typed breakpoint qualification

ADRs 0034 and 0035 added four backend-owned mutations without exposing x64dbg
commands or expressions. Conditional software breakpoints compile one to four
closed register, thread-ID, or hit-count predicates, enable fast resume, and
return an operation-derived `managed_id`. Exception breakpoints accept one exact
32-bit code plus `first`, `second`, or `both` chance policy and use the same
recoverable ownership model. Both removals fail closed on a foreign identity.

The first x64 live run exposed a callback-shape issue: x64dbg reports an
exception-breakpoint hit through `CB_BREAKPOINT`, with the exception code in the
breakpoint address field. It does not provide the actual first-chance flag there.
The runtime now retains only the preceding `EXCEPTION_DEBUG_EVENT`, correlates
code/process/thread to the breakpoint callback, emits the real exception address
and chance, and immediately consumes the pending record. A lifecycle regression
test fixes that behavior rather than inferring chance from configuration.

Fresh isolated x64 instance `f8edad8c-0cae-4c3b-a24e-42c8e4160a87` and x32
instance `96baf49c-d4ea-4f1a-8e23-00476f796968` both skipped the first fixture
function hit and paused on hit count two. Both then raised private code
`0xe0424242`, returned `first_chance: true`, recovered managed identities through
`breakpoints.list`, refused foreign removal, replayed exact mutations, removed
owned records, completed the full previous workflow, stopped the debuggee, and
closed the debugger-owned sidecar.

The 0.14.0 package gate passed 52 Rust unit/contract tests, seven supervised
shutdown tests, 13 native x32 tests, 13 native x64 tests, installer, Codex
registration, skill, and offline package-verifier contracts. The installed
checksum.exe smoke used instance `dfcf5d4b-8286-4dfc-951e-16e6f38ace8f`, resolved
`CHECKSUM.EXE+0xa78a0` to `0x6678a0` from ASLR base `0x5c0000`, and completed
conditional and exception set/list/replay/remove without executing either new
breakpoint. Existing reversible patch, hardware/memory breakpoint, run-to, and
shutdown checks also passed. The offline-verified archive SHA-256 is
`de7e8aed6be7839391d1d5f28c51d4094611cbf01c020a0248e76ce2b9596eb8`.
Both global Codex endpoints remain enabled with static Authorization headers,
and the managed workflow skill is version 0.14.0.

## 0.15.0 thread-scoped context qualification

ADR 0036 extends `registers.read` and `debugger.snapshot` with an optional exact
TID while preserving selected-thread defaults. A deterministic fixture worker
made the non-current path repeatable. Fresh isolated x32dbg and x64dbg runs
matched that worker's register CIP and compact-snapshot IP to `threads.list`,
kept the selected TID unchanged, returned `INVALID_ARGUMENT` for an absent TID,
completed every prior workflow, and closed both owned listeners.

The 0.15.0 package gate passed 52 Rust unit/contract tests, seven supervised
shutdown tests, 13 native x32 tests, 13 native x64 tests, installer, Codex
registration, skill, and offline-verifier contracts. Installed checksum.exe
instance `b86c5801-d9d8-4ee1-94c8-3370accbe100` paused at
`CHECKSUM.EXE+0xa78a0` (`0x6678a0`, ASLR base `0x5c0000`) and captured the exact
active thread `0x269c` through both new inputs. The two-instruction explicit
snapshot used the same generation and IP; the complete prior reversible
mutation and shutdown workflow also passed. The offline-verified archive
SHA-256 is
`9c59a9d539209f2290b1fcde8f575b56d8fc93b037946c8059c7b07f7dfabfed`.
Both Codex endpoints and the managed skill were then updated to 0.15.0.

## 0.16.0 typed DLL launch qualification

ADR 0037 added `debuggee.launch_dll` as a separate no-argv mutation rather than
overloading executable launch. Bounded native PE parsing rejects DLL/EXE kind
or backend-machine mismatches before debugger mutation and enforces x64dbg's
fixed loader-path mapping bound. The initial result reports the generated
loader and explicitly states that the target DLL is not loaded.

Fresh isolated x32dbg and x64dbg workflows used architecture-matched DLL
fixtures. Each verified exact operation replay, changed-argument conflict,
initial loader/target separation, one explicitly authorized resume, the loaded
fixture module, and a breakpoint pause exactly at its entry. Debugger stop
removed the generated `DLLLoader*` helper. Both owned sidecars exited and both
loopback listeners closed after their debugger hosts ended.

The complete 0.16.0 package gate then passed 52 Rust unit/contract tests, seven
supervised shutdown tests, Clippy with warnings denied, 14 native tests per
architecture, installer/Codex/skill contracts, offline package verification,
SBOM generation, and checksums. The archive SHA-256 is
`d50994d1a18202f555bc77559092a5b5e76a2dbbce1d6409e5e51aa73fb9b3e8`.

The verified package was installed into `C:\tools\x64dbg`; installed x32/x64
plugins and the sidecar matched their packaged hashes, both Codex endpoints
retained static Authorization headers, and the managed skill reported 0.16.0.
Installed instance `aa53ed03-1973-416e-acf7-58aaa437f1d2` then qualified the
Flare-On `checksum.exe` workflow at ASLR-resolved `CHECKSUM.EXE+0xa78a0`
(`0x6678a0`): exact-thread context, function analysis, reversible patching,
typed breakpoints, and owned run-to-address all passed before clean stop.

## 0.17.0 bounded trace-session qualification

ADR 0038 added `trace.start`, `trace.status`, `trace.cancel`, and
`trace.results` as one owned address-path facility rather than an executor-held
step loop or x64dbg file trace. The public contract accepts only into/over mode,
1-4,096 steps, and a 100-30,000 ms deadline. One joinable supervisor owns the
deadline, the callback writes only to a preallocated 4,097-point buffer, and
plugin stop converts an active trace to `backend_shutdown` before joining it.

Fresh isolated x32dbg instance `6782380c-30f7-44aa-a01d-0241d300330f` and x64dbg
instance `767a74c7-3aaa-47d1-a653-f66da638c6b4` completed the entire prior
workflow plus exact eight-step completion with nine ordered points, immutable
three-item pagination, replay/conflict behavior, one-active rejection,
caller cancellation, 100 ms timeout, and interruption by an existing software
breakpoint. Both preserved selected-thread identity and closed their owned
sidecars. Separate native lifecycle cases started a 30-second active trace and
stopped in under three seconds with the retained `backend_shutdown` reason.

The 0.17.0 package gate passed 52 Rust unit/contract tests, seven supervised
sidecar shutdown tests, Clippy with warnings denied, 16 native tests per
architecture, installer/Codex/skill contracts, the offline verifier, SBOM, and
checksums. The 60-file verified archive SHA-256 is
`721e760c8f0d99139be8c2007049ceb2a5743648fc2283e43204d25ee51f44c5`.

The verified x32 plugin, x64 plugin, and sidecar were installed into
`C:\tools\x64dbg` and matched their packaged hashes; Codex retained both static
Authorization-header endpoints and installed skill 0.17.0. Installed Flare-On
`checksum.exe` instance `1d5d551b-c7c5-44e3-9d56-f6dff191a910` again resolved
`CHECKSUM.EXE+0xa78a0` to `0x6678a0` from base `0x5c0000`, completed the prior
reversible workflow, then recorded trace `5eedb021-9de2-4127-bc7a-5cb33e823404`
at exactly eight steps and nine points with exact start replay. Debugger stop,
host exit, and both backend listener checks were clean.

## 0.18.0 exact typed breakpoint transition qualification

ADR 0039 added only `breakpoints.enable` and `breakpoints.disable`. Their closed
selector covers plain software, hardware, memory, managed conditional, and
managed exception breakpoints. Every mutation reads one exact native record,
uses one fixed explicit-identity command and private queue fence when a state
change is necessary, then proves the requested enabled state without changing
configuration. Already-requested state is a verified `changed: false` result.
Hardware identity is address/access/size; a disabled record reports `slot: null`
and may acquire another slot when enabled.

The 0.18.0 gate passed 52 Rust unit/contract tests, seven supervised sidecar
shutdown tests, Clippy with warnings denied, and 16 native tests on each
architecture. Fresh isolated x64dbg instance
`f48e77e1-beba-43eb-9cd7-94d01bf3dfde` and x32dbg instance
`6f0e1acc-7525-413f-96ec-6ac4228dc0ce` completed five-kind disable/enable
cycles, hardware slot release/reacquisition, exact replay, changed-selector
operation conflict, managed policy preservation, live breakpoint hits, and
clean debugger-owned sidecar shutdown. One earlier x32 run completed all new
breakpoint checks but encountered a retryable `BUSY` in the pre-existing late
pause loop; a fresh complete rerun passed.

The final release sidecar was then rerun through the updated workflow as x64
instance `89e16145-68dc-4275-a209-1469573301c7` and x32 instance
`c071577b-61ab-4c3f-9783-e0f7592a6e99`. Both explicitly proved the new
already-enabled hardware path returns `changed: false`, all five transition
kinds remain true, the changed-selector conflict remains rejected, and final
debugger state is absent.

The 61-file package passed installer, Codex registration, managed-skill,
manifest, SBOM, checksum, and offline-verifier gates. Archive SHA-256 is
`8c133215c69e23aa01a189e3df0b4ff5ec1e40b9cd9d10d5623d4b8c50ea6665`.
Installed x32 plugin, x64 plugin, and sidecar hashes are respectively
`cf04156fd472459bcafb549dfb170c5bfd67bdfda874645bc75a711050785b75`,
`fe28140ad5b5d07c063ca294a162e4f494a4f6755ae79db58ea738ef1d8ed49e`,
and `55bb9e54ee222130357a75205cdec3b1701af5d29b2f4e4600192a71a90c2a49`.

Installed Flare-On `checksum.exe` instance
`f888807e-a9c4-4119-97ce-ca5de361c3cc` resolved
`CHECKSUM.EXE+0xa78a0` to `0x9b78a0` from ASLR base `0x910000`. Without leaving
temporary state, it toggled all five breakpoint kinds, preserved conditional
and exception managed identities, released/reacquired a hardware slot, hit the
hardware and memory breakpoints, restored the tracked patch and register, ran
the bounded trace, and stopped. The debugger, sidecar, ports 43132/43164, and
temporary managed breakpoint state were all absent afterward. Both Codex
endpoints retain static Authorization headers and the managed skill is 0.18.0.

## 0.18.1 manual Codex setup qualification

ADR 0040 removed the stateful `register-codex.ps1` helper. The debugger
installer remains responsible only for the x32/x64 plugins, shared sidecar, and
server configuration. After a successful write it now prints exact
`mcp_servers.x64dbg` and `mcp_servers.x32dbg` TOML using the effective ports and
shared static Authorization value, plus offline commands that copy the complete
version-matched skill from the verified package. The output explicitly treats
the displayed token as secret. It never modifies Codex configuration, skills,
or environment variables.

The installer contract passed first install, idempotent reinstall, custom ports,
partial repair, explicit rotation, token mismatch fail-closed behavior, and
`-WhatIf`. It additionally proved both ready-to-paste tables, the token appearing
in exactly two Authorization headers, the correct `config.toml` path, the full
skill copy instruction, and the restart warning. Skill validation, 52 Rust
unit/contract tests, seven supervised shutdown tests, Clippy with warnings
denied, and all 16 native tests on each architecture passed.

The offline verifier accepted the 0.18.1 package (61 manifest entries plus the
manifest) and proved the removed helper is absent while all four required skill
files are checksummed. Archive SHA-256 is
`ea7c8ba1512128346192b6b3b718a23bbb3508555dd2a8348afa03b88c228fb5`.
No debugger field rerun was required because the backend tool, IPC, threading,
and lifecycle implementations did not change in this patch release.
