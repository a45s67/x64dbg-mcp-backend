# Development principles and roadmap

Status: Active project guideline as of 2026-08-29.

This document governs post-0.7 development. It is intentionally about this
backend's design and delivery discipline, not about matching another project's
tool count. Feature-specific decisions still require an ADR before
implementation when they change the public contract, native trust boundary, or
mutation behavior.

## Product direction

The backend should make remote debugging predictable enough for an agent while
remaining understandable to the local debugger user. It must stay:

- independently usable as a loopback Streamable HTTP MCP server;
- composable behind the Dynamic Analysis Gateway without knowing the Gateway's
  namespace;
- behaviorally equivalent in x32dbg and x64dbg except where architecture rules
  genuinely differ;
- conservative about mutations, debugger commands, and process ownership; and
- easy to install without placing development runtimes on the target machine.

The catalog is curated. A smaller set of precise, bounded tools is preferable to
a broad set whose state, completion, or side effects are ambiguous.

## Core engineering rules

### Keep tools atomic and policy-visible

- Tool names remain backend-local, dotted, and verb-specific.
- Read, mutation, and destructive behavior must not share one action-union tool.
- MCP annotations must describe every path through the tool accurately.
- One mutation request performs one logical mutation. Avoid batches with partial
  success or implicit cleanup mutations.
- Do not expose arbitrary debugger commands, shell execution, or general
  scripting as a shortcut around tool design.

### Make debugger state explicit

- Every state-sensitive tool declares its valid plugin/debuggee states.
- Paused reads return the debugger generation they observed.
- A native read that spans possible debugger churn captures the generation,
  copies its data, and rechecks before returning.
- Module-relative input is resolved in the same serialized native work item as
  the operation that consumes it.
- Results must not combine registers, memory, symbols, or pause metadata from
  different generations without reporting a structured `BUSY` or stale-state
  error.

### Prove completion instead of guessing

- `DbgCmdExec` admission is not completion.
- Fixed sleeps and state polling alone are not accepted completion evidence.
- Execution mutations require a correlated callback and generation transition.
- Database mutations require a command-queue fence plus an observable native
  postcondition.
- Memory/register/breakpoint/patch mutations require exact read-back or another
  equally strong postcondition.
- An interruption by a breakpoint, exception, user pause, disconnect, or unload
  must remain distinguishable from successful completion.

### Treat mutation retries as a protocol problem

- Every mutation requires the current canonical lowercase UUID `instance_id`
  and a fresh canonical lowercase UUID `operation_id`.
- Completed calls replay the recorded result without re-execution.
- Reusing an ID with different arguments is a conflict.
- Timeout or disconnect after admission produces an explicit unknown outcome.
- Neither the backend, Gateway, installer, workflow skill, nor tests may blindly
  retry an unknown mutation.
- Backend instance identity must make restart boundaries visible because an
  in-memory operation ledger cannot prove outcomes from a previous process.

### Bound every dimension

Each tool defines finite limits for all applicable dimensions:

- request fields, strings, arrays, byte ranges, native record counts, and
  expression length;
- output items, encoded bytes, disassembly instructions, stack frames, and text
  context;
- native allocation, scan range, iteration count, queue occupancy, concurrency,
  deadline, and retained history;
- cursor length and the state/filter identity bound into a cursor; and
- shutdown/drain time.

Never allocate directly from an unchecked SDK count or caller length. Pagination
does not excuse an unbounded native enumeration performed before paging.

### Keep the native boundary narrow

- All x64dbg SDK and Bridge calls appear in `docs/native-api-audit.md` before a
  tool is enabled.
- Calls run through the single serialized debugger executor unless an API is
  independently documented and audited as safe elsewhere.
- Bridge-owned allocations are copied and released in the same work item on
  every success and error path.
- Callback data is copied synchronously; callback pointers are never retained.
- Caller-controlled strings are not interpolated into debugger commands when a
  typed SDK call or closed enum can express the operation.
- GUI selection is not an addressing or completion mechanism.

### Return machine-usable contracts

- Success returns bounded structured content, not only prose.
- Addresses return canonical absolute values and module/RVA metadata when known.
- Collections report completeness, truncation, and a filter-bound cursor when
  applicable.
- Errors use stable codes, a concise message, retryability, debugger state, and
  an actionable diagnostic code where useful.
- OS error strings, stack traces, secrets, and unbounded debugger text never
  cross the public boundary.
- Compact defaults should answer the common workflow without injecting repeated
  large snapshots into every response.

### Own security and lifecycle

- The listener remains loopback-only and bearer authentication remains
  mandatory.
- Tokens never appear in process arguments, logs, health responses, skills, or
  generated examples.
- Every thread, process, socket, pipe, wait, and request is owned and has a
  bounded shutdown path. No detached connection workers are permitted.
- Plugin unload enters draining state, rejects new work, wakes waits, closes the
  ownership channel, joins workers, and only then unregisters callbacks.
- A debugger crash must not leave an orphaned sidecar.
- Closing an attached session must not terminate a process the backend does not
  own.

### Keep compatibility deliberate

- The sidecar owns MCP/HTTP validation; the plugin owns debugger semantics.
- IPC changes are versioned and fail closed on mismatch.
- Additive optional result fields may remain compatible; new tools or input
  behavior require contract tests and an intentional package/skill version
  decision.
- The Gateway may prefix names but must not be required to repair backend-local
  schemas, retries, state, or authentication.

## New-tool admission checklist

A proposed tool is not ready for implementation until its ADR or design note
answers all of the following.

### Contract

- What user problem requires a new tool instead of composing existing tools?
- Is it read-only, mutating, or destructive, and do its annotations agree?
- What exact input schema, address form, state precondition, output schema, and
  error codes are exposed?
- What are every input, output, native-count, time, and concurrency bound?
- Is an empty result complete, known-only, filtered, or inconclusive?

### Native execution

- Which SDK/Bridge calls are used and who owns their returned memory?
- Which executor/thread may call them?
- How are architecture width, address overflow, state generation, and unload
  handled?
- Does the implementation depend on GUI selection, arbitrary expressions, or
  caller command text? If so, redesign it.

### Mutation semantics

- What is the exact single side effect?
- What proves the side effect completed?
- What state is captured before admission and verified afterward?
- What result is stored in the operation ledger?
- What happens if the response, debugger, sidecar, or client disappears at each
  admission stage?

### Verification

- Pure validation/policy unit tests.
- Rust MCP schema, argument, error, and response-bound contract tests.
- Native executor, allocation, generation-churn, timeout, and unload tests.
- Isolated real x32dbg and x64dbg integration tests.
- Shutdown with idle, queued, active, and disconnected requests as applicable.
- A real authorized sample qualification when the feature changes debugger
  behavior; prefer a suitable sample under `Flare-On11_Challenges`.
- Package, installer, architecture, checksum, and offline verification when a
  versioned artifact changes.

## Implementation workflow

Each feature stage follows this order:

1. Record the durable decision and threat boundary.
2. Freeze MCP schema, structured errors, IPC shape, bounds, and examples.
3. Add fake-adapter contract tests and pure native policy tests.
4. Update the native API/threading audit.
5. Implement the smallest vertical slice through sidecar, IPC, and plugin.
6. Add failure, ambiguity, generation-churn, and shutdown coverage.
7. Run both native architectures plus Rust tests and Clippy.
8. Run isolated x32dbg/x64dbg integration and an appropriate real sample.
9. Package, offline-verify, install, and refresh client registration only when
   the shipped artifact or public contract changed.
10. Record evidence, limitations, version, and checksum before committing the
    completed stage.

Do not combine unrelated mutations or several new native API families in one
stage. Read-only tools that share one audited native snapshot may be grouped when
their failure and ownership models are genuinely the same.

## Active roadmap

### Stage 1: backend instance identity and restart safety (completed in 0.8.0)

Goal: make debugger/sidecar restart boundaries observable so clients never
mistake a new backend for the process that admitted an earlier mutation.

Deliverables:

- one unpredictable `instance_id` per sidecar/plugin association;
- consistent identity in authenticated readiness, `debugger.state`, and relevant
  MCP metadata;
- documented relationship between `instance_id`, debugger generation, backend
  type, and operation ledger lifetime;
- structured stale/restarted diagnostics without automatic mutation replay; and
- restart, reconnect, active-request, unload, x32, x64, and Gateway contract
  tests.

Exit: a client can distinguish unavailable, unauthorized, no-debuggee, and
restarted-backend states and can safely stop rather than replay an uncertain
mutation across an instance boundary.

Completed on 2026-08-29 under ADR 0023. The authenticated handshake,
readiness, MCP metadata, and native state share a sidecar-generated UUID v4;
all mutation schemas bind to it. Unit/contract tests prove mismatch rejection
before adapter dispatch, supervised restart proves the replacement pipe receives
no stale request, x32/x64 lifecycle and isolated integration pass, and the
installed `checksum.exe` qualification preserves identity through all mutation
families and clean shutdown.

### Stage 2: bounded read-only analysis ergonomics (completed in 0.9.0)

Add these tools, each behind its own completed admission checklist:

- `callstack.read`: current or explicit thread, bounded depth, native stack API,
  structured frames, generation consistency, and explicit completeness;
- `patches.list`: bounded/paginated tracked patch ranges with original/current
  bytes and module/RVA metadata;
- `symbols.resolve`: exact module-scoped name or address resolution with explicit
  missing/ambiguous results; and
- `functions.at`: return the known analyzed function containing one structured
  address without silently triggering analysis.

For call stacks, a frame-pointer-only fallback must be labeled incomplete and
must never be presented as equivalent to the debugger's native unwind result.
For patch enumeration, validate the SDK byte/count result before allocation and
merge adjacent byte records into bounded ranges.

Exit: all four tools pass contract, native ownership, generation-churn, isolated
x32/x64, shutdown, and real-sample tests without adding a mutation surface.

Completed on 2026-08-30 under ADRs 0024-0027. The catalog now contains 41
atomic tools. Native x32/x64 tests keep assertions enabled in Release builds;
isolated integration covers current and explicit-thread unwind, empty and
bounded patch ranges, disjoint range pagination, snapshot churn without a
debugger generation change, exact symbol name/address agreement, explicit
missing symbols, and known function containment. All four operations execute
on the existing serialized debugger executor and add no connection thread or
mutation path.

### Stage 3: structured debuggee launch arguments (completed in 0.10.0)

Extend `debuggee.launch` with a bounded `arguments` array rather than an opaque
command-line string.

Deliverables:

- per-argument and total command-line limits;
- rejection of NUL and invalid Unicode;
- one reviewed Windows argv quoting algorithm with edge-case fixtures for empty
  values, whitespace, quotes, and trailing backslashes;
- no `cmd.exe`, PowerShell, shell expansion, or caller debugger command;
- callback-confirmed launch with full argument-array operation replay identity;
  and
- an independently evaluated, closed-enum entry-break policy only if x32/x64
  callback semantics can prove it.

Exit: fixture debuggees observe the exact intended `argv` on both architectures,
and a lost response never causes a second process launch.

Completed on 2026-08-30 under ADR 0028. The backend accepts only a bounded
string array, performs the Windows quoting itself, launches to the initial
actionable pause, and commits the complete command line through the typed SDK
`SetCmdline` function before any resume. Isolated x64 and x32 fixtures observed
empty, space-containing, quoted, trailing-backslash, comma, and Unicode values
exactly. Replay returned the original result and a changed array under the same
operation ID was rejected before native dispatch. Entry-break selection remains
unadmitted because the current callbacks do not prove a portable closed enum.

### Stage 4: additional read-only candidates

Evaluate, in order of demonstrated workflow value:

- `imports.list` and `exports.list`, module-scoped and paginated;
- bounded debugger event history with sequence numbers, type filters, overflow
  indication, and a fixed-capacity ring; and
- precise module/section metadata not already supplied by `modules.list` and
  `memory.map`.

Do not add a tool when existing bounded tools already return the same information
with comparable precision.

Progress: ADR 0029 admits `imports.list` and `exports.list`. Both are implemented
and isolated x32/x64-qualified; event history and section-metadata evaluation
remain before this stage can close or ship.

### Stage 5: controlled mutation candidates

These are proposals, not a batch commitment. Each requires a separate ADR and
must be implemented one at a time:

- `debugger.run_to_address` with temporary-breakpoint ownership, interruption
  reporting, callback confirmation, and safe cleanup;
- conditional or exception breakpoints with closed structure and no arbitrary
  breakpoint command text;
- thread switch/suspend/resume with exact thread identity, ownership, and
  postcondition checks; and
- bounded trace sessions with an explicit trace ID, step/output caps, status,
  cancellation, and unload behavior.

No proposal may use fixed sleep, unbounded synchronous tracing, delete-all
cleanup, or automatic retry to simplify its implementation.

## Parked work

The following are intentionally outside the active roadmap until explicitly
resumed:

- coverage-guided fuzzing and sanitizer toolchain selection;
- publisher signing;
- pristine-VM qualification;
- multiple debugger instances of the same backend type;
- non-loopback transport, TLS, or OAuth;
- arbitrary debugger command or scripting tools;
- file upload, unrestricted dump paths, and general shell integration; and
- outbound reference enumeration until a precise bounded native source or index
  is available.

Parked work must not silently become a release requirement or be reported as
completed by inference from adjacent tests.

## Definition of done for a stage

A stage is complete only when:

- its ADR and public contracts match the implementation;
- the native audit accounts for every new SDK call and allocation;
- all bounds and state transitions have automated negative tests;
- mutation ambiguity and no-blind-retry behavior are tested where applicable;
- Rust, x32, x64, integration, and shutdown gates pass in proportion to risk;
- real-sample evidence is recorded for debugger-visible behavior;
- install/package documentation and the workflow skill use only published tool
  names and schemas;
- no owned process, listener, thread, handle, or temporary debugger state remains
  after the test; and
- limitations are stated accurately rather than hidden behind a success result.
