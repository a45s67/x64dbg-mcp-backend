# ADR 0016: Explicit function analysis with command-queue confirmation

Status: Accepted before implementation on 2026-08-29.

## Context

The discovery tools intentionally report `completeness: "known_only"`. Empty
`functions.list` or `references.to` results are therefore common until the user
explicitly asks x64dbg to analyze code. Hiding analysis inside those reads would
violate their contract and make an apparently retryable request mutate the
debugger database.

x64dbg's module-wide `anal`, `cfanal`, `analx`, and `analadv` commands take no
module argument. Their implementation selects the module from the mutable GUI
disassembly selection. Using them remotely would therefore race with the user,
an unrelated plugin, and other GUI navigation. The address-taking `analr`
command instead performs recursive analysis for one function and installs its
function markers.

`DbgCmdExec` only confirms admission to x64dbg's asynchronous command queue. It
does not prove that the analysis finished. Merely polling for a function marker
is also insufficient when the target was already known: the request could be
reported complete before its newly queued command ran.

## Decision

Add one backend-local mutation:

```text
analysis.function(address, operation_id)
```

This wire-contract addition advances the backend package and managed workflow
skill to 0.3.0; the skill declares backend 0.3.0 as its minimum.

- `address` uses the existing structured `AddressRef` schema and must resolve
  uniquely into a loaded module while the debuggee is paused.
- The plugin renders only the resolved pointer-width-checked address into the
  fixed command `analr <hex-address>`. No debugger command or expression text is
  accepted from the MCP caller.
- The operation analyzes at most one recursively discovered function. Whole
  module and advanced analysis remain deferred because the available commands
  depend on GUI selection and do not provide a stable module parameter.
- The module image is limited to 128 MiB. This bounds the address space the
  native recursive analyzer can traverse, in addition to the normal request,
  concurrency, and mutation deadlines.

The plugin registers a private, debug-only command fence. After x64dbg accepts
the analysis command, the plugin queues a fence containing an internally minted
64-bit correlation value. The fence callback accepts only that value and wakes
the waiting runtime operation. A response is successful only after:

1. the matching fence ran after the analysis command in x64dbg's command queue;
2. the debuggee is still paused at the original state generation; and
3. `Script::Function::GetInfo` reports a function covering the requested
   address in the same loaded module.

The result returns the requested structured location, the resulting function's
structured inclusive start/end locations, instruction count, manual status,
`already_known`, and the unchanged `state_generation`. Analysis changes the
analysis database, not execution state, so it does not increment the debugger
event generation.

## Errors and lifecycle

- Invalid or ambiguous module/RVA resolution, an address outside a module, an
  over-128-MiB module, or a non-function result is a structured error.
- A queue rejection before the analysis command is accepted is retryable
  `BUSY` and has no mutation effect.
- Rejection of the fence after analysis admission, timeout, disconnect, unload,
  or debugger-generation change makes the outcome ambiguous. It is recorded
  under the original `operation_id` and is never blindly retried.
- Fence state is bounded to the single serialized native work item. Plugin stop
  wakes the waiter, unregisters the private command, drains the executor, and
  leaves no detached thread.
- Replaying the same completed `operation_id` returns the ledger result without
  re-running analysis. Reusing it with different arguments remains a conflict.

## Rejected alternatives

- **Run `analadv` after navigating the GUI to a module.** Selection is global
  mutable state and can race; it also surprises the local debugger user.
- **Expose an arbitrary command tool.** This defeats input validation,
  mutation classification, bounds, and Gateway policy.
- **Treat `DbgCmdExec` success as completion.** It means queued, not finished.
- **Poll only for a marker.** An already-known function produces a false early
  confirmation.
- **Use `DbgAnalyzeFunction` alone.** The exported API returns a graph but the
  upstream implementation does not install the function markers consumed by
  `functions.list`.

## Verification

- Rust schema and generated argument-corpus tests cover strict fields,
  `AddressRef`, canonical operation IDs, and mutation classification.
- Native tests cover fence correlation, early queue rejection, already-known
  functions, missing markers, deadline expiry, generation change, and stop while
  waiting.
- Isolated x32dbg/x64dbg integration analyzes a previously unknown fixture
  function, observes it through `functions.list`, verifies operation replay does
  not execute twice, and proves clean sidecar/port shutdown.
- An installed Flare-On sample confirms a selected function by module/RVA and
  compares bounded discovery before and after the explicit mutation.
