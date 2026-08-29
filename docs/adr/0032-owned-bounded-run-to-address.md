# ADR 0032: Owned bounded run-to-address

Status: Accepted on 2026-08-30.

## Context

Clients can compose `breakpoints.set`, `debugger.resume`,
`debugger.wait_for_pause`, and `breakpoints.remove`, but that sequence does not
atomically own its temporary breakpoint. Interruption, timeout, client
disconnect, or concurrent requests can leave a persistent breakpoint or delete
state the client did not create. A backend tool is useful only if it improves
that ownership boundary rather than wrapping the same commands loosely.

x64dbg's documented `run address` command creates a single-shot breakpoint, but
an interruption before the target leaves cleanup identity implicit. The command
documentation also defines named single-shot software breakpoints. The backend
can therefore create a uniquely named single-shot breakpoint, confirm it through
the command queue and typed breakpoint read-back, then run and clean up only the
record it owns.

## Decision

Add one paused-state controlled mutation:

```text
debugger.run_to_address(address, timeout_ms?, operation_id, instance_id)
```

`address` uses the existing absolute/module-RVA union. `timeout_ms` defaults to
9,000 and is 100 through 20,000, leaving cleanup time inside the existing
30-second mutation deadline. The ordinary sidecar instance precondition and
operation ledger apply. Replay returns the recorded result and never runs again.

Before mutation, the plugin resolves the address in the paused generation,
requires a decodable target instruction, and rejects any existing software
breakpoint at that address. If the instruction pointer already equals the target,
the operation succeeds with `completed: true` and `resumed: false` without
creating a breakpoint.

Otherwise the plugin derives a fixed safe name from the validated operation UUID,
queues only:

```text
bp 0x<address>, "__x64dbg_mcp_run_to_<uuid>", ss
run
```

The first command is followed by the private command-queue fence. Typed
`GetBridgeBp` read-back must confirm the exact address, enabled/active software
type, single-shot flag, and exact backend-owned name before `run` is submitted.
No caller command, condition, expression, or label text is interpolated.

The executor waits on callback-maintained state, never a fixed sleep. A newer
pause at the target with a software-breakpoint reason completes the operation.
Another breakpoint, exception, step, or user pause returns
`completed: false` with its structured pause reason. Process exit returns a
known incomplete result. When the caller's timeout expires while still running,
the backend queues one `pause`, requires a confirmed newer paused callback, and
reports a known timeout interruption.

On every confirmed pause, the plugin inspects the target breakpoint. If the
single-shot record was removed by a target hit, cleanup is already complete. If
the exact owned name and shape remain, the plugin queues an address-only delete
and confirms absence before returning. A different record at that address is
never deleted. Cleanup rejection, ambiguous pause admission, unload, or missing
confirmation returns a structured outcome-unknown error under the original
operation ID; the backend never resubmits `run`, `pause`, or deletion blindly.

Successful results include `completed`, `resumed`, target location, final
debuggee state/generation, applicable pause reason and instruction pointer,
interruption (`null`, `breakpoint`, `exception`, `step`, `user_pause`,
`process_exited`, or `timeout`), and `temporary_breakpoint_cleaned: true`.

Only one native executor work item owns the complete sequence, so another MCP
operation cannot interleave. Callback handling remains independent and wakes the
bounded wait. Plugin drain wakes the same state condition, stops the command
fence, and joins the executor; no helper or detached thread is introduced.

## Verification

Contract tests cover address, timeout, operation, and mutation annotations.
Native tests cover fixed command/name formatting and exact owned-breakpoint
shape matching. The deterministic fixture provides a repeated interrupter and a
later run-to target. Isolated x32/x64 integration proves interruption preserves
the caller's breakpoint while removing the temporary target, successful run-to
reaches the target, same-operation replay does not run twice, changed arguments
conflict, and timeout pauses and removes an unreachable temporary target. Active
shutdown remains bounded and never retries the admitted mutation.

## Consequences

Agents gain a reliable atomic run-to primitive and do not need to coordinate a
fragile four-call cleanup sequence. The tool intentionally monopolizes the
single native executor until completion or bounded cleanup. It is not a trace,
conditional run, arbitrary expression runner, or guarantee that user GUI edits
at the owned address can be reconciled automatically.
