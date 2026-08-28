# ADR 0004: callback-backed pause observation and reasons

- Status: Accepted
- Date: 2026-08-29
- Scope: Execution observation after resume/step/launch

## Context

`debugger.resume` confirms the running callback and returns. A client currently
uses sleeps and repeated `debugger.state` calls to discover the following pause.
That polling can miss short state transitions, produces unnecessary requests,
and cannot distinguish system, entry, user-breakpoint, exception, step, and
explicit-pause stops without inspecting IP and breakpoint lists.

Combining resume and wait into one mutation would make a wait timeout look like
an ambiguous resume even when the resume callback was already confirmed. The two
operations therefore need distinct semantics.

## Decision

Add this read-only observation tool:

```text
debugger.wait_for_pause(after_generation, timeout_ms?)
```

- `after_generation` is a required non-negative JSON integer copied from a
  prior state or mutation result.
- `timeout_ms` defaults to 5,000 and is bounded to 1-9,000 milliseconds, below
  the default 10-second read deadline.
- The tool returns immediately when the retained pause generation is greater
  than `after_generation`; otherwise it waits on the callback condition
  variable, never a polling sleep.
- It is read-only, idempotent, and requires no `operation_id`. A timeout is
  retryable observation failure and does not make an already-confirmed mutation
  ambiguous.
- Plugin draining, debuggee termination, and transport loss wake the waiter and
  return structured cancellation or no-debuggee errors.

Successful results contain one generation-consistent snapshot:

```json
{
  "debuggee_state": "paused",
  "state_generation": 27,
  "instruction_pointer": "0x140001000",
  "active_thread_id": "0x1234",
  "pause_reason": {
    "kind": "breakpoint",
    "address": "0x140001000",
    "breakpoint_type": "software",
    "hit_count": 1
  }
}
```

The bounded pause-reason vocabulary is:

- `process_created`;
- `system_breakpoint`;
- `breakpoint` with available `BRIDGEBP` metadata;
- `exception` with code, address, and first-chance flag;
- `step`;
- `user_pause`;
- `unknown` when x64dbg does not provide a more precise callback.

Register the specific x64dbg callbacks in addition to the generic debug-event
callback. Callback payloads are copied immediately; no native pointer is
retained. A specific pause callback owns the generation and reason. A following
generic `CB_PAUSEDEBUG` for the same already-paused stop must not overwrite it.

All callback-confirmed state-changing results, especially `debugger.resume`,
also expose their confirmed `state_generation`, giving clients an unambiguous
value for the subsequent wait.

## Consistency and bounds

Only the most recent pause observation is retained. The waiter and synchronous
register/IP read execute in the serialized debugger executor after the callback;
the result is rejected if the retained pause generation changed while the
snapshot was collected. No unbounded event history is introduced.

## Rejected alternatives

- **Fixed sleeps and state polling.** Racy, noisy, and lacks pause reasons.
- **`resume_until_pause` mutation.** Conflates a confirmed mutation with a
  fallible observation and complicates no-blind-retry semantics.
- **Unbounded event queue.** Adds memory/lifecycle pressure when only the latest
  stop is needed for this workflow.
- **Infer every reason from IP after stopping.** Cannot reliably distinguish
  exceptions, explicit pause, and stepping.

## Acceptance tests

- Immediate return for an already-observed newer pause and callback wake for a
  future pause.
- Bounded retryable timeout without mutation-ledger involvement.
- Specific breakpoint/exception/step reasons are not overwritten by the generic
  pause callback.
- Stop, disconnect, and plugin unload wake active waiters within shutdown bounds.
- x32 and x64 fixtures use resume -> wait without sleeps or state polling.
- A Flare-On sample reaches a structured module/RVA breakpoint and reports a
  breakpoint reason, address, thread, IP, hit count, and consistent generation.

## Validation evidence

The x32 and x64 isolated fixtures passed resume/wait timeout, explicit pause,
step, breakpoint metadata, and active-wait unload tests. The installed x64 build
then reached Flare-On 11 `checksum.exe` main from the module-relative reference
`checksum.exe+0xa78a0`; the callback snapshot reported a software breakpoint,
hit count 1, matching IP/address, active thread, and generation 26.
