# ADR 0018: Verified single-register writes and callback-confirmed step out

Status: Accepted before implementation on 2026-08-29.

## Context

Register modification is useful for controlled dynamic analysis, but a batch
write can partially succeed and leave an ambiguous machine context. Register
names also differ between x32dbg and x64dbg, and JSON numbers cannot exactly
represent every 64-bit value.

x64dbg exposes synchronous `Script::Register::Set(RegisterEnum, duint)` on the
plugin API. It avoids forwarding caller-controlled debugger expressions or
commands, but success still needs a copied before/after register snapshot and a
debugger-generation check.

x64dbg's `StepOut/rtr` is implemented as repeated step-over until the current
stack frame reaches a return instruction. Unlike step-into and step-over, its
normal final callback is `CB_PAUSEDEBUG`, not `CB_STEPPED`. Waiting for
`CB_STEPPED` would therefore time out after a successful operation, while
accepting any pause as successful step-out would confuse a breakpoint,
exception, or user interruption with reaching the return.

## Decision

Add two backend-local mutations:

```text
registers.write(name, value, operation_id)
debugger.step_out(operation_id)
```

This wire and workflow addition advances the backend package and managed skill
to 0.5.0.

### Register write

- One call writes exactly one register. There is no batch form and therefore no
  partial multi-register commit.
- `name` is lowercase and must be a full-width core register. x64 accepts
  `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `rbp`, `rsp`, `rip`, `r8` through
  `r15`, and `eflags`. x86 accepts `eax`, `ebx`, `ecx`, `edx`, `esi`, `edi`,
  `ebp`, `esp`, `eip`, and `eflags`. Partial registers, vector registers,
  segments, and debug registers are excluded.
- `value` is a canonical lowercase `0x` hexadecimal string. It must fit the
  selected register and debugger architecture; JSON floating-point precision is
  never involved.
- The serialized debugger executor requires a paused debuggee, captures the
  current generation and register value, calls the typed
  `Script::Register::Set` API, captures the register dump again, verifies the
  exact value, and rechecks the generation. The result reports name, previous
  value, current value, `changed`, and `state_generation`.
- API rejection before the typed call is a known failure. Failure or mismatch
  after submitting the synchronous write is an unknown mutation outcome and is
  never automatically retried. The operation ledger replays a completed result
  for the same operation ID and arguments.

### Step out

- The executor accepts the operation only while paused and submits the fixed
  `rtr` command through `DbgCmdExec`. No repeat count or caller command text is
  accepted.
- Completion first requires a paused callback generation newer than the
  pre-command generation. The executor then captures CIP, CSP, pause metadata,
  and one decoded instruction and rechecks that exact paused generation.
- `completed: true` requires the current instruction to be a decoded return and
  the final CSP to be greater than or equal to the initial CSP. This matches the
  debugger's run-until-return behavior; the return instruction itself has not
  yet executed.
- A confirmed pause at a breakpoint, exception, or manual interruption is a
  known result with `completed: false`, the actual pause reason, CIP/CSP, and
  generation. Clients inspect it and choose the next action; they do not issue a
  speculative retry.
- Queue rejection is retryable `BUSY`. Timeout, unload, exit before a confirmed
  pause, or loss of correlation after command admission has unknown outcome.

## Bounds, threading, and lifecycle

Both tools use the existing one-slot mutation ledger and one serialized native
executor. They create no thread. Inputs and outputs are fixed-size, request
deadlines remain bounded, callback waits are woken during unload, and all native
structures are copied before returning.

## Rejected alternatives

- **Batch register writes.** Partial success cannot be rolled back safely.
- **Register expressions or a generic `mov` command.** Expands the parser and
  injection surface without improving the core workflow.
- **Partial or debug-register writes.** Aliasing and breakpoint ownership make
  verification and intent less clear; typed breakpoint tools own debug state.
- **Use `CB_STEPPED` for step-out.** x64dbg does not emit it for normal `rtr`
  completion.
- **Treat the first generic pause as successful return.** Existing breakpoints,
  exceptions, and user pauses can interrupt `rtr` first.
- **Fixed sleeps followed by CIP polling.** Racy and not callback-correlated.

## Verification

- Rust tests cover strict schemas, canonical hexadecimal values, register-name
  allowlists, operation IDs, and catalog mutation annotations.
- Native policy tests cover architecture-specific register mapping/width and
  return-instruction classification. The isolated integration covers exact
  read-back, generation correlation, and mutation replay.
- Isolated x32dbg and x64dbg integration changes and restores a disposable
  general-purpose register, proves replay does not re-execute, breaks inside an
  exported fixture function, and confirms `step_out` reaches its return.
- Installed Flare-On qualification uses only a disposable register value and a
  reliably reached function frame; otherwise the deterministic dual-architecture
  fixture remains the mandatory evidence and the limitation is recorded.
