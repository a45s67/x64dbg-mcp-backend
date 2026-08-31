# ADR 0039: Exact typed breakpoint enable and disable transitions

Status: Implemented and qualified in 0.18.0 on 2026-08-31.

## Context

The backend can create, list, and remove software, hardware, memory,
conditional, and exception breakpoints, but it cannot temporarily disable one
without deleting its configuration. x64dbg exposes separate enable and disable
commands for each native breakpoint kind. Those commands preserve the record,
yet their identity and side effects are not uniform.

Current upstream command implementations show that a disabled hardware
breakpoint relinquishes its debug-register slot and may receive a different
slot when enabled again. Memory breakpoints retain their region, access, size,
and single-shot policy. Exception breakpoints retain their chance policy.
Conditional breakpoints are native software breakpoints whose backend-derived
name is their durable ownership marker. The no-argument software commands also
have an enable-all or disable-all form, which is outside this backend's bounded
mutation model.

The decision is based on the pinned SDK and the current upstream command
implementation and documentation:

- <https://github.com/x64dbg/x64dbg/blob/development/src/dbg/commands/cmd-breakpoint-control.cpp>
- <https://help.x64dbg.com/en/latest/commands/breakpoint-control/EnableBPX.html>
- <https://help.x64dbg.com/en/latest/commands/breakpoint-control/EnableHardwareBreakpoint.html>
- <https://help.x64dbg.com/en/latest/commands/breakpoint-control/EnableMemoryBreakpoint.html>
- <https://help.x64dbg.com/en/latest/commands/breakpoint-control/EnableExceptionBPX.html>

## Decision

Add exactly two paused-state mutations:

```text
breakpoints.enable(selector, operation_id, instance_id)
breakpoints.disable(selector, operation_id, instance_id)
```

`selector` is a closed discriminated union:

- `software`: address;
- `hardware`: address, access, and size;
- `memory`: address, access, and size;
- `conditional`: address and `managed_id`; or
- `exception`: code, chance, and `managed_id`.

Addresses use the existing absolute/module-RVA union. Access, size, chance,
canonical exception-code, UUID, and architecture constraints are identical to
the corresponding set/remove tools. Extra or kind-inapplicable fields are
rejected. There is no name, expression, debugger command, wildcard, list of
breakpoints, PID, slot selector, or all-breakpoints mode.

Before mutation, the plugin resolves the address and reads one exact native
record. The requested kind and every immutable selector field must match.
`software` refuses any backend-managed conditional record and any record with
conditional/action fields, so it cannot bypass conditional ownership.
`conditional` and `exception` require the exact recoverable managed identity.
Foreign, renamed, missing, or shape-modified records fail closed without a
command. Hardware identity is address, access, and size; its transient DR slot
is explicitly not identity.

The executor emits exactly one fixed command with an explicit hexadecimal
address or exception code:

```text
bpe / bpd
bphwe / bphwd
bpme / bpmd
EnableExceptionBPX / DisableExceptionBPX
```

It never invokes a no-argument command. A private command-queue fence is used
because these transitions do not provide a dedicated completion callback. The
plugin then reads the record back and requires exact presence, requested
enabled state, and unchanged identity and configuration. A hardware enable may
change only its slot; all other selected and policy fields remain invariant.
Enabling hardware also preflights slot availability and reports a bounded
conflict if all four slots are occupied.

Requesting the state already observed is a successful no-op with
`changed: false`; otherwise success returns `changed: true`. Both return the
normalized typed breakpoint observation, including the current nullable
hardware slot. The normal instance-bound operation ledger provides exact replay
and changed-argument conflict behavior. After command submission, a missing or
contradictory read-back is outcome unknown; neither the server nor a client may
blindly retry the mutation under a new operation ID.

Managed breakpoint ownership is unchanged by toggling. Disabled conditional
and exception records retain their managed IDs and remain removable by their
typed remove tools. Plugin unload does not re-enable, delete, or otherwise
rewrite breakpoint state.

## Verification

Contract tests cover the selector union, kind-specific required and forbidden
fields, address/code bounds, UUIDs, instance and operation identity, result
shape, annotations, and malformed inputs. Native policy tests cover exact
identity, ordinary-versus-managed software separation, disabled managed
ownership, invariant read-back, hardware slot churn and exhaustion, and fixed
command formatting.

Fresh isolated x32dbg and x64dbg workflows must create every supported kind,
disable it, confirm listing and non-trigger behavior where practical, re-enable
it, confirm exact configuration and trigger behavior, replay the same operation,
reject changed arguments, remove it, and shut down cleanly. Shutdown tests cover
active requests. The installed package and managed skill must pass offline
verification, followed by a non-destructive Flare-On breakpoint transition
smoke on both applicable architectures.

## Consequences

Agents can temporarily silence exact breakpoints without losing policy or
ownership, and can compose this with list, run, wait, and remove operations.
The tools remain narrow state transitions rather than a general breakpoint
editor. Bulk enable/disable, arbitrary conditions or commands, slot selection,
process scope, automatic analysis, scripting, tracing extensions, and all other
previously rejected candidates remain outside the roadmap.
