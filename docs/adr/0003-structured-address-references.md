# ADR 0003: structured module-relative address references

- Status: Accepted
- Date: 2026-08-29
- Scope: Address resolution and address-taking debugger tools

## Context

Runtime absolute addresses change under ASLR. During the `checksum.exe` field
test, the caller had to enumerate modules and manually translate the stable
`main.main` RVA into an absolute address before setting a breakpoint. Other
debugger integrations commonly pass arbitrary debugger expressions such as
`module+offset`; this is convenient, but it makes validation, ambiguity,
cross-backend behavior, and mutation auditing depend on a debugger-specific
expression language.

Resolving a module in the Rust sidecar would also create a time-of-check to
time-of-use race: the module snapshot could change before the C++ plugin queues
the actual breakpoint or memory operation.

## Decision

Define `AddressRef` as this closed union:

```json
"0x140001000"
```

```json
{ "absolute": "0x140001000" }
```

```json
{ "module": "sample.exe", "rva": "0x1000" }
```

The legacy canonical hexadecimal string remains accepted. Structured objects
reject unknown fields. Addresses and RVAs remain lowercase hexadecimal strings;
module names are bounded, contain no control characters or path separators, and
are matched case-insensitively as Windows module names.

Add a read-only `address.resolve(address)` tool. Resolution and every consuming
debugger operation happen inside the same serialized debugger-safe executor.
Successful results include the canonical absolute address, owning module and
base when available, RVA when available, and the debugger state generation.

Initially, `AddressRef` is accepted by:

- `address.resolve`;
- `memory.read` and `memory.write`;
- `breakpoints.set` and `breakpoints.remove`;
- `disassembly.read`.

The module-relative form requires a paused debuggee, exactly one matching loaded
module, an RVA strictly below the reported module size, and overflow-safe base
addition. Missing and duplicate modules, out-of-range RVAs, and overflow return
structured `INVALID_ARGUMENT` errors. Absolute addresses outside modules remain
valid for memory and debugger operations, but their resolved module metadata is
null.

Arbitrary x64dbg expressions are not part of `AddressRef`. The existing
read-only `expression.evaluate` escape hatch remains separate and its result can
be supplied explicitly as an absolute address.

## Consequences

- Gateway clients can preserve `{module, rva}` across ASLR without knowing an
  x64dbg expression grammar.
- Mutations record the caller's original structured arguments in the operation
  ledger and return the exact runtime address they used.
- Module reload cannot occur between resolution and the native operation on the
  debugger thread. Returned generation metadata lets clients reject stale
  observations after the call.
- The same `AddressRef` schema can later add a discriminated symbol form without
  changing existing absolute or module-relative calls.

## Rejected alternatives

- **Accept all `DbgEval` expressions everywhere.** Too broad and
  backend-specific for mutation inputs.
- **Resolve module addresses in the sidecar or Gateway.** Introduces stale
  module snapshots and repeats resolver behavior across clients.
- **Require a separate resolve call before every operation.** Useful for
  inspection, but insufficient for atomic mutation resolution.
- **Treat file offsets as RVAs.** PE file offsets and virtual RVAs are distinct
  and cannot be safely interchanged.

## Acceptance tests

- Schema and runtime accept all three forms and reject malformed, unknown-field,
  oversized, path-like, uppercase-hex, and out-of-range inputs.
- Module matching is case-insensitive and rejects both missing and duplicate
  matches.
- Absolute and module-relative forms resolve to the same canonical location in
  x32dbg and x64dbg fixtures.
- Breakpoint, memory, and disassembly operations return the location actually
  used; mutation replay returns the recorded result without resolving again.
- The installed x64 workflow can set the `checksum.exe` `main.main` breakpoint
  directly with `{ "module": "checksum.exe", "rva": "0xa78a0" }`.
