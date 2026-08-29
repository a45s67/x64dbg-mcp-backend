# ADR 0027: Read the known function containing an address

Status: Accepted on 2026-08-29.

## Context

`functions.list` provides bounded discovery and `analysis.function` explicitly
mutates the analysis database. A client often only needs to know whether one
address is already inside a retained function. Searching pages is inefficient,
while automatically invoking analysis would violate read-only intent.

## Decision

Add the read-only backend-local tool:

```text
functions.at(address)
```

`address` uses the existing closed absolute or module/RVA reference. The tool is
valid only while paused. It resolves the address natively, captures the current
module snapshot, and calls only `Script::Function::GetInfo` for that address. It
never invokes `analr`, a command fence, GUI selection, or another mutation.

The result contains `found`, nullable `function`,
`completeness: "known_only"`, and `state_generation`. A found function contains
structured `start`, `end_inclusive`, `instruction_count`, `manual`, and
`contains_query: true`. The returned module must match the resolved query module;
start must not exceed the query or end, end must remain inside the module, and
all address arithmetic must fit the debugger pointer width. A missing record is
a successful `found: false` result and is not permission to analyze.

No native allocation is returned by `GetInfo`. The executor still applies the
request deadline before and after the call and rechecks paused state/generation
before emitting a result.

## Errors and verification

Stable failures are `INVALID_ARGUMENT`, `INVALID_DEBUGGER_STATE`, `NOT_FOUND`
for an unresolved module-relative address, `BUSY`, `TIMEOUT`, `CANCELLED`, and
`INTERNAL`. The tool takes no operation ID.

Tests cover address schemas, missing/found boundaries, exact inclusive end,
malformed module/RVA records, overflow, generation churn, proof that no command
or mutation fence is used, shutdown, x32/x64 behavior, and a known analyzed
function in an authorized sample.

## Consequences

The common point query becomes one compact read. Analysis remains an explicit,
separately authorized mutation through `analysis.function`, preserving the
backend's read-versus-mutate boundary.
