# ADR 0023: Bind mutations to a backend instance

Status: Accepted on 2026-08-29.

## Context

The debugger state generation identifies changes observed by one plugin runtime,
but it is not a process identity. A sidecar restart creates a new in-memory
operation ledger while the debugger process and its generation may remain
unchanged. If a client blindly sends an earlier mutation again, the replacement
ledger cannot know whether the previous sidecar admitted or completed it and may
otherwise execute it a second time.

Transport failure, an absent debuggee, failed bearer authentication, and a
replacement backend are different states. Clients and the Dynamic Analysis
Gateway need a bounded structured identity with which to distinguish them. The
launch nonce cannot serve this purpose because it is an authentication secret
and must never cross the public HTTP/MCP boundary.

## Decision

Each sidecar process generates one unpredictable UUID v4 `instance_id` before it
connects to a plugin or starts listening. The identifier is a canonical lowercase
hyphenated UUID. It is correlation data, not an authentication credential.

For a plugin-supervised sidecar, IPC protocol minor version 1 adds `instance_id`
to the authenticated handshake acknowledgement. The plugin strictly validates
and stores the accepted UUID before entering `ready`; it then returns the same
value from `debugger.state`. The launch nonce remains secret and has a separate
purpose. A rejected acknowledgement contains no instance identity.

The sidecar exposes its identity through:

- authenticated `GET /health/ready` as `instance_id`;
- `debugger.state` as `instance_id`, with the sidecar rejecting a mismatched
  plugin value as an internal association failure; and
- the MCP `initialize` result under the bounded `_meta` key
  `x64dbg-mcp-backend/instance_id`.

Public liveness stays anonymous. It proves only that an HTTP process is alive.
Bearer authentication, loopback binding, origin checks, and output limits remain
unchanged.

Every mutating MCP tool requires both:

- `operation_id`: the canonical UUID identifying one attempted operation within
  a ledger; and
- `instance_id`: the backend identity from a successful authenticated readiness,
  initialization, or `debugger.state` observation.

The sidecar validates `instance_id` before operation-ledger admission or IPC
dispatch. A well-formed mismatch returns the non-retryable structured error
`BACKEND_RESTARTED` with `outcome: "unknown"`, the expected and current instance
IDs, and a `REFRESH_BACKEND_STATE` diagnostic. It never replays or infers the
outcome of an operation admitted by another instance. A missing or malformed ID
is `INVALID_ARGUMENT` and also never reaches the adapter.

The sidecar removes the public `instance_id` correlation field before encoding
the native IPC request. The operation ledger and the sidecar share exactly the
same lifetime, so a completed result can only be replayed while the supplied
instance ID still matches. The ledger remains bounded and in memory; this ADR
does not claim persistence or cross-instance deduplication.

The three state dimensions have distinct meanings:

- `instance_id` changes whenever the sidecar process is replaced;
- `backend` identifies the x32dbg or x64dbg backend type and is not unique; and
- `state_generation` changes as one plugin observes debugger lifecycle/state
  transitions and is not globally unique.

A client must treat a changed `instance_id` as a hard session boundary even if
the backend type, process ID, addresses, or debugger generation look identical.
Reads may be repeated deliberately after re-observing state. Mutations require a
new decision and a new `operation_id`; they are never automatically retried.

## Bounds and lifecycle

`instance_id` is always exactly 36 ASCII characters and adds no unbounded state.
There is one value per sidecar, one stored plugin copy, and no identity history.
Active requests continue to follow the existing bounded drain and cancellation
rules. Closing or unloading the plugin closes the ownership channel and ends the
sidecar; a replacement sidecar necessarily receives a different UUID.

The sidecar fails closed if the authenticated plugin rejects the protocol minor,
the acknowledgement is malformed, the UUID is non-canonical, or the plugin later
reports a different identity. No compatibility shim silently removes the new
mutation precondition.

## Verification

The stage must add:

- UUID and protocol acknowledgement unit tests, including malformed and rejected
  handshakes;
- MCP schemas and argument tests proving every mutation requires both UUIDs;
- authenticated readiness, initialization metadata, `debugger.state`, mismatch,
  and no-dispatch contract tests;
- operation-ledger tests proving replay works only inside one instance;
- supervised restart, active-request, disconnect, and unload tests; and
- isolated x32dbg and x64dbg integration plus a suitable authorized Flare-On
  qualification before packaging.

## Consequences

This is an intentional breaking mutation-input change and requires a minor
product release, refreshed examples, workflow skill, scripts, contracts, and
package verification. Read-only tool inputs remain compatible. Direct HTTP MCP
clients and the Gateway can correlate a backend without learning the launch
nonce, and stale mutations fail before they can reach x64dbg.

The design does not make an old mutation outcome knowable after a crash. It makes
that uncertainty explicit and prevents the replacement backend from turning an
ambiguous retry into an accidental second mutation.
