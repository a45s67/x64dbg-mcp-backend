# ADR 0011: Bounded shutdown matrix

Status: Accepted

## Context

The backend already has focused lifecycle tests for idle plugin shutdown, an
active `debugger.wait_for_pause`, inherited-supervisor EOF, installed
configuration, and an injected sidecar crash. Those tests establish important
individual properties, but do not yet exercise the HTTP-to-IPC admission stages
as a matrix.

The sidecar accepts a bounded number of HTTP requests. Its `IpcAdapter` owns one
authenticated duplex stream protected by an asynchronous mutex, so exactly one
request can be on the wire while other admitted HTTP requests wait before IPC.
The native worker then processes that one request synchronously. Consequently,
the relevant MVP shutdown states are:

- no active request;
- one read waiting for a plugin reply;
- a second read waiting for the IPC mutex;
- a mutation waiting for the IPC mutex;
- one mutation sent with no reply yet;
- an HTTP client disconnect while plugin work is active; and
- either peer disappearing unexpectedly.

Mutations are especially sensitive: cancellation or a lost reply must produce an
unknown outcome, never an automatic replay.

## Decision

Maintain a deterministic Windows shutdown matrix against the real sidecar and a
controlled named-pipe peer. Each case uses a fresh process, pipe, loopback port,
and bounded deadline. The matrix will assert:

1. supervisor EOF stops accepting new work and the process exits within the
   configured drain bound;
2. active HTTP work cannot keep the sidecar alive past that bound;
3. requests waiting for the IPC mutex are cancelled without reaching the plugin;
4. a sent mutation is observed exactly once even when no response is returned;
5. disconnecting an HTTP client does not create an unmanaged background worker;
6. plugin and sidecar crash paths remain separately covered by native lifecycle
   tests; and
7. all test processes, sockets, and pipe handles are owned and joined or dropped.

The test timeout is deliberately shorter than normal production defaults so a
regression fails quickly. Tests use public HTTP and the versioned IPC contract;
they do not add production-only debug endpoints.

Release verification also repeats the real isolated x32dbg and x64dbg integration
flows. Repetition is finite and opt-in rather than an unbounded soak: automation
must never leave debugger or sidecar processes behind, and it must not terminate
unrelated user processes.

## Consequences

- Shutdown behavior is verified at each reachable admission stage rather than
  inferred from a single active-request test.
- A queued mutation is proven not to cross IPC during a blocked read, while an
  active mutation is proven not to be retransmitted.
- The matrix complements native unload tests; it cannot prove that an arbitrary
  third-party debugger SDK call will return. Such calls remain admissible only
  when their API contract and observed behavior are finite.
- The native executor queue remains a defensive capacity bound, although current
  IPC serialization means it normally contains at most one work item.

## Rejected alternatives

- **Detached cleanup workers.** They would allow code to run after plugin unload
  and violate ownership requirements.
- **Killing unrelated processes by image name during tests.** This can destroy a
  user's debugger session and hides ownership leaks.
- **Retrying a mutation after timeout or disconnect.** The first attempt may have
  taken effect; only the operation ledger or an explicit state query may resolve
  the outcome.
- **An endless soak in the default test suite.** It makes failures difficult to
  reproduce and violates bounded CI execution. Repetition must have an explicit
  finite count.
