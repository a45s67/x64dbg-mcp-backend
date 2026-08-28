# MVP design

This document is normative for the first implementation unless superseded by a
new ADR. Keywords MUST, SHOULD, and MAY express implementation requirements.

## 1. Topology and responsibilities

```text
Direct MCP client ----\
                       >-- HTTP /mcp --> Rust sidecar
Dynamic Analysis GW --/                    |
                                      private named pipe
                                           |
                                C++ adapter plugin (.dp32/.dp64)
                                           |
                                  x32dbg/x64dbg APIs
```

The sidecar owns HTTP, MCP negotiation, bearer authentication, JSON validation,
limits, deadlines, cancellation, structured logs, metrics, and IPC correlation.
The plugin owns x64dbg callbacks, the authoritative debugger-state snapshot,
debugger-thread scheduling, and all SDK/Bridge calls.

There is one sidecar/plugin/debugger association per backend type in the MVP. A
machine MAY run one x32 association and one x64 association simultaneously, using
different configured ports and pipe names. A second instance of the same type
fails startup with `INSTANCE_ALREADY_RUNNING`; it never silently attaches to an
arbitrary debugger.

The sidecar exposes backend-local names. Gateway configuration adds its own dotted
prefix and MUST NOT require the backend to know that prefix.

## 2. Configuration

Configuration precedence is command line, environment, then a TOML file beside
the sidecar. Secrets MUST NOT be accepted on the command line because process
arguments are inspectable.

| Setting | Environment | Default | Rule |
|---|---|---:|---|
| bind address | `X64DBG_MCP_BIND` | `127.0.0.1` | MVP accepts loopback addresses only |
| port | `X64DBG_MCP_PORT` | none | Required, 1-65535; no fallback scan |
| bearer token | `X64DBG_MCP_TOKEN` | none | Required; secret reference/file preferred |
| backend type | `X64DBG_MCP_BACKEND` | inferred by plugin handshake | `x32dbg` or `x64dbg` |
| request timeout | `X64DBG_MCP_REQUEST_TIMEOUT_MS` | 10000 | capped at 30000 |
| mutation timeout | `X64DBG_MCP_MUTATION_TIMEOUT_MS` | 30000 | capped at 120000 |
| shutdown timeout | `X64DBG_MCP_SHUTDOWN_TIMEOUT_MS` | 10000 | capped at 30000 |
| max in-flight HTTP | `X64DBG_MCP_MAX_INFLIGHT` | 8 | hard maximum 32 |
| max queued debugger ops | `X64DBG_MCP_MAX_QUEUE` | 32 | hard maximum 128 |
| max request body | `X64DBG_MCP_MAX_BODY_BYTES` | 1048576 | hard maximum 4 MiB |
| max response body | `X64DBG_MCP_MAX_OUTPUT_BYTES` | 1048576 | hard maximum 4 MiB |
| max header count | `X64DBG_MCP_MAX_HEADER_COUNT` | 64 | hard maximum 128 |
| max header bytes | `X64DBG_MCP_MAX_HEADER_BYTES` | 32768 | hard maximum 64 KiB |
| request rate | `X64DBG_MCP_MAX_REQUESTS_PER_SECOND` | 100 | global fixed-window; hard maximum 1000 |

The token is at least 32 random bytes (base64url/hex representation permitted),
compared in constant time, redacted from logs, and never returned by health or MCP.
Configuration errors prevent the listener from starting.

## 3. HTTP and MCP contract

### Endpoints

#### `POST /mcp`

- Requires `Authorization: Bearer <token>`.
- Requires `Content-Type: application/json` and an `Accept` value allowing
  `application/json` (clients MAY also list `text/event-stream`).
- Implements MCP lifecycle (`initialize`, `notifications/initialized`, `ping`),
  `tools/list`, and `tools/call` for protocol revision `2025-06-18`.
- Returns a single JSON-RPC response as `application/json; charset=utf-8`. Notifications return
  HTTP 202 with no body. JSON-RPC batches are rejected with JSON-RPC `-32600`.
- Unsupported negotiated protocol versions fail initialization. Clients still
  follow the MCP initialization sequence, but the stateless MVP does not retain
  cross-request initialization state or claim to reject a later POST based on it.
- The MVP does not issue `Mcp-Session-Id`, does not retain transport sessions, and
  does not implement server-to-client requests.

#### `GET /mcp`

Returns 405 with `Allow: POST`; the MVP has no standalone SSE stream.

#### `GET /health/live`

Unauthenticated, loopback-only, constant-size response. HTTP 200 means the sidecar
event loop is alive:

```json
{"status":"ok"}
```

#### `GET /health/ready`

Requires bearer authentication. HTTP 200 only when configuration is valid, the
plugin handshake is complete, versions are compatible, and shutdown has not begun.
Otherwise HTTP 503. Response is bounded and contains no target path or token:

```json
{
  "status":"ready",
  "backend":"x64dbg",
  "plugin_connected":true,
  "debugger_state":"paused",
  "diagnostic_code":null,
  "next_actions":[],
  "protocol_version":"2025-06-18",
  "version":"0.1.0"
}
```

Unknown paths return 404. Authentication failure returns HTTP 401 with a generic
body and `WWW-Authenticate: Bearer`; authorization data is never logged.
All JSON health and structured HTTP error responses also declare
`application/json; charset=utf-8` for compatibility with clients that do not
apply JSON's UTF-8 default correctly.

When the plugin is connected without a debuggee, readiness remains HTTP 200 and reports
`diagnostic_code: "NO_DEBUGGEE"` with the single non-executing action hint
`{"code":"CALL_DEBUGGEE_LAUNCH","tool":"debuggee.launch"}`. A disconnected diagnostic
sidecar returns HTTP 503 with `PLUGIN_DISCONNECTED` and `START_DEBUGGER_WITH_PLUGIN`.
Structured HTTP errors always contain bounded `details`; media-type and protocol validation
errors list their accepted values as specified by ADR 0010.

### Tool result and error envelope

Successful tool calls return MCP textual JSON content plus `structuredContent` of
the same logical value. Tool execution failures use `isError: true` so callers can
inspect them; malformed MCP/JSON-RPC calls use standard JSON-RPC errors.

```json
{
  "ok": false,
  "error": {
    "code": "INVALID_DEBUGGER_STATE",
    "message": "operation requires a paused debuggee",
    "retryable": false,
    "details": {"required":["paused"],"actual":"running"},
    "operation_id": "caller-id-if-present"
  }
}
```

Stable backend codes include `UNAUTHENTICATED`, `INVALID_ARGUMENT`,
`INVALID_DEBUGGER_STATE`, `NO_DEBUGGEE`, `NOT_FOUND`, `ACCESS_DENIED`,
`REQUEST_TOO_LARGE`, `OUTPUT_LIMIT_EXCEEDED`, `STALE_CURSOR`, `BUSY`, `TIMEOUT`, `CANCELLED`,
`PLUGIN_UNAVAILABLE`, `VERSION_MISMATCH`, `INSTANCE_ALREADY_RUNNING`,
`OPERATION_ID_CONFLICT`, `UNSUPPORTED`, and `INTERNAL`. Internal errors expose a
correlation ID, never stack traces or raw OS error text.

## 4. Initial tool catalog

All addresses and machine-sized integers are JSON strings in canonical lowercase
hex (`0x...`) to avoid JSON precision loss. ADR 0003 additionally permits the
closed address-reference objects `{ "absolute": "0x..." }` and
`{ "module": "sample.exe", "rva": "0x..." }`; resolution remains native and
atomic with the consuming debugger operation. Byte payloads are lowercase hex
unless explicitly documented. Every list uses `limit` and an opaque `cursor`;
output is truncated only at item boundaries and reports `next_cursor`.

| Tool | Kind | Valid state | Purpose / key bounds |
|---|---|---|---|
| `debugger.state` | read | any | Backend, lifecycle state, PID/TID, architecture |
| `debugger.snapshot` | read | paused | Compact pause/register/IP snapshot with at most 64 instructions |
| `debugger.wait_for_pause` | read | active debuggee | Wait for a newer callback pause; 1-9,000 ms; structured reason |
| `debugger.pause` | mutate | running | Request pause; bounded wait for callback confirmation |
| `debugger.resume` | mutate | paused | Resume execution |
| `debugger.step_into` | mutate | paused | One instruction, then bounded wait for pause |
| `debugger.step_over` | mutate | paused | One instruction, then bounded wait for pause |
| `debugger.stop` | mutate | starting/running/paused | Stop current debug session |
| `debuggee.launch` | destructive mutation | absent | Canonicalize and load an existing executable, then wait past process creation for an actionable callback pause |
| `registers.read` | read | paused | Selected registers or bounded complete register set |
| `address.resolve` | read | paused | Resolve absolute or module/RVA input and return canonical location metadata |
| `memory.read` | read | paused | Read at most 64 KiB per call; report partial/unreadable ranges |
| `memory.write` | mutate | paused | Write at most 4 KiB; explicit hex bytes and operation ID |
| `memory.map` | read | paused | Paginated regions, at most 256 per page; optional module/committed/executable/compact filters |
| `modules.list` | read | paused | Paginated loaded modules, at most 256 per page |
| `threads.list` | read | paused | Paginated threads, at most 256 per page |
| `breakpoints.list` | read | paused/running | Paginated breakpoint snapshot |
| `breakpoints.set` | mutate | paused | Create software breakpoint with explicit address |
| `breakpoints.remove` | mutate | paused | Remove backend-observed breakpoint by address/type |
| `disassembly.read` | read | paused | At most 256 decoded instructions from an address |
| `expression.evaluate` | read | paused | Evaluate x64dbg expression; no command execution |
| `symbols.search` | read | paused | Search up to 65,536 retained symbols with bounded, filter-bound pagination |
| `functions.list` | read | paused | List retained analyzed functions and exact-start symbol names; known-only |
| `strings.search` | read | paused | Scan at most 1 MiB per request for bounded ASCII/UTF-8 or UTF-16LE strings |
| `references.to` | read | paused | Paginate up to 65,536 retained inbound xrefs for an address |

Every mutating tool requires `operation_id` as a canonical lowercase UUID. Arbitrary debugger
command execution, process launch/attach, file upload/download, scripting, shell
execution, and unbounded search are intentionally excluded from the MVP. They need
separate threat-model ADRs.

Tool annotations advertise `readOnlyHint`, `destructiveHint`, and
`idempotentHint` accurately. Mutation IDs make replay detectable; they do not turn
intrinsically non-idempotent debugger actions into blind-retry-safe operations.

## 5. State and threading model

### Debugger state

The plugin maintains an atomic/versioned snapshot:

```text
plugin: starting -> ready -> draining -> stopped
debuggee: absent -> starting -> paused <-> running -> stopping -> absent
                                      \-> exited -> absent
```

Transitions come from x64dbg callbacks, not inference from a command return value.
Each snapshot carries a monotonically increasing `state_generation`. Requests state
their required state and revalidate it on the debugger executor immediately before
touching debugger APIs. A command completes only after the relevant callback/state
transition or its deadline; an accepted command is not reported as completed.
Callback-confirmed mutations include their confirmed generation in the tool
result. Clients pass that value to `debugger.wait_for_pause`; an observation
timeout is retryable and never changes the already-confirmed mutation outcome.
State-sensitive reads capture the generation before native collection and
recheck it afterward. A callback during collection returns retryable `BUSY`;
the backend never labels mixed-generation data with a newer generation.

### Threads and queues

- Sidecar accept/HTTP tasks run on a bounded Tokio runtime. A semaphore limits
  in-flight requests before parsing expensive bodies.
- Exactly one bounded IPC request queue feeds the plugin. Overload returns `BUSY`;
  it never grows without limit.
- The plugin IPC thread validates and copies request data. It never calls debugger
  APIs that require debugger-thread affinity.
- A `DebuggerExecutor` serializes operations. Mutating debugger commands are
  submitted through x64dbg's queued command path and completed from state/event
  callbacks; they are never invoked directly on the HTTP or IPC thread. Read APIs
  require an API-by-API thread-affinity audit before use. Each work item owns copied
  data and a promise/cancellation token; no callback-owned pointer escapes its
  callback. If no supported safe scheduling path exists for an operation, that
  operation is omitted rather than called from the wrong thread.
- Read operations may execute concurrently only after API-by-API proof of thread
  safety. The MVP default is serialized debugger access.
- Deadlines are absolute and propagated HTTP -> IPC -> executor. Cancellation can
  remove queued work. Once a mutation starts, cancellation means “outcome may be
  unknown”; the backend observes state and records the result under `operation_id`
  instead of retrying.

The IPC is length-prefixed, versioned, bounded binary messages with request ID,
deadline, operation ID, method, payload, and typed response. Maximum frame size is
1 MiB. The pipe uses a random per-launch nonce plus a Windows ACL limited to the
current user (and SYSTEM where required). Both peers authenticate the handshake and
negotiate an exact major protocol version.

## 6. Security, limits, and lifecycle

### Security

- Bind only to configured loopback IPv4/IPv6 addresses in the MVP. Reject wildcard
  and non-loopback addresses rather than warning.
- Require the bearer token on `/mcp` and readiness. Apply authentication before
  JSON parsing or debugger queue admission.
- Validate `Origin` when present: allow an explicit configured list; otherwise
  reject browser origins. Do not enable CORS by default.
- Apply header count/size, body size, parse-depth, string length, request-rate,
  queue, operation, response, and deadline limits.
- Logs are structured and bounded. Redact auth headers, tokens, memory bytes,
  expressions, target paths, and IPC nonces by default.
- Treat all tool inputs, debuggee memory, symbols, and debug strings as untrusted.
  Never format them as format strings and never interpret memory as commands.

### Startup

1. Plugin obtains a same-user single-instance lock for its backend type.
2. It creates the secured named pipe and launch nonce.
3. After plugin initialization (never from `DllMain`), an owned worker starts the
   installed sidecar by absolute path. Manual launch is diagnostic-only. The nonce
   is passed through a restricted inherited handle or protected pipe handshake—not
   a command-line secret. Startup does not block the debugger UI.
4. Sidecar validates configuration, binds loopback, authenticates the plugin, and
   becomes ready. Binding failure is explicit; no port increment fallback occurs.
5. Plugin callback registration and state synchronization complete before ready.

### Graceful shutdown and unload

1. `plugstop` atomically changes plugin state to `draining`; readiness becomes 503.
2. Sidecar stops accepting new MCP work. New/queued requests receive
   `PLUGIN_UNAVAILABLE` or `CANCELLED` as appropriate.
3. Read-only active work gets a short drain window. Queued mutations are cancelled.
   Started mutations are not replayed; their last observed outcome is cached.
4. Plugin signals all waits, stops pipe reads, and joins every owned thread.
5. It unregisters callbacks/commands only after no executor work can begin, closes
   handles, zeroes secrets, and returns from `plugstop` only when plugin code cannot
   execute again.
6. Sidecar exits when its plugin disconnects (default) after flushing bounded logs.

Default drain is 5 seconds and total shutdown deadline is 10 seconds. Windows I/O
cancellation is used to break blocking pipe operations. There are no detached
threads. If an SDK call itself cannot be interrupted, it must not be admitted
without a known finite bound; unload safety takes priority over completing a call.

## 7. Packaging and installation

A release ZIP is self-contained and signed when release infrastructure permits:

```text
x64dbg-mcp-backend/
  x64/plugins/x64dbg-mcp-backend.dp64
  x32/plugins/x64dbg-mcp-backend.dp32
  server/x64dbg-mcp-server.exe
  config/config.example.toml
  LICENSES/
  checksums.txt
```

The installer/copy script places `.dp64` in the x64 plugins directory and `.dp32`
in the x32 plugins directory; x64dbg uses those distinct extensions. The sidecar
may be shared but configuration must allocate different ports for x32 and x64.
Installation never generates a predictable token: an interactive helper creates a
cryptographically random token and writes a current-user-readable config/secret
file. Manual installation remains supported and documented.

Build outputs include SBOM, third-party notices, checksums, versions, and protocol
compatibility metadata. Do not require Python, Node, Rust, or Visual C++ build tools
on the target machine; either statically link permitted runtimes or ship the
documented redistributable.

## 8. Verification strategy

- Unit: parsing/validation, address codec, state transition table, error mapping,
  limits, deduplication, redaction, pagination, timeout and cancellation races.
- Contract: golden MCP initialize/list/call/error exchanges, content negotiation,
  auth, 405 behavior, JSON-RPC notifications, tool schemas, and health responses.
- IPC contract: cross-language golden frames, corrupt/truncated/oversize frames,
  version mismatch, nonce failure, disconnect at every operation phase.
- Integration: launch sidecar with a fake deterministic plugin; then exercise real
  x32dbg and x64dbg against small fixture binaries in isolated Windows CI workers.
- Shutdown: unload during idle, queued read, active read, queued mutation, active
  mutation, blocked pipe read, client disconnect, and sidecar crash. Assert all
  handles/threads/processes terminate within deadline and the debugger remains
  usable.
- Robustness: fuzz HTTP/JSON/tool inputs and IPC decoding; soak bounded concurrency;
  verify memory use, queue length, output size, and log volume remain capped.

No mutation test relies on retry. Tests inject lost replies and assert that querying
the same `operation_id` yields the recorded/unknown outcome without re-execution.

## 9. Phased implementation plan

### Phase 0 — decision and contract freeze

Accept this ADR, assign IPC/schema versions, create threat model, select Rust MCP
and HTTP crates by spike, and turn example exchanges/tool schemas into golden files.
Exit: architecture and externally observable MVP contract are review-approved.

### Phase 1 — sidecar skeleton and fake adapter

Implement configuration, loopback enforcement, auth, health, lifecycle, tool
registry, limits, errors, structured logging, and a deterministic fake IPC adapter.
Exit: unit and MCP/health contract tests pass without x64dbg.

### Phase 2 — versioned IPC and plugin lifecycle

Implement secured pipe handshake, bounded framing, correlation/deadlines, plugin
exports, callbacks, state snapshot, executor abstraction, and strict unload path.
Exit: IPC fault tests and repeated load/unload tests pass for Win32 and x64.

### Phase 3 — read-only debugger tools

Implement state, registers, memory read/map, modules, threads, breakpoints list,
disassembly, and expression evaluation with pagination and output caps.
Exit: fixture-based x32/x64 integration tests pass; fuzz targets are clean.

### Phase 4 — controlled mutations

Add operation ledger and pause/resume/step/stop, memory write, and breakpoint
mutations. Completion is callback-confirmed and ambiguous outcomes are preserved.
Exit: mutation race, cancellation, deduplication, and no-retry tests pass.

### Phase 5 — hardening and release

Run soak and shutdown matrices, audit plugin calls/thread affinity, generate SBOM
and signed packages, document direct-client and Gateway configuration, and perform
a clean-machine install test for x32dbg and x64dbg.
Exit: all automated suites pass and no process, thread, or handle leak remains.

Post-MVP work (separate ADRs): SSE/resumption, remote bind with TLS/OAuth, multiple
same-type debugger instances, resources/prompts, attach/launch, scripting, and
arbitrary command execution.

Accepted post-MVP additions are the bounded `debuggee.launch` mutation in ADR
0002 and structured module-relative address references in ADR 0003. Neither
exposes arbitrary debugger commands or expressions to mutation inputs.

## References

- [MCP specification revision 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/),
  especially Base Protocol, Lifecycle, Tools, Authorization, and
  [Streamable HTTP Transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports).
- [x64dbg plugin basics](https://help.x64dbg.com/en/latest/developers/plugins/basics.html),
  [callback rules](https://help.x64dbg.com/en/latest/developers/plugins/Callbacks/index.html),
  and [plugin installation conventions](https://help.x64dbg.com/en/latest/developers/plugins/).
