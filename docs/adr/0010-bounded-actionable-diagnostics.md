# ADR 0010: Bounded actionable bootstrap diagnostics

## Status

Accepted before implementation on 2026-08-29.

## Context

The transport already distinguishes public liveness, authenticated backend readiness, plugin
connectivity, and debuggee state. That distinction is correct, but callers still have to infer the
next step when a manually launched sidecar has no plugin or when a connected debugger has no
debuggee. HTTP media-type failures also have stable codes but do not return machine-readable
accepted values. Field testing additionally showed that starting a second debugger process is not
a supported way to hand a target to the already connected backend.

Diagnostics must remain small, stable, non-secret, and observational. They must not launch a
target, retry a mutation, enumerate local paths, reveal a bearer token or pipe nonce, or convert
readiness into target availability.

## Decision

Keep `/health/live` unchanged and public. Extend authenticated `/health/ready` and
`debugger.state` with the same bounded diagnostic vocabulary:

- connected with no debuggee (`absent` or callback-observed `exited`):
  `diagnostic_code: "NO_DEBUGGEE"` and one next action
  `{code: "CALL_DEBUGGEE_LAUNCH", tool: "debuggee.launch"}`;
- connected with a debuggee: `diagnostic_code: null` and `next_actions: []`;
- disconnected manual diagnostic sidecar: HTTP 503, `diagnostic_code: "PLUGIN_DISCONNECTED"`,
  and one next action `{code: "START_DEBUGGER_WITH_PLUGIN"}`.

`next_actions` is always an array and is capped by construction at one item in this revision.
Action codes are hints, not commands. The server never executes them. Readiness remains `ready`
when the plugin is connected but the debuggee is absent, because the backend can immediately
accept `debuggee.launch`.

Extend structured HTTP validation errors with a bounded `details` object. Existing errors receive
an empty object. `INVALID_ACCEPT` reports
`accepted_media_types: ["application/json", "*/*"]`; `INVALID_CONTENT_TYPE` reports
`accepted_media_types: ["application/json"]`; and `INVALID_PROTOCOL_VERSION` reports
`supported_versions: ["2025-06-18"]`. Authentication and origin errors do not disclose more
configuration.

Document that one debugger instance exists per backend type in the MVP. A target must be loaded
through `debuggee.launch` on the connected instance (or manually in that same UI); starting a
second x64dbg/x32dbg process is not a backend handoff mechanism.

## Rejected alternatives

- **Make readiness fail when no debuggee exists.** Conflates an operational backend with target
  state and prevents clients from discovering that launch is available.
- **Return free-form remediation paragraphs only.** Harder for gateways and agents to consume
  reliably than stable codes and exact tool names.
- **Expose configuration paths, process command lines, tokens, or pipe names.** Adds sensitive
  local detail without improving safe remediation.
- **Automatically launch the last target.** Hidden mutation, surprising lifecycle behavior, and
  incompatible with explicit operation identity.

## Verification

- HTTP contract tests assert authenticated absent/paused/disconnected diagnostic shapes and exact
  bounded media/protocol details.
- Native state tests and isolated x32/x64 integrations assert the absent hint before launch and its
  removal after launch.
- Installed acceptance verifies `debuggee.launch` from the advertised action, normal paused state,
  and clean debugger/sidecar shutdown.
