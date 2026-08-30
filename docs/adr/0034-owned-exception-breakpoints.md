# ADR 0034: Owned typed exception breakpoints

Status: Implemented and qualified in 0.14.0 on 2026-08-31.

## Context

Malware, packers, and anti-debug logic frequently use structured exceptions.
The backend already reports exception pauses and lists native breakpoint types,
but it cannot ask x64dbg to stop on one exact exception code and chance.
Composing an arbitrary debugger command would discard operation identity,
ownership, typed read-back, and bounded cleanup.

The pinned SDK exposes `BpRefException`, `BpRefExists`, typed breakpoint fields,
and `BPEXTYPE`. Upstream x64dbg implements one exception-breakpoint record per
32-bit code and distinguishes first chance, second chance, and all chances. The
creation and deletion commands accept an exact code, while `BP_REF` provides
the authoritative postcondition.

## Decision

Add two current-debuggee mutations:

```text
breakpoints.exception.set(code, chance, operation_id, instance_id)
breakpoints.exception.remove(code, chance, managed_id, operation_id, instance_id)
```

`code` is canonical lowercase hexadecimal from `0x0` through `0xffffffff`.
`chance` is `first`, `second`, or `both`; `both` maps only to x64dbg's native
`ex_all` value and is returned as `both`. Names and symbolic exception
expressions are not accepted.

Set requires a paused current debuggee, rejects an existing exception
breakpoint for the code, and derives an internal name from the canonical set
operation UUID:

```text
__x64dbg_mcp_exception_<uuid>
```

The plugin queues only a fixed `SetExceptionBPX 0x<code>, <chance>` command,
waits for the private queue fence, assigns the fixed internal name through the
typed breakpoint-field API, and reads the record back. Success requires exact
code, enabled exception type, native chance, internal name, and empty command
and logging fields. The result returns the UUID as `managed_id`, not the
internal prefix.

Remove requires the same code, chance, and `managed_id`. It refuses an absent,
foreign, renamed, disabled, or chance-modified record. It queues one exact
`DeleteExceptionBPX 0x<code>` command and confirms absence. It never invokes
the command's dangerous no-argument delete-all form.

If creation succeeds but naming or read-back fails, the executor may issue one
compensating delete only while the precondition and exact newly created record
remain provable. Any ambiguous creation, cleanup, deletion, timeout, disconnect,
or unload result is recorded as outcome unknown under the original operation
ID. A caller must query `breakpoints.list` or replay that same operation ID; the
backend never blindly submits the mutation again.

`breakpoints.list` adds `code`, `chance`, and `managed_id` for exception
records. `managed_id` is null for user- or externally-created records. Managed
records belong to the current x64dbg debug database and remain ordinary visible
x64dbg breakpoints after client disconnect or plugin unload; unload does not
silently mutate debugger state. Explicit typed removal is the cleanup rule, and
the recoverable managed ID remains visible after backend restart.

The tools do not accept a PID. Scope is the one active debuggee owned by this
backend instance, consistent with the MVP's one-debugger-instance model.

## Verification

Contract tests cover the code, chance, managed identity, instance identity, and
mutation annotations. Native policy tests cover chance mapping, fixed command
and name formatting, exact ownership checks, and rejection of foreign records.
The deterministic fixture raises and handles one private exception code only
after an MCP-controlled trigger. Isolated x32 and x64 integrations prove set,
same-operation replay, list recovery, first-chance pause metadata, exact remove,
changed-argument conflict, foreign-record refusal, and clean shutdown. A real
Flare-On smoke proves set/list/remove without resuming challenge logic.

## Consequences

Agents gain a precise exception stop policy without a debugger command or
script surface. The MVP intentionally omits exception names, wildcard codes,
process enumeration, arbitrary exception conditions, logging, commands on hit,
and delete-all behavior.

The live x64dbg callback shape required one refinement: an exception breakpoint
arrives as `CB_BREAKPOINT` with its code in the breakpoint address field. The
runtime therefore retains only the immediately preceding
`EXCEPTION_DEBUG_EVENT` metadata and consumes it when code, process, and thread
match that exception-breakpoint callback. It does not infer first chance from
the configured policy. Isolated instances
`f8edad8c-0cae-4c3b-a24e-42c8e4160a87` (x64) and
`96baf49c-d4ea-4f1a-8e23-00476f796968` (x32) proved the correlation and exact
managed lifecycle.
