# ADR 0037: Typed DLL launch through x64dbg's fixed loader

Status: Implemented and qualified in 0.16.0 on 2026-08-31.

## Context

x64dbg's Open/`init` workflow accepts either an executable or a DLL. For a DLL,
the debugger does not invoke `rundll32` and does not call a requested export. It
copies its architecture-matched `loaddll.exe` to a temporary
`DLLLoader32_<id>.exe` or `DLLLoader64_<id>.exe`, starts that helper, creates a
PID-named shared mapping containing the target path, and lets the helper call
`LoadLibraryW`. When the target module arrives, x64dbg installs its configured
single-shot DLL entry breakpoint before `DllMain` executes.

The current `debuggee.launch` implementation forwards any regular file to
`init` and then rewrites the created process command line through `SetCmdline`.
That behavior is correct for an executable but misleading for a DLL: argv
belongs to the temporary loader and is not an argument contract for `DllMain`
or an export. It also does not identify the helper/target distinction.

The audited upstream behavior is documented by x64dbg's File/Open and
InitDebug documentation and by `InitDLLDebugW` plus `loaddll.cpp` in the
official source:

- <https://help.x64dbg.com/en/latest/gui/menus/File.html>
- <https://help.x64dbg.com/en/latest/commands/debug-control/InitDebug.html>
- <https://github.com/x64dbg/x64dbg/blob/development/src/dbg/debugger.cpp>
- <https://github.com/x64dbg/x64dbg/blob/development/src/loaddll/loaddll.cpp>

## Decision

Add a separate mutation:

```text
debuggee.launch_dll(path, working_directory?, instance_id, operation_id)
```

The tool accepts one canonical existing absolute DLL path and an optional
canonical existing working directory. It accepts no argv, export name,
ordinal, calling convention, environment, host executable, or raw command.
Calling an export is application-specific execution and remains outside this
tool. `debuggee.launch` is tightened to require an executable PE rather than a
DLL, so the public contracts cannot silently select different launch semantics.

Before submitting a mutation, the plugin reads only bounded PE headers and
requires a valid DOS/NT signature, the DLL characteristic, an optional-header
magic consistent with the backend, and the matching `I386` or `AMD64` machine.
The executable launch path rejects the DLL characteristic. Architecture or
kind mismatch is non-retryable `INVALID_ARGUMENT` and does not cross the
debugger command queue.

The canonical DLL path must occupy fewer than 512 UTF-16 code units. This
matches x64dbg's fixed `WCHAR[512]` loader mapping and rejects an overlong path
before `init` can mutate debugger state.

The DLL tool verifies that the matching x64dbg-distributed `loaddll.exe` exists,
builds the same fixed path-only `scriptcmd init` form used for executable
launch, and waits for the first callback-confirmed non-process-created pause.
It deliberately does not call `SetCmdline`: the shared mapping, not argv, is
the loader's target-path channel.

Successful completion is the initial paused loader process, before the backend
has issued any resume. The result identifies `target_kind: "dll"`, the
canonical target and working directory, the observed generated loader module,
`target_loaded: false`, and the state generation. The target DLL is not claimed
loaded at this point. To reach its entry, a caller separately authorizes
`debugger.resume`, retains that generation, waits with
`debugger.wait_for_pause`, and verifies the target module plus pause IP. An
intervening exception or user breakpoint is observed normally and is never
auto-resumed.

The helper is an x64dbg-owned implementation detail. x64dbg first attempts to
copy it beside the target DLL and falls back to its user directory; x64dbg
deletes the generated helper during debugger teardown. The backend neither
deletes that file itself nor claims ownership beyond reporting the observed
loader module. Failure after accepted `init` remains outcome-unknown and is not
blindly retried.

## Verification

A pure native PE policy suite covers truncated/overflowing headers, bad
signatures, executable-versus-DLL classification, optional-header mismatch,
I386/AMD64 mismatch, and both architecture successes. A deterministic DLL
fixture exports a marker and has a nonzero `DllMain` entry.

Fresh isolated x32dbg and x64dbg workflows must launch their matching fixture,
confirm the initial generated loader pause and absent target module, explicitly
resume once, observe the x64dbg-owned target entry breakpoint before fixture
logic, confirm the target module/RVA, stop, and prove the helper, sidecar, and
listener are gone. Contract, operation replay/conflict, malformed input,
shutdown, package, and installed-sample regressions remain mandatory.

## Consequences

DLL startup becomes explicit without pretending that `DllMain` has argv or
that every DLL exposes a safe callable export. The first tool result is a
loader pause rather than a loaded-module claim, so the mutation never hides
execution behind automatic resumes. Reaching DLL entry costs one normal,
observable resume/wait cycle and retains x64dbg's own TLS/entry/event policy.
