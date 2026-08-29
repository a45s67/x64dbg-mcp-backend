# ADR 0028: Structured and exactly quoted launch arguments

Status: Accepted on 2026-08-30.

## Context

`debuggee.launch` deliberately omitted a raw command-line string. Agents need to
launch ordinary fixtures and analysis targets with arguments, but accepting one
opaque string would mix caller intent, Windows `argv` serialization, and x64dbg
command syntax. It would also make operation replay identity ambiguous and could
turn quoting mistakes into additional debugger commands.

The pinned x64dbg command buffer is `deflen` (1,024 bytes). x64dbg's nested
`init` command-string escaping does not preserve every already-quoted Windows
argument: real integration showed an embedded quote collapsing that and later
arguments into one `argv` entry. The SDK's `SetCmdline` function can instead
commit a complete command line while the newly created process is still at its
initial actionable pause.

## Decision

Extend the existing mutation with one optional field:

```text
debuggee.launch(path, working_directory?, arguments?, instance_id, operation_id)
```

`arguments` is an array of zero to 32 UTF-8 strings. Each element is at most 256
UTF-8 bytes and the aggregate caller text is at most 512 bytes. JSON parsing must
produce valid Unicode. NUL, C0/C1 control characters, and DEL are rejected; empty
strings, whitespace, commas, quotes, backslashes, and non-ASCII text are valid.
The field is optional for compatibility and omission is identical to an empty
array.

The native adapter performs two separate steps:

1. `QuoteWindowsArgument` serializes every array element as one always-quoted
   Windows argument. Runs of backslashes before a quote are doubled plus one;
   terminal backslashes are doubled before the closing quote. Arguments are
   joined by one ASCII space.
2. It launches the executable with an empty argument field through the fixed
   `scriptcmd init` template, waits for an actionable initial pause, and calls
   `DbgFunctions()->SetCmdline` with the quoted executable plus rendered array.
   This occurs before any backend-issued resume and therefore before user code.

The implementation converts the complete process command line to UTF-16 and rejects a
Windows command line above 32,766 code units. It separately rejects a rendered
UTF-8 argument string above 768 bytes or the fixed path-only launch command if it
would not fit, including its terminator, in `deflen`. Paths retain ADR 0002
canonicalization and x64dbg command escaping. No shell,
environment expansion, response file, script, or arbitrary debugger command is
invoked.

The result echoes the canonical `arguments` array. The complete array remains in
the existing operation-ledger request fingerprint, so replaying the same
operation ID with different arguments is `OPERATION_ID_CONFLICT`; an ambiguous
accepted launch is never submitted again.

## Entry-break policy

This stage does not add an entry-break option. Current x32/x64 callback behavior
proves an actionable pause but does not independently distinguish every loader,
TLS, system, and executable-entry policy in a closed enum. That proposal remains
unadmitted rather than being approximated with fixed resumes or sleeps.

## Verification

A pure native policy suite covers empty values, whitespace, commas, embedded
quotes, runs of backslashes, terminal backslashes, Unicode, aggregate limits,
x64dbg escaping, and the 1,024-byte final command boundary. Sidecar contract
tests cover the JSON bounds and unknown fields.

The x32 and x64 integration fixture records the actual wide process command line
through `CommandLineToArgvW`. Tests compare every observed `argv[1..]` byte-for-
byte with the requested array, including empty, quoted, trailing-backslash, comma,
space, and non-ASCII values. Existing callback, replay, shutdown, and Flare-On
launch tests remain required.

## Consequences

Launch arguments become convenient without exposing raw command syntax. A
failure after process creation but before `SetCmdline` confirmation is reported
as outcome-unknown and the operation ledger forbids automatic resubmission.
The debugger's 1,024-byte command limit applies only to canonical paths; the
separately bounded argument array is not nested in that command string.
