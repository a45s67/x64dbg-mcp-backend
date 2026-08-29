# Field notes: architecture-matched Flare-On samples

These notes supplement the deeper `checksum.exe` record with a small,
repeatable initial-pause smoke test. Samples are treated as untrusted: the
runner validates the PE machine, launches only in an isolated debugger tree,
does not resume into sample code, bounds every read, and sends exactly one stop
mutation without retry.

## 2026-08-30 x32 Frog qualification

Flare-On 11 `frog.exe` was identified as PE32/i386 (`Machine = 0x014c`) with
SHA-256
`56540de243f437d9a5012b5ccdfcd5521755d60b68e9465d0d674461a6ff3561`.
Isolated x32 instance `22443af1-7774-43f2-9892-b13539b1907b` reached the
system breakpoint in generation 23 at `0x77001b53`. The bounded observations
returned eight decoded instructions, the relocated sample at base `0xd50000`,
five loaded sections, one 64-item import page, and 16 filtered startup events.
`debugger.stop` returned the absent state, x32dbg exited, and the ephemeral MCP
listener was closed. The sample's challenge logic was never resumed.

The same runner rejected the x86 sample for the x64 backend before starting a
debugger: `Sample machine 0x014c does not match x64.` It also now rejects an
isolated run immediately when another debugger of that backend type is active,
instead of waiting for the single-instance sidecar lock to time out.

An installed x32 distribution on this machine was separately unable to start
before plugin initialization because its binaries retained Mark-of-the-Web and
Windows could not build the signature chain to a trusted root. This is a host
distribution trust issue, not an MCP result. The installer intentionally does
not clear alternate streams or weaken security policy; the isolated x32 test
provides backend evidence while keeping that decision explicit.

The generic x64 rerun was not forced because an existing installed x64dbg
session owned the MVP's x64 single-instance slot. The complete 0.12.0 release
gate and installed `checksum.exe` qualification already provide x64 evidence;
a new generic x64 observation should be recorded only after that session is
closed normally.
