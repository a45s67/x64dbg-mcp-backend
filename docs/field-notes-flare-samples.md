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

## 2026-08-30 x64 Checksum qualification

After `debugger.state` confirmed that the installed x64dbg session had no
debuggee, the GUI was closed normally and its owned sidecar exited without a
force termination. Flare-On 11 `checksum.exe` was identified as PE32+/AMD64
(`Machine = 0x8664`) with SHA-256
`9a08155ddcd2b88164a9661fa19c491e6e4f6331d8b17851497eaaca7d765580`.

Isolated x64 instance `8bf45169-6292-4339-9de3-aa6cb6262734` reached the system
breakpoint in generation 10 at `0x7ff91d9a0861`. The bounded observations
returned eight decoded instructions, the relocated sample at base `0xf80000`,
15 loaded sections, all 47 imports in the first bounded page, and six filtered
startup events. `debugger.stop` returned the absent state, x64dbg exited, and
the ephemeral MCP listener was closed. The sample's challenge logic was never
resumed.

Together with the x32 Frog run, this independently exercises the same smoke
contract on both architecture builds while retaining the backend's one-instance
ownership rule.

## 2026-08-31 bounded memory-search qualification

The 0.13.0 qualification added `memory.search` without resuming either Flare-On
sample's challenge logic. An isolated x32 Frog run (instance
`499e3269-0ce3-48de-909a-862642aa4293`) found the relocated module's `MZ`
signature at base `0x580000`, then stopped the debuggee and closed the listener.
An isolated x64 Checksum run (instance
`decd4089-e4ee-472c-90d3-19e7f95f4c87`) found `MZ` at base `0xbb0000` and one
exact `FlareOn2024` byte-pattern match before the same clean shutdown.

The architecture-matched fixture integrations separately proved exact-range
and wildcard matches, overlapping scan mechanics, unreadable-memory accounting,
filter-bound cursors, and stale-generation rejection. The deployed 0.13.0 x64
package then passed the full installed Checksum qualification as instance
`5e3d7fdc-eb16-471b-a6b2-753f47903013`: it reached the owned main breakpoint at
`0x6678a0`, completed the existing typed read/mutation and replay checks,
restored modified state, stopped the debuggee, and let the debugger-owned
sidecar exit.
