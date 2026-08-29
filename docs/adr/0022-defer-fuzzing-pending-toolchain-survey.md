# ADR 0022: Defer fuzzing and sanitizer integration pending toolchain survey

Status: Accepted on 2026-08-29.

## Context

ADR 0021 proposed a deterministic native mutation harness plus MSVC
AddressSanitizer. A local prototype proved that the parser seam could be tested
for x86 and x64, but it also exposed a material toolchain constraint: current
MSVC AddressSanitizer executables depend on an architecture-specific runtime DLL
even when the project uses `/MT`. Headless execution therefore needs deliberate
runtime provisioning and Windows error-dialog suppression.

More importantly, the proposed generator was not coverage-guided. Adding and
maintaining a second fixed corpus would overlap ADR 0012 without establishing
that it finds meaningfully different defects. Choosing it only because it has no
new dependency would prematurely lock in a weaker long-term design.

## Decision

Do not merge a new fuzz target, sanitizer build option, or sanitizer runner in
this stage. Keep fuzzing and sanitizers as explicit future quality work. The
existing fixed, replayable Rust and native malformed-input corpora from ADR 0012
remain part of the normal release gate and continue to be described accurately;
they are not coverage-guided fuzzing.

Before implementation, survey at least these candidate boundaries and tools:

- clang-cl plus libFuzzer and ASan for the native IPC parser and pure policies;
- MSVC's experimental `/fsanitize=fuzzer` support and its x86/x64 runtime model;
- Rust `cargo-fuzz` for sidecar HTTP, MCP, and IPC decoding boundaries;
- corpus interchange and minimized regression promotion across native and Rust
  targets.

The survey must compare coverage feedback, x86 and x64 support, reproducibility,
offline/locked operation after bootstrap, CI suitability, crash-dialog behavior,
symbolization, runtime provisioning, maintenance cost, and whether the target
tests the shipped parsing boundary rather than a duplicate implementation.

Any future proposal must keep sanitizer/fuzzer dependencies out of release
artifacts and target-machine installation. It must define bounded local and CI
budgets, persist exact seeds and crashing inputs, minimize findings into ordinary
regression tests, and never load an instrumented plugin into the user's normal
x64dbg installation.

## Consequences

- Product code, plugin ABI, package contents, and normal prerequisites remain
  unchanged.
- The optional Visual Studio ASan component may exist on a developer machine but
  is not a repository or deployment prerequisite.
- ADR 0021 remains as design history but is superseded before its prototype is
  merged.
- Publisher signing and pristine-VM qualification remain separately deferred
  and are not coupled to this future survey.
