# ADR 0021: Bounded native mutation fuzzing and AddressSanitizer gate

Status: Accepted before implementation on 2026-08-29.

## Context

The release gate already runs fixed malformed-input corpora, Rust contract tests,
and native x32/x64 policy and lifecycle tests. Those tests are reproducible, but
they do not continuously mutate the native IPC request parser and they run normal
MSVC binaries without runtime memory instrumentation.

The current workstation has the MSVC x86/x64 compiler but not the optional MSVC
AddressSanitizer component. It also has neither clang/libFuzzer nor cargo-fuzz.
Making either coverage-guided fuzzer a release or target-machine dependency would
conflict with the offline, independently installable package contract.

## Decision

Add a separate developer-only native robustness gate with two layers:

1. A dependency-free deterministic mutation harness directly exercises the
   native IPC request parser and pure patch policy. It mutates known-valid wire
   messages and arbitrary bounded byte strings with an explicit seed.
2. The same harness and native policy tests are built for x32 and x64 with MSVC
   `/fsanitize=address`, then executed with fail-fast AddressSanitizer settings.

The harness is fuzzing because it systematically generates and mutates many
inputs beyond handwritten examples. It is not coverage-guided fuzzing, and its
reports must not claim libFuzzer/AFL-style coverage discovery. A future worker
with clang/libFuzzer or cargo-fuzz may add that additional layer without changing
this decision.

### Isolation boundary

- Fuzz targets run in ordinary console test processes. They never load an
  instrumented plugin into x64dbg, attach, launch a debuggee, open an MCP port,
  or submit a debugger mutation.
- The request target uses the lifecycle-harness compilation boundary, where the
  JSON parser is real but debugger-native execution is excluded.
- The released `.dp32`, `.dp64`, and server executable remain the normal MSVC
  Release artifacts. Sanitizer runtimes are not packaged.
- Third-party x64dbg and Jansson binaries are not claimed to be instrumented.

### Bounds and replay

- Default native fuzzing uses a fixed documented 64-bit seed and 50,000 cases
  per architecture.
- Each request input is at most 64 KiB; policy byte/text inputs are at most 256
  bytes and prepared patch spans remain at most 32 bytes so rejection paths are
  exercised without unbounded allocation.
- CLI overrides for seed and case count are validated and capped. Failures print
  architecture, target, seed, and case index.
- No input is read from the network or an untrusted corpus directory.
- Every discovered crashing input must be minimized and promoted to a normal
  regression test before the issue is closed.

### Gate behavior

- A dedicated script locates Visual Studio Build Tools, validates that the ASan
  runtime is installed, creates isolated x86 and x64 build directories, builds
  only the native robustness targets, and runs them with bounded CTest timeouts.
- A missing sanitizer component is a clear prerequisite error, not a silently
  skipped success.
- The ordinary release/package gate remains dependency-free and continues to run
  the deterministic non-sanitized tests.

## Rejected alternatives

- **Instrument and load the production plugin into x64dbg.** Mixing an ASan
  plugin with a large uninstrumented debugger process complicates ownership and
  can destabilize the user's debugger rather than isolate a backend defect.
- **Install Python and ship a random network driver.** It adds an unrelated
  prerequisite, reduces replay quality, and needlessly opens real transports.
- **Require nightly Rust or download cargo-fuzz dependencies in packaging.** It
  breaks the offline locked release gate and tests developer infrastructure
  rather than the shipped package.
- **Call the fixed generator coverage-guided.** It has no coverage feedback and
  is reported accurately as deterministic mutation fuzzing.
- **Unbounded random lengths or run time.** They can turn robustness testing into
  a denial of service and make CI completion unpredictable.

## Verification

- Normal x32/x64 native tests include the deterministic harness and retain their
  existing lifecycle/shutdown coverage.
- Sanitized x32/x64 runs complete the configured corpus with no ASan report,
  crash, hang, debugger process, sidecar process, or listening port.
- The normal Rust, package, install, and isolated debugger gates remain green,
  proving the optional developer configuration did not alter release artifacts.
