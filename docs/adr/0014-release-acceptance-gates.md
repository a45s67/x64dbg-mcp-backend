# ADR 0014: Layered release acceptance gates

Status: Accepted

## Context

The automated checks are intentionally split across Rust, native C++, packaging,
and real-debugger scripts. Running only one family can produce a package that is
locally green but has not exercised the plugin/sidecar ownership boundary in both
x32dbg and x64dbg. Conversely, a public release cannot honestly claim publisher
signing or a pristine-machine install merely because local integration passed.

## Decision

Release acceptance has three explicit layers:

1. The repository package gate builds from locked inputs, runs Rust unit and MCP
   contract tests, Clippy, the supervised shutdown matrix, x86/x64 native tests,
   installer/manual-Codex-output and skill contracts, emits the SBOM/checksum manifest,
   and verifies the staged package offline.
2. The local real-debugger gate prepares isolated x32dbg and x64dbg trees that
   contain only this plugin, runs the bounded integration soak, and proves each
   owned sidecar and loopback listener disappear after its debugger exits.
3. Publisher qualification verifies signatures and performs installation plus
   launch on a pristine supported Windows VM. These checks require release
   identity and disposable VM infrastructure and must not be inferred from a
   developer-machine run.

`scripts/run-release-gate.ps1` composes layers 1 and 2 and writes a machine-readable
report. It may additionally run the installed `checksum.exe` Flare-On smoke when
the caller explicitly supplies that local sample. The sample is not redistributed
and is qualification coverage, not a package dependency.

Coverage-guided sanitizer jobs remain an additional CI hardening activity as
recorded by ADR 0012. The dependency-free deterministic corpus remains mandatory
in every package gate; any sanitizer-discovered regression must be minimized into
that permanent corpus.

## Safety and bounds

- The gate accepts only output below the repository workspace and refuses an
  existing output directory.
- Integration uses a bounded iteration count and isolated debugger copies.
- The gate never kills a process by image name and never retries mutations.
- Flare-On qualification is opt-in because it operates on the installed debugger
  tree and a locally supplied third-party sample.
- A successful local report says `publisher_qualification: "not_run"`; only the
  publisher may replace that with signed/pristine-VM evidence.

## Consequences

- A developer has one reproducible command for the complete locally available
  release evidence.
- Automation cannot accidentally present checksum validation as code signing or
  an integration copy as a clean-machine test.
- The generated report identifies the exact archive and SHA-256 digest that was
  exercised.
