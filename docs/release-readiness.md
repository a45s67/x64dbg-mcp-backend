# Release readiness

The MVP implementation meets the repository-controlled requirements. From the
repository source tree, the canonical local acceptance command is:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\run-release-gate.ps1 -X64dbgRoot C:\tools\x64dbg
```

To also qualify the currently installed backend with the local Flare-On sample:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\run-release-gate.ps1 -X64dbgRoot C:\tools\x64dbg `
  -InstalledFlareSamplePath C:\Users\fish\Downloads\Flare-On11_Challenges\checksum.exe
```

For a read-only-at-initial-pause check of another architecture-matched PE in an
isolated integration tree:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\run-generic-sample-smoke.ps1 -Backend x32 `
  -IntegrationRoot artifacts\integration `
  -SamplePath C:\path\to\sample-x86.exe
```

The generic runner validates the PE machine before launch, refuses to compete
with an already-running debugger of the same backend type, never resumes the
sample, performs bounded initial-pause reads, submits one stop operation, and
requires both the isolated debugger and its listener to exit. It is diagnostic
evidence, not a substitute for the release gate.

## Evidence matrix

| Requirement | Repository evidence |
| --- | --- |
| Independent Streamable HTTP MCP server and Gateway compatibility | MCP/health contract tests and `docs/design/mvp.md` |
| Configurable loopback bind, port, and bearer token | configuration tests, installer contracts, and `docs/install.md` |
| x32dbg and x64dbg | x86/x64 native suites and isolated real-debugger integration |
| Safe debugger-thread execution | executor tests and `docs/native-api-audit.md` |
| Read-only cross-thread context | ADR 0036, x86/x64 context conversion tests, deterministic-worker dual-architecture integration, and installed paused Flare-On qualification |
| Typed conditional and exception breakpoint ownership | ADRs 0034/0035, closed-schema compiler tests, callback-correlation regression, dual-architecture live hits, and installed non-resuming Flare-On lifecycle smoke |
| Owned threads/processes and graceful unload | supervised shutdown matrix, native lifecycle tests, and finite integration soak |
| Explicit state and structured errors | MCP golden/handler tests and actionable diagnostic contracts |
| Bounded input, output, concurrency, operations, and discovery | Rust/native deterministic robustness corpus and bounded tool contracts |
| No blind mutation retry | instance-bound mutation schemas, replacement-sidecar no-dispatch test, operation-ledger tests, shutdown mutation cases, and workflow skill contracts |
| Automated unit, contract, integration, and shutdown tests | package gate plus `scripts/run-integration-soak.ps1` |
| Installable x32/x64 package | idempotent installer tests, SBOM/checksums, PE architecture validation, and offline verifier |

## Publisher gates

The following are deliberately not claimed by a local report:

- Authenticode signing requires the publisher's certificate and protected signing
  service. SHA-256 package checksums verify integrity but not publisher identity.
- A pristine supported Windows VM install requires disposable external VM
  infrastructure. The repository tests a disposable fake install tree and real
  local x32dbg/x64dbg trees, but labels those accurately.
- Coverage-guided fuzzing with sanitizers is optional CI hardening. The mandatory
  release gate uses the fixed, replayable malformed-input corpus from ADR 0012.
