# Release readiness

The MVP implementation meets the repository-controlled requirements. The
canonical local acceptance command is:

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

## Evidence matrix

| Requirement | Repository evidence |
| --- | --- |
| Independent Streamable HTTP MCP server and Gateway compatibility | MCP/health contract tests and `docs/design/mvp.md` |
| Configurable loopback bind, port, and bearer token | configuration tests, installer contracts, and `docs/install.md` |
| x32dbg and x64dbg | x86/x64 native suites and isolated real-debugger integration |
| Safe debugger-thread execution | executor tests and `docs/native-api-audit.md` |
| Owned threads/processes and graceful unload | supervised shutdown matrix, native lifecycle tests, and finite integration soak |
| Explicit state and structured errors | MCP golden/handler tests and actionable diagnostic contracts |
| Bounded input, output, concurrency, operations, and discovery | Rust/native deterministic robustness corpus and bounded tool contracts |
| No blind mutation retry | operation-ledger tests, shutdown mutation cases, and workflow skill contracts |
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

