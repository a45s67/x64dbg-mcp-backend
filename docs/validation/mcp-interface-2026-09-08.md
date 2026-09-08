# MCP Interface Validation: 2026-09-08

## Scope and Decisions

The 64 shipped tool names and existing argument names are preserved.

- Corrected the closed `symbols.resolve` alternatives and fully typed exception register override items.
- Added real Draft 2020-12 JSON Schema validation tests against runtime argument validation.
- Limited address inputs to 64-bit hexadecimal values; the native debugger still checks architecture-specific constraints.
- Aligned path limits with the MCP boundary's 8192 UTF-8 bytes, rejected zero thread IDs, corrected instruction character constraints, and advertised string-context dependencies.
- JSON Schema character counts cannot express UTF-8 byte budgets or comparisons between arbitrary input values. Those limits, unique override register names, search mask equality, and patch-byte relationships remain explicit runtime constraints with tests.
- Added descriptions for operation/instance identity, retry handling, opaque cursors, thread selection, defaults, and byte units.
- Added output schemas for 18 core tools, preserving native result shapes, completion/completeness guarantees, and tool-error envelopes. Unmodeled fields remain open; other tools do not claim output contracts.
- Added bounded state, snapshot, memory, execution, search, and error text summaries. Truncated previews identify that full data remains in `structuredContent`.
- Fixed an existing native ordering bug: rejected exception continuations now validate state/disposition before applying register overrides. Register writes and resume submission are not a rollback-capable transaction.

Naming audit decisions:

- Keep `memory.read.length` and explicit `memory.search.scope.length`; these describe transfer/span lengths. Keep breakpoint `size` for widths/ranges. Both use bytes and are already consumed by native parsing and test clients. A rename offers no demonstrated interoperability benefit.
- Keep `expression.evaluate` and `expressions.evaluate_batch`; the names distinguish a single expression and a batch without a client migration.
- Keep `scyllahide.profile` with action-scoped mutation handling. Splitting get/set would improve static annotations but expand the public API without a demonstrated client need.
- No compatibility aliases were added.

## Automated and Real-Debugger Tests

| Check | Final result |
| --- | --- |
| Rust workspace tests | 102 passed, none failed or skipped |
| Rust format and Clippy with warnings denied | Passed |
| x86 native CTest | 17 passed |
| x64 native CTest | 17 passed |
| Real integration, x32 and x64 | Both passed |
| Attach integration, x32 and x64 | Both passed |
| Host-control integration, x32 and x64 | Both passed |
| Package artifact selector | 6 successful selections and 5 fail-closed cases passed |
| Installer contracts | Passed |
| Six-file package layout and PE verification | Passed |

Rust breakdown: 80 library, 8 output-contract, 7 input-contract, and 7 supervised-shutdown tests. Integration entries are suite counts, not individual assertion counts.

The exception regression exercised `handled` and `not_handled` from a nonexception breakpoint on both architectures. All four calls returned `INVALID_DEBUGGER_STATE` without changing the observed thread register map. A separate second-chance exception regression was not added.

Builds used Rust 1.98.0 via the installed stable toolchain, with `CARGO_TARGET_DIR=Z:\build-cache\x64dbg-mcp-backend`. Workspace `build` is a junction to `Z:\build-cache\x64dbg-mcp-backend\native-validation-20260908`. Packaging now obtains the executable from Cargo compiler-artifact messages, including configured target directories/triples, instead of copying a potentially stale `target\release` binary.

Machine-local detailed evidence (not release-package contents):

- `build/validation-report/run-20260908-025311/REPORT.md`
- `build/validation-report/run-20260908-025311/summary.json`
- `build/validation-report/sample-checksum-20260908-summary.md`

## Package and Installation

Version remains `0.1.2`; this is a locally validated build, not a published release.

- Package: `build/package-validation-20260908/x64dbg-mcp-backend-0.1.2.zip`
- ZIP SHA-256: `3e914a86e65ac83435f00031cb9a9678fa69bb7004b4ea2c18cbbfcd5224abee`
- Installed root: `C:\tools\x64dbg`
- Backup: `build/install-backup-20260908`, restricted to the current user and SYSTEM because it includes configuration credentials.

Installed server, controller, and both plugins match packaged hashes. Existing ports and tokens were preserved without logging credentials. Other installed plugins, including ScyllaHide and the unrelated MCP plugin, were not removed or disabled.

## Sample Validation

One sample was selected from the authorized FLARE-On 11 directory; two smoke suites passed.

- Archive: `C:\tmp\Flare-On11_Challenges\checksum.7z`
- Archive SHA-256: `1d36ce633a71a5de97a6ef88e3ef29ac1ad5a43733ece7ccac2a797a8fcaa0c8`
- Sample: `build/samples-validation-20260908/checksum.exe`, PE32+ x64, 2,490,368 bytes.
- Sample SHA-256: `9a08155ddcd2b88164a9661fa19c491e6e4f6331d8b17851497eaaca7d765580`

The isolated suite verified launch, state/snapshot consistency, modules, sections, imports, MZ/ASCII memory search, events, and stop. The installed suite additionally exercised five breakpoint kinds, breakpoint transitions/hits, thread reads, assembly/patch restoration, register restoration, discovery/analysis, replay, run-to-address, an eight-step trace with nine points, and step-into.

Known-only symbol search returned no matches and exact resolution returned `missing`; this was not counted as proof of symbol discovery. The archive and sample remained hash-identical afterward. Endpoint process/parent ownership was verified, and all owned test processes/listeners were gone at completion. No challenge solution was attempted. The installed third-party plugin opened its own listener on `0.0.0.0:9094` while the test debugger ran; that listener closed on exit and is not this backend's loopback-only MCP endpoint.

## Limitations and Follow-up

An earlier real-integration run expected trace `timed_out/timeout` but observed `interrupted/user_pause` with zero steps. An unchanged rerun passed. No assertion was relaxed, and the root cause remains unconfirmed; see `TODO.md`.

Other early failures were test-harness assumptions: junction versus physical paths, retry-safe `BUSY` snapshots during attach, which fixture thread a timeout pause selected, and the installed server filename used in the ownership check. Harness corrections retained the intended assertions; final complete runs passed.

This validation does not establish exhaustive output contracts for all 64 tools, successful challenge solving, a pristine-machine installation, or the absence of debugger timing races.
