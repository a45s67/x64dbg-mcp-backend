# TODO

## MCP Improvements (Priority Order)

- [x] 1. Fix input schema correctness: remove the conflicting outer `additionalProperties: false` from `symbols.resolve` while preserving closed alternatives, and define the `register_overrides` item schema for `debugger.continue_exception`.
- [x] 2. Add schema contract tests using a real JSON Schema validator. Cover valid and invalid arguments and compare schema acceptance with runtime validation.
- [x] 3. Align shared types and limits across schemas and runtime validation: address widths, UTF-8 byte limits, path limits, nonzero thread IDs, and cross-field dependencies. Constraints not expressible in standard JSON Schema remain explicitly documented and runtime-tested.
- [x] 4. Improve model-facing descriptions: explain mutation IDs and retry rules, required debugger states, opaque cursor usage, and completed versus incomplete results.
- [x] 5. Add core output contracts and useful text summaries, prioritizing `debugger.state`, `debugger.snapshot`, memory tools, execution tools, search tools, and errors. Eighteen tools now advertise conservative output schemas with error compatibility.
- [x] 6. Evaluate naming consistency and tool splitting only after the above improvements. Preserve shipped expression names and `scyllahide.profile`; no client requirement justifies a breaking rename or get/set split.

## Naming Audit

- [x] Audit `length` versus `size` naming across MCP tool inputs, including `memory.read`, `memory.search` ranges, and breakpoint sizes. Preserve `length` for read/search spans and `size` for breakpoint widths/ranges; document bytes. Existing native parsing, test clients, and public schemas use these names. No aliases were added.

## Verification

Completed on 2026-09-08: 102 Rust tests, 34 native tests, six x32/x64 real-debugger suites, packaging/installer contracts, verified installation into `C:\tools\x64dbg`, and two smoke suites using one FLARE-On checksum sample. See [the validation report](docs/validation/mcp-interface-2026-09-08.md) for scope, evidence, and limitations.

## Follow-up Found During Testing

- [ ] Investigate intermittent trace timeout classification: one integration attempt returned `interrupted/user_pause` instead of `timed_out/timeout`; an unchanged rerun passed. The assertion was not relaxed and the root cause is not yet established.
