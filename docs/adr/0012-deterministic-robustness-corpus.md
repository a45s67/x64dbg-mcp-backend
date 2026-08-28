# ADR 0012: Deterministic malformed-input robustness corpus

Status: Accepted

## Context

The backend validates HTTP sizes, JSON complexity, tool schemas, IPC frame
lengths, and native UTF-8 boundaries. Existing tests cover representative empty,
truncated, oversized, malformed, and semantically invalid values, but a small
handwritten set is unlikely to exercise combinations such as corrupted length
prefixes plus arbitrary payload bytes or deeply varied JSON shapes.

A permanent coverage-guided fuzzer is useful, but requiring cargo-fuzz, Clang
sanitizer runtimes, Python, or a downloaded corpus would make the normal Windows
build and release gate less reproducible. Random tests with an implicit seed are
also poor regression tests because failures cannot be replayed reliably.

## Decision

Add dependency-free deterministic mutation corpora to the normal Rust and native
test suites:

- use an explicitly fixed pseudo-random seed and a small documented generator;
- cap case count and every generated allocation;
- mutate both arbitrary bytes and known-valid protocol inputs;
- exercise exact IPC decoding, MCP request handling, all tool argument
  validators, JSON/response bounds, and native UTF-8 escaping/search helpers;
- require every accepted IPC value to survive canonical encode/decode round-trip;
- require every MCP result to remain bounded valid JSON with a JSON-RPC shape;
- require native JSON escaping to produce bounded valid UTF-8 for every case;
- keep the corpus entirely in-process with no sockets, debugger mutation, files,
  sleeps, or external process ownership; and
- print the seed/case index in assertions so a failure is directly reproducible.

The deterministic corpus is a release regression gate, not a claim of exhaustive
fuzzing. Coverage-guided libFuzzer/AFL runs with sanitizers remain an additional
CI/release activity when that infrastructure is available. Any crashing input
found there must be minimized and promoted into this deterministic suite.

## Bounds

- Rust arbitrary byte inputs: at most 4 KiB each.
- Rust generated JSON: bounded recursion, container count, and string length.
- Native byte strings: at most 256 bytes each.
- Default case counts are compile-time constants and complete in seconds.
- No accepted path may allocate based on an unchecked attacker length.

## Consequences

- Malformed-input regressions run under ordinary `cargo test` and both MSVC
  architecture suites without adding installation prerequisites.
- A fixed corpus explores substantially more combinations while preserving fast,
  deterministic failures.
- The tests verify safety and bounds rather than expecting every mutation to be
  rejected; a mutation that remains a valid protocol message is allowed.
- Sanitizer and coverage-guided fuzz coverage remain visible release gaps until a
  suitable CI worker is configured.

## Rejected alternatives

- **Unseeded property tests.** Non-reproducible failures are difficult to debug
  and can make the release gate flaky.
- **Shipping a Python fuzz driver.** It adds a target-machine misconception and a
  development prerequisite for logic that can run in the native test binaries.
- **Accepting malformed frames and scanning for the next prefix.** Resynchronizing
  after corruption can reinterpret attacker-controlled bytes; the IPC contract
  remains fail-closed.
- **Calling deterministic tests “complete fuzz coverage.”** They do not provide
  coverage feedback, sanitizers, or exhaustive exploration.
