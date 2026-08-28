# ADR 0008: Versioned Codex workflow skill

## Status

Accepted before implementation on 2026-08-29.

## Context

The MCP server exposes bounded debugger primitives, but tool schemas alone do not teach a client
the non-obvious operating invariants: select the debugger matching the PE architecture, let the
plugin own the sidecar, use module/RVA references across ASLR, treat mutations as non-retryable,
and pair resume with callback-backed pause observation. The checksum field test also showed that
empty symbol/function/xref databases mean only "not currently known" and that useful triage needs
a compact sequence of reads rather than a large unfiltered memory map.

Embedding all workflow policy in tool descriptions would bloat every MCP session and couple
client guidance to the executable. A skill containing credentials or machine-specific paths would
be unsafe and non-portable.

## Decision

Ship an independently versioned `x64dbg-debugging` Codex skill in the release package. Its
frontmatter records skill version `0.1.0`, minimum backend version `0.1.0`, and MCP protocol
`2025-06-18`. The concise entrypoint carries only shared state, address, and mutation invariants.
Detailed recipes and troubleshooting are separate references loaded only when relevant.

The skill names backend-local dotted tools. Direct Codex registrations select the `x64dbg` or
`x32dbg` MCP server; a Dynamic Analysis Gateway may add its own namespace without changing the
backend-local suffix. The skill never contains bearer tokens, ports, user paths, target-specific
addresses, or authorization to launch or mutate a target.

`register-codex.ps1` installs the packaged skill into
`<CodexHome>/skills/x64dbg-debugging` together with the two MCP registrations. A package marker
identifies ownership. Registration refuses to overwrite an existing same-named directory that
lacks that marker, preserving user-authored skills. Re-registration updates only the managed
copy, does not print credentials, and remains idempotent. `install.ps1` remains debugger-only, so
Gateway deployments do not modify Codex state.

## Skill behavior

- Inspect `debugger.state` before choosing a workflow and do not treat connection refusal as a
  reason to start a detached sidecar.
- Prefer `{module, rva}` address references and use `address.resolve` only when the runtime
  absolute location itself is needed.
- Generate a new canonical lowercase UUID for each intended mutation. Preserve it after an
  ambiguous outcome; never use a new ID to blindly repeat the mutation.
- Use `debugger.resume` -> `debugger.wait_for_pause(after_generation=...)`, validate pause reason
  and IP, then collect bounded generation-consistent reads.
- Treat discovery output as `known_only`; empty results do not prove absence and do not authorize
  implicit analysis.

## Rejected alternatives

- **Put recipes in every tool description.** Increases context cost and duplicates policy.
- **Install the skill from `install.ps1`.** Surprises Gateway-only users and mixes debugger and
  client state again.
- **Overwrite any same-named skill.** Could destroy user-maintained instructions.
- **Store tokens in the skill.** Leaks credentials into ordinary instruction context and source
  packages.
- **Create a single compound mutation tool.** Weakens explicit authority and no-blind-retry
  semantics.

## Verification

- Run the skill creator's structural validator.
- Contract-test new, repeated, and unmanaged-conflict Codex registrations in an isolated temp
  home, including proof that no token enters skill files or command output.
- Verify the packaged skill checksums and installed file equality.
- Use the installed skill guidance with the deployed backend on a Flare-On sample, exercising a
  module/RVA breakpoint, callback wait, generation-consistent reads, bounded discovery, and clean
  shutdown without blind mutation retry.
