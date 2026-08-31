# ADR 0040: Manual Codex registration from installer output

Status: Accepted for implementation on 2026-08-31.

## Context

The backend installer and `register-codex.ps1` currently form two separate
steps. The second script parses installed configuration, edits the user's
Codex `config.toml`, and copies the packaged workflow skill. Although tested and
idempotent, this expands the release surface with a stateful editor for a file
owned by another product. A user who prefers an explicit configuration change
must still inspect that mutation afterward.

A Codex skill is not downloaded from an MCP endpoint. Codex discovers a local
skill directory when a session starts, while MCP transport configuration lives
separately in `~/.codex/config.toml`. The packaged skill contains referenced
files in addition to `SKILL.md`, so downloading only one file from a GitHub web
URL would be incomplete and could drift from the installed backend version.

## Decision

Remove `register-codex.ps1` and its stateful configuration-editing contract.
After a successful backend install, `install.ps1` prints:

- the exact `notepad.exe "$HOME\.codex\config.toml"` command;
- complete `[mcp_servers.x64dbg]` and `[mcp_servers.x32dbg]` TOML tables using
  the effective installed ports and shared static Authorization header;
- bounded PowerShell commands that create
  `$HOME\.codex\skills\x64dbg-debugging` and copy the complete version-matched
  packaged skill directory into it; and
- an instruction to restart Codex.

The output labels the bearer token as a secret because the exact usable header
necessarily exposes it in the local terminal transcript. The installer still
does not modify Codex configuration, environment variables, or skill storage.
Users must not paste the output into an issue, chat, or build log.

The documented table names remain `mcp_servers.x64dbg` and
`mcp_servers.x32dbg`; aliases such as `x64dbg-mcp` are not invented. The config
filename is `config.toml`, not `config`. The skill installation uses the
verified extracted package as its source and does not depend on GitHub, `curl`,
the network, a branch head, or a single-file skill approximation.

Gateway deployments may ignore the Codex instructions and continue to use the
same installed endpoint and secret through the Gateway's own secret facility.

## Verification

Installer contract tests must prove that output contains both exact endpoint
tables, matching installed Authorization values, the correct Codex config path,
the full packaged-skill copy commands, and the restart warning. Reinstall,
custom-port, partial-repair, token-rotation, and `-WhatIf` behavior remain
covered. Package tests must prove the removed helper is absent, the complete
skill is present, and the offline verifier accepts only the new required
layout.

## Consequences

Installation becomes easier to audit and no longer edits unrelated Codex state.
It is intentionally less automatic: the user owns the final paste and skill
copy, duplicate-table cleanup, and Codex restart. Existing installations keep
working; removing the helper does not remove already-written Codex entries or
skills. A future Codex plugin may replace these manual steps only when it can
handle per-machine ports and generated bearer credentials without committing or
exporting secrets.
