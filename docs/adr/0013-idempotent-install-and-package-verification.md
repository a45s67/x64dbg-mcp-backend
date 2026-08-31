# ADR 0013: Idempotent installation and offline package verification

Status: Accepted

## Context

The release ZIP is self-contained and the installer copies the correct x32/x64
plugins and shared sidecar. It currently generates a new bearer token and writes
default ports on every invocation. That is safe for a first install, but a routine
reinstall silently invalidates existing Codex or Gateway credentials and can
discard intentionally selected ports.

Packaging generates SHA-256 checksums, an SBOM, and version metadata, but the
extracted release does not contain a one-command offline verifier. The installer
also lacks a disposable-tree contract test for first install, repair, reinstall,
explicit rotation, and failure-without-partial-writes behavior.

## Decision

### Installer semantics

- A first install generates one cryptographically random 48-byte token shared by
  the x32 and x64 configurations.
- A normal reinstall preserves an existing valid shared token.
- If exactly one backend configuration exists with a valid token, repair reuses
  that token for the missing peer.
- If both configurations contain different tokens, installation fails before
  copying anything. It never guesses which credential is authoritative.
- `-RotateToken` explicitly generates a new shared token for both backends.
- A port passed explicitly with `-X32Port` or `-X64Port` replaces that backend's
  port. An omitted port preserves a valid installed value, otherwise it uses the
  documented default.
- Validation and effective configuration are computed before `ShouldProcess` and
  before any target write. `-WhatIf` therefore has no side effects.
- Installation remains a simple file copy plus TOML write. It does not modify
  ACLs, environment variables, other plugins, or Codex configuration.

Token rotation and client configuration remain separate operations. After an
explicit rotation, clients must be refreshed intentionally using the new manual
Codex output or the Gateway's secret facility (ADR 0040).

### Offline release verification

Ship `scripts/verify-package.ps1`. It accepts an extracted package root and:

- parses `checksums.txt` using a strict lowercase SHA-256 and relative-path form;
- rejects duplicate, absolute, traversal, missing, or unlisted files;
- hashes every listed file except the checksum manifest itself;
- validates required layout, version metadata, target names, and protocol fields;
- verifies PE signatures and machine types for dp32 (x86), dp64 (x64), and the
  sidecar (x64); and
- performs no network access and writes no files.

The packaging script runs this verifier before creating the deterministic ZIP.
A dependency-free installer contract test uses a disposable fake debugger and
package tree to cover initial install, idempotent reinstall, partial-config
repair, explicit ports, explicit token rotation, mismatch failure, and `-WhatIf`.

## Consequences

- Updating binaries no longer breaks configured MCP clients by default.
- Credential divergence is explicit and recoverable with a deliberate rotation.
- A release can be verified on a clean Windows host with only built-in
  PowerShell/.NET; Rust, Python, CMake, Ninja, and Visual Studio are not required.
- Code signing is still dependent on external release identity/infrastructure;
  checksums verify integrity against the manifest but do not establish publisher
  identity.

## Rejected alternatives

- **Always rotate on reinstall.** This creates avoidable client failures and
  couples binary updates to secret distribution.
- **Silently choose one of two mismatched tokens.** Either choice can lock out an
  existing client and hides configuration drift.
- **Store the token in an environment variable.** It reintroduces startup noise,
  scope confusion, and secret lifetime outside the installed configurations.
- **Require a third-party checksum utility or Python verifier.** Built-in .NET
  cryptography and PE parsing are sufficient and keep target prerequisites small.
