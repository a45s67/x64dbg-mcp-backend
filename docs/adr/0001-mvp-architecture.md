# ADR 0001: MVP architecture and technology baseline

- Status: Accepted
- Date: 2026-08-28
- Scope: First independently usable x64dbg/x32dbg Streamable HTTP MCP backend

## Context

The backend must run with both x64dbg and x32dbg, safely marshal debugger work,
survive bounded concurrent MCP traffic, and unload without leaving code executing
from an unloaded plugin DLL. It must work either directly with an MCP client or
behind the Dynamic Analysis Gateway. The Gateway, not this backend, adds a dotted
namespace prefix.

## Decisions

### 1. Use a sidecar, not an HTTP server embedded in the plugin

Each debugger process loads a thin native plugin (`.dp64` or `.dp32`). One owned
sidecar process serves one plugin/debugger instance. The sidecar is the MCP server;
the plugin is a private debugger adapter reached through a local named pipe.

Reasons:

- HTTP parsing, authentication, request cancellation, and connection concurrency
  stay outside the debugger address space.
- Plugin unload has a small, auditable surface: stop accepting IPC work, cancel or
  drain queued work, join owned plugin threads, close the pipe, then return.
- A stuck or malformed HTTP client cannot directly retain plugin DLL code.
- The server is independently usable: any Streamable HTTP MCP client can connect
  to its `/mcp` URL; the Gateway is optional.
- The same sidecar binary serves x32dbg and x64dbg; only the adapter DLL differs.

Costs accepted: two artifacts, a versioned IPC protocol, process supervision, and
careful authentication of the local pipe. An embedded server can be reconsidered
only if measured deployment friction outweighs these safety properties.

### 2. Use Rust for the sidecar and C++20 for the plugin

- Sidecar: stable Rust, Tokio, an async HTTP stack, Serde, and the official/current
  Rust MCP SDK if it passes contract tests. Pin all dependency versions and commit
  `Cargo.lock`. Avoid an SDK abstraction where it prevents protocol compliance.
- Plugin: C++20, CMake, MSVC, and the matching x64dbg plugin SDK. Build Win32 and
  x64 from the same sources. Use only the Windows API and x64dbg SDK at the plugin
  boundary; do not embed a language runtime.
- CI/build: CMake presets plus Cargo. Produce reproducible Release artifacts for
  both architectures. Warnings are errors in project code.

The accepted Windows toolchain baseline is MSVC ABI throughout:

- Plugin: the pinned Visual Studio 2026 MSVC compiler/linker, initially verified
  with compiler version 19.51.36256, built for Win32 and x64.
- Sidecar: stable Rust target `x86_64-pc-windows-msvc`; the initial pinned
  environment is Rust/Cargo 1.98.0.
- Host prerequisites: Visual Studio 2026 Build Tools only, with the current MSVC
  x86/x64 tools and a Windows 10/11 SDK. The Visual Studio IDE, ATL, MFC, C++/CLI,
  and legacy toolsets are not required. The initial environment provides CMake
  4.3.1-msvc1 and Ninja 1.13.2.
- CMake and Ninja drive native builds; Cargo drives the sidecar. Zig/MinGW and
  clang-cl are not release toolchains for the MVP, though clang-cl MAY later be
  added as an additional CI diagnostic compiler.
- The initial x64dbg SDK/integration baseline is release `2026.05.27`, commit
  `9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87`, installed outside the repository at
  `C:\tools\x64dbg`. Builds consume `pluginsdk`; integration tests consume
  `release\x32` and `release\x64`. The path is configurable and is not embedded in
  release artifacts.

Rust is selected for the network-facing concurrent component. C++ is required at
the ABI boundary and keeps the adapter small enough to audit.

### 3. Implement a deliberately small Streamable HTTP profile

The MVP implements protocol revision `2025-06-18`, JSON-RPC 2.0, tools, and the MCP
lifecycle. `POST /mcp` is supported. `GET /mcp` returns 405 because unsolicited SSE
and resumability are not required for the initial tool set. `DELETE /mcp` is only
implemented if sessions are enabled; the initial preference is stateless transport.
Batch JSON-RPC is rejected. The exact behavior is frozen by contract tests.

### 4. Make every operation explicit about state and mutation

Each tool is classified as read-only or mutating and declares valid debugger
states. Mutation requests carry a caller-generated `operation_id`. The backend
deduplicates completed and in-flight mutation IDs for a bounded lifetime and never
blindly retries a mutation after an ambiguous IPC failure. Reads may be retried by
the caller, not secretly by the backend.

### 5. Own and join every thread and process

No detached threads are allowed. The sidecar owns its listener, tasks, cancellation
tokens, and child-process relationship. The plugin owns its IPC reader and debugger
executor coordination. All have explicit stop signals and bounded joins. Failure
to drain within the shutdown deadline fails closed and is observable; plugin code
must never return from `plugstop` while an owned thread can execute it.

## Consequences

The IPC protocol is a first-class compatibility boundary and needs its own tests.
The plugin cannot be a passive collection of SDK calls: it must maintain a state
snapshot from callbacks and a serialized debugger-operation queue. Packaging must
install the sidecar beside both plugins and provide per-instance configuration.

## Deferred decisions

- Exact Rust MCP SDK and HTTP crate, after a dependency/security spike.
- SSE, resumability, resources, prompts, remote binding, and multiple debugger
  instances per backend type are post-MVP.

## Accepted follow-up: sidecar supervision

- Date: 2026-08-28
- The plugin launches the sidecar automatically after plugin initialization; it
  MUST NOT launch a process from `DllMain` or block the debugger UI while waiting.
- The sidecar executable is resolved from configured/installed paths, never an
  untrusted `PATH` lookup. A per-backend single-instance lock prevents duplicates.
- Normal unload uses the graceful drain protocol. A Windows Job Object provides
  crash cleanup as a last resort, not as the normal shutdown mechanism.
- Manual sidecar launch remains a supported diagnostic mode, not the default user
  workflow.
