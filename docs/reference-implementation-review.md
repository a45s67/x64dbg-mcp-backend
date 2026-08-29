# Focused x64dbg MCP reference review

Reviewed on 2026-08-29 from the local, pinned survey copies. This is a design
comparison, not a source template. No implementation is copied wholesale.

## Selected implementations

| Implementation | Tool shape | Useful ideas | Constraints we do not adopt |
|---|---|---|---|
| `x64dbg-mcp-server` (Zig) | About 80 fine-grained tools in one embedded plugin | Clear agent-oriented descriptions; step responses include immediate context; many practical reverse-engineering operations | Fixed sleeps stand in for completion; register/assembly inputs are interpolated into commands; broad expression/command surfaces; mutations lack operation IDs and replay semantics; mostly text results |
| `x64dbg-mcp` (layered C++) | Fine-grained MCP tools mapped through handlers, managers, permissions, and a native bridge | Hardware breakpoint type/size/alignment validation; architecture-specific schemas; typed assembler preview; post-mutation breakpoint matching; separated business layers | Some run-state commands use direct execution or polling/sleeps; attach can implicitly detach/stop first; schemas and outputs are not consistently hard-bounded; mutation deduplication is absent |
| `x64dbg_mcp` (TypeScript sidecar plus C++ HTTP plugin) | Roughly 23 action-based tools, each containing a discriminated action union | Smaller top-level catalog; related actions are easy to browse together; Zod gives readable enums | Read, mutate, and destructive actions share one MCP tool annotation; large unions move complexity inside each tool; batch configuration permits partial success; strings/arrays often lack hard maxima; tool names hard-code x64dbg |

## Decisions for this backend

1. Keep backend-local, verb-specific tools. The Gateway may add its dotted
   namespace. Do not add `x64dbg_` prefixes and do not collapse unrelated
   read/mutate/destructive actions into a mega-tool.
2. Keep the catalog curated rather than maximizing tool count. Add a tool only
   when it has a bounded contract, an explicit state precondition, native API
   ownership, a completion postcondition, and automated dual-architecture tests.
3. Make descriptions workflow-aware: state prerequisites, whether the operation
   mutates, completion semantics, and no-blind-retry behavior belong in the
   description. Larger recipes remain in the versioned skill instead of an
   always-injected server prompt.
4. Use JSON Schema enums, exact field sets, architecture/width validation, and
   structured module/RVA addresses. Never accept an arbitrary debugger command
   merely because another implementation exposes one.
5. Preserve one mutation per operation ID. Avoid batch mutations where partial
   success cannot be made atomic or safely rolled back.
6. Return structured, generation-correlated context after control-flow
   mutations. Do not use fixed sleeps as completion evidence.
7. For typed hardware/memory breakpoints, adopt explicit condition, size,
   alignment, architecture, and read-back matching rules. Do not hide those
   modes behind ambiguous one-letter strings.
8. For assembly and patching, separate non-mutating assembly preview from a
   bounded verified patch mutation. A boolean `write_to_memory` would otherwise
   make MCP annotations and authorization inaccurate.

These decisions refine ADR 0018 and are inputs to the upcoming typed-breakpoint
and bounded assemble/patch ADRs.
