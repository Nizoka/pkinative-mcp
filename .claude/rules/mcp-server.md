---
paths:
  - "src/server.ts"
  - "src/tools/**"
  - "src/cli.ts"
  - "src/http.ts"
  - "src/auth.ts"
  - "src/resources.ts"
  - "src/projection.ts"
---
<!-- GENERATED from .github/instructions/mcp-server.instructions.md by scripts/build-claude-rules.ts — do not edit -->

# MCP Server Standards

## Transport and lifecycle
- stdio transport by default; Streamable HTTP when `PKINATIVE_MCP_PORT` is set (loopback bind + Host/Origin guard in `src/http.ts`; opt-in bearer token via `PKINATIVE_MCP_HTTP_TOKEN`, `src/auth.ts`: ≥ 16 chars, no whitespace, constant-time compare, 401 + `WWW-Authenticate`; a weaker value refuses to start).
- SDK: `@modelcontextprotocol/server` ^2.0.0 (MCP 2026-07-28 with `server/discover`, automatic 2025-era `initialize` fallback). Stay on the low-level `Server` + `setRequestHandler` surface — `McpServer.registerTool` would validate `structuredContent` against the projected output schemas and break the `verbosity` / `fields` contract.
- Operator knobs are read ONCE at boot in `src/cli.ts` / `src/caps.ts` / `src/time.ts` / `src/secrets.ts`, never per call: the ceilings `PKINATIVE_MCP_MAX_INPUT_BYTES` (≥ 1024), `PKINATIVE_MCP_MAX_KDF_ITERATIONS` (≥ 1), `PKINATIVE_MCP_MAX_PATHS_EXPLORED` (≥ 1); the pinned instant `PKINATIVE_MCP_AT` (ISO 8601 or epoch ms); the operator password `PKINATIVE_MCP_PASSWORD` (exclusive with the per-call `password`). An invalid value refuses to start; only the PRESENCE of a secret is logged. All nine variables are declared in `server.json` (asserted by tests/metadata.test.ts).
- Gracefully close the server on SIGINT/SIGTERM.
- stdout purity: never write to stdout except JSON-RPC frames (eslint `no-console`; log to stderr through the `[pkinative-mcp]` logger). Every engine call runs with the diagnostics sink installed (`src/diagnostics.ts`), so the engine's `console.warn` fallback can never fire.

## Tool contract
- Each tool module exports `<NAME>_NAME`, `<NAME>_INPUT_SCHEMA` (JSON Schema `as const`), a Zod `z.strictObject` twin that mirrors it exactly (unknown keys at any depth → `VALIDATION_ERROR`, matching `additionalProperties: false`), `<NAME>_OUTPUT_SCHEMA`, `<NAME>_SUMMARY_PROPERTIES` for projectable read tools, and a handler `(args: unknown) => Promise<Result>`.
- Register through `defineTool` (`src/tools/_definition.ts`) in the group file `src/tools/_group-*.ts`, in catalogue order, with `kind` — `read` (a report, projectable), `verdict` (`valid` + `reasons[]`, never `isError` for a negative verdict), `artefact` (a produced DER), `engine` (`describe_engine`), `explain` (`explain_code`, `resolve_oid`), `governance` (`draft_governance_issue`) — `title`, `description` (what it does, when to prefer another tool, the caps, the codes it raises), annotations `READ_ONLY` / `WRITES` / `PRODUCES`, and at most two executable `_meta.examples` (validated against `inputSchema` in tests; more examples belong in `examples/*.json`).
- Return tool-level errors as `isError` results — `"<tool> failed [CODE]: message"` + `_meta.error` — never throw across the MCP boundary. Engine errors are mapped ONLY in `src/pki-errors.ts` (`guard` / `guardAsync` / `mapPkiError`), keeping the `PKI_*` code verbatim. The one protocol-level exception: an unknown tool name on `tools/call` is a JSON-RPC `-32602` `[UNKNOWN_TOOL] Unknown tool: <name>`.
- Every tool ships `_meta.apiVersion` (`TOOL_API_VERSION`, `src/version.ts`).
- Read tools are projectable: `verbosity: 'summary'` collapses to the tool's summary and `fields: [...]` keeps dot-paths (≤ 16, `src/projection.ts`); the advertised `outputSchema` is the full shape with every property optional (`projectableOutputSchema`), so a missing field never fails validation — test new output fields on the default, `summary` and projected paths.
- Artefact tools deliver the bytes ONCE: an embedded `resource` block (base64 DER, `application/pkix-*` / `application/pkcs7-*` …) in inline mode or a `resource_link` in file mode, never duplicated in `structuredContent`; the summary carries fingerprints and facts, never the DER back (no raw echoes, `src/views.ts` `stripRaw`).
- `tools/list` structure is pinned by `tests/_fixtures/tool-shape.json`; any change to types, enums, defaults, constraints, `required`, `additionalProperties` or example count needs `npm run build && npx tsx scripts/tool-shape.ts --write` and a review; `tests/_fixtures/tool-shape.v1.0.0.json` is the frozen baseline the live catalogue must stay a superset of.
- No `$ref` / `$defs` and no `$schema` keyword in input schemas (host compatibility).
- Update `SERVER_INSTRUCTIONS` (decision tree + pitfalls), AGENTS.md, README.md, `docs/AGENT_CONTRACT.md` and llms.txt together whenever you add a tool or change its behaviour — the counts are asserted by `verify:docs`.

## Resources
- `resources/list` / `resources/read` (`src/resources.ts`) expose the sandbox only (`pkinative://output/…`), bounded by `MAX_LISTED_RESOURCES` / `MAX_RESOURCE_WALK_DEPTH` / `MAX_RESOURCE_READ_BYTES`, after a realpath check of the file itself; key-bearing extensions (`SECRET_EXTENSIONS`) are never listed and never served.

## Caching (the cache gate)
- `isCacheable` (`src/server.ts`) serves the opt-in cache (`PKINATIVE_MCP_CACHE_DIR`, plaintext at rest, `src/cache.ts`). NEVER cacheable: a `path` input, a call carrying a `password` or a `signer`, `outputMode: 'file'`, a `'random'` serial or nonce, a `'now'` instant, any clock-dependent instant (an omitted `at` / `notBefore` / `signingTime` without `PKINATIVE_MCP_AT`), `describe_engine`, `draft_governance_issue`. The key namespace carries the tool API, package and engine versions.
- A new tool whose output depends on a secret, the clock, the environment or an operator knob declares `cacheable: false` or lists its `instantInputs`; a miss here is silent and wrong (tests/cache-policy.test.ts).

## Safety
- Never trust tool arguments — validate at the boundary with Zod; every path goes through `src/sandbox.ts`; every size through `src/caps.ts`; every bound through `src/limits.ts` (`resolveCallLimits` holds the ceilings).
- Keep output bounded (50 MiB inline, 1 GiB file, 128 MiB decoded inline input, 256 MiB stdio frame / HTTP body) and reproducible: a pinned instant plus explicit serial / nonce makes an artefact a pure function of its inputs.
- Never echo `PKINATIVE_MCP_HTTP_TOKEN`, a password, a key byte or an absolute sandbox path in a result, an error message or stderr.

## Compatibility
- Keep tool names stable across patch releases; additive changes only within a major.
- Bump `TOOL_API_VERSION` when a cached response would become unsafe to serve.
- Breaking changes require explicit migration notes in release-notes.
