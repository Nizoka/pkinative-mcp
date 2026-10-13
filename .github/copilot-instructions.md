# pkinative-mcp - Project Guidelines

> Full context (architecture, tool schemas, output system, security design):
> [`docs/KNOWLEDGE_BASE.md`](../docs/KNOWLEDGE_BASE.md). Don't duplicate it here.
> Repository rules shared by every coding agent: [`AGENTS.md`](../AGENTS.md) — keep this file consistent with it.
> Contract for agents that *use* the server (tool catalogue, decision tree, token economy, error codes):
> [`docs/AGENT_CONTRACT.md`](../docs/AGENT_CONTRACT.md).

## Overview

MCP server bridging pkinative 1.0.0 (pinned `^1.0.0`) to AI clients over stdio or Streamable
HTTP, on the MCP TypeScript SDK v2 (`@modelcontextprotocol/server`, MCP 2026-07-28 with automatic
2025-era fallback). 34 tools in five groups (certificates, paths, CMS / time-stamps, keys, encodings), the 22
`PkiLimits` bounds by name, nine `PKINATIVE_MCP_*` operator variables. Current release 1.0.0
(`TOOL_API_VERSION` 1.0.0). Three runtime dependencies (pkinative, the MCP SDK, zod) — never add one.
Quality bar: production-grade OSS (strict TypeScript, strong validation, secure file IO, **no network, ever**,
reproducible artefacts, deterministic releases). Faithful thin wrapper: every PKI decision lives in the engine;
never reimplement one on raw primitives, never over-promise (state engine limits in the tool description).
OpenSSL 3 is the external conformance judge (CI runs it on four runner images); it is a CI tool, not a dependency.

## Doctrine (the lines no change crosses)

- **No key byte leaves.** The key and PKCS#12 tools (`inspect_private_key`, `inspect_pkcs12`, `open_pkcs12`) return
  allow-list views built field by field in `src/key-views.ts`; no key generation, no key export, no PKCS#8 / PKCS#12 /
  CRL / OCSP-response / time-stamp-response writer. Key-bearing files (`.key .p8 .p12 .pfx`) are read by the key tools only,
  never written and never served as resources.
- **No network code path.** No `fetch`, `http`, `https`, `net`, `dns` anywhere; no URL from a tool argument; no telemetry.
  Revocation evidence (CRL, OCSP response) and time-stamp tokens are inputs the caller supplies.
- **Secrets.** A password comes from the per-call `password` input or the operator-side `PKINATIVE_MCP_PASSWORD`
  (both at once is `VALIDATION_ERROR`); never in a log, an error text, a cache file, a resource or a result; `src/secrets.ts`
  redacts, `isCacheable` refuses to cache a call carrying one. Only the presence of `PKINATIVE_MCP_PASSWORD` /
  `PKINATIVE_MCP_HTTP_TOKEN` is logged at boot.
- **Refusals stay refusals.** SHA-1 is opt-in (`allowSha1`), the RSA scheme is explicit, PBES1 / RC2 / 3DES / legacy
  SHA-1 MAC PKCS#12 are refused with the engine's remedy; `describe_engine.refusals` and `UNEXPOSED_EXPORTS` say so honestly.
- **Verdicts are not errors.** A negative verdict is `valid: false` + `reasons[]`, never `isError`; a malformed input is a coded
  `isError`; nothing throws across the MCP boundary.

## Architecture (one line each)

- src/cli.ts — stdio / Streamable HTTP entry point; the operator knobs are read once at boot (an invalid value refuses to start).
- src/http.ts — Node http ↔ Web Request/Response bridge, loopback bind, Host/Origin guard; src/auth.ts — opt-in bearer token
  (`PKINATIVE_MCP_HTTP_TOKEN`, ≥ 16 chars, constant-time compare, 401 + WWW-Authenticate).
- src/server.ts — request handlers, `isCacheable`, projection, artefact delivery, SERVER_INSTRUCTIONS, `TOOL_API_VERSION`.
- src/tools/_definition.ts — `defineTool`, the tool kinds (read / verdict / artefact / engine / explain / governance), the
  annotations (`READ_ONLY` / `WRITES` / `PRODUCES`); src/tools/_registry.ts + `_group-*.ts` — the catalogue in order;
  src/tools/_shared.ts — `parseInput`, `ProjectionShape`, `withDiagnostics`.
- src/tools/* — one file per tool: JSON Schema `as const` + parallel Zod `strictObject` + handler + output schema.
- src/pki-input.ts (`pem` XOR `derBase64` XOR `path`, bundles), src/content-input.ts (`text` / `base64` / `path`), src/parse-context.ts
  (`PARSE`: encodingRules, pemMode, strict, limits), src/limits.ts (the 22 bounds + ceilings), src/caps.ts (every byte / count cap,
  `CAPS`), src/signer.ts (`SIGNER`), src/trust.ts (`TRUST`), src/time.ts (`at`, `PKINATIVE_MCP_AT`), src/names.ts, src/spki.ts,
  src/x509-spec.ts, src/asn1-spec.ts — the shared input fragments.
- src/views.ts, src/key-views.ts, src/wire.ts — the wire views every result is built from (no raw DER echoes).
- src/pki-errors.ts — `guard` / `guardAsync` / `mapPkiError`, the ONLY module that reads `err.code`; src/wrapper-codes.ts — the
  wrapper's own codes; src/errors.ts — ToolError, SecurityError, GovernanceError; src/diagnostics.ts — the diagnostics sink.
- src/sandbox.ts — the single filesystem boundary (`PKINATIVE_MCP_OUTPUT_DIR`, realpath checks, `wx` writes); src/output.ts — artefact
  emission (base64 or sandboxed file); src/resources.ts — MCP resources over the sandbox (key-bearing files never listed).
- src/projection.ts — `verbosity: 'summary'` / `fields`; src/cache.ts — opt-in content-addressed cache; src/random.ts — the wrapper's
  randomness (`serialNumber: 'random'`, `nonce: 'random'`); src/governance.ts — the HITL contract; src/engine.ts — engine identity and probes.
- scripts/* — TypeScript run by tsx: gate.ts, generate-samples.ts + verify-samples.ts (the baseline chain), generate-pki-corpus.ts +
  validate-pki.ts (the OpenSSL corpus), tool-shape.ts, verify-docs.ts, release-prepare.ts, build-claude-rules.ts; scripts/helpers/
  (hermetic env, built-server driver); scripts/validators/ (the pkilint driver).
- tests/* — vitest, one `*.test.ts` per tool or module; `_`-prefixed shared helpers (`_pki-fixtures.ts`, `_pki-assert.ts`, `_secrets.ts`,
  `_mcp-harness.ts`); tests/fixtures/pki/ (42 OpenSSL-made files pinned by SHA256SUMS, never regenerated); tests/_fixtures/
  (tool shape, sample baseline); tests/interop/ (OpenSSL); tests/tools/ (repository tooling).
- examples/*.json — executable `tools/call` sequences, run by `npm run examples:check` and rendered into the sample baseline.

## Core conventions

- Strict TypeScript, ESM-first (relative imports carry `.js`); no `any` (use `unknown` + narrowing); English everywhere.
- Validate every tool input at the boundary with Zod `strictObject` (unknown keys at any depth are a `VALIDATION_ERROR`);
  keep JSON Schema and Zod aligned, built from the same constants where a shared fragment exists.
- Every failure is an `isError` result with one documented code (`docs/AGENT_CONTRACT.md` §6): a wrapper code, or the engine's
  `PKI_*` code verbatim through `guard` / `guardAsync` — no uncoded failure, no raw `err.message` from the filesystem.
- `tools/list` is structurally fingerprinted: after a deliberate schema change run `npm run build && npx tsx scripts/tool-shape.ts --write`
  (refreshes `tests/_fixtures/tool-shape.json`, checked by `npm run verify:tool-shape`) and review under docs/API_STABILITY.md;
  `tests/_fixtures/tool-shape.v1.0.0.json` is the frozen baseline the live catalogue stays a superset of.
- Additive and byte-identical: default artefacts of existing tools do not change for the same deterministic inputs
  (a pinned `at` / `notBefore` / `signingTime`, an explicit serial or nonce, a fixture key); new behaviour is opt-in.
- Unknown tool name on `tools/call` is a JSON-RPC `-32602` `[UNKNOWN_TOOL]` protocol error.
- On stdio, stdout carries JSON-RPC frames only: never `console.log` in `src/` — log to stderr (eslint `no-console`).
- Never write outside `PKINATIVE_MCP_OUTPUT_DIR`; never overwrite (`wx`); reject absolute paths, traversal, NUL bytes, a symlinked
  parent or file, and any key-bearing extension on the write side.
- Operator env vars (9, read once at boot, declared in server.json, an invalid value refuses to start): `PKINATIVE_MCP_OUTPUT_DIR`,
  `PKINATIVE_MCP_CACHE_DIR`, `PKINATIVE_MCP_PORT`, `PKINATIVE_MCP_HTTP_TOKEN`, `PKINATIVE_MCP_PASSWORD`, `PKINATIVE_MCP_AT`,
  `PKINATIVE_MCP_MAX_INPUT_BYTES`, `PKINATIVE_MCP_MAX_KDF_ITERATIONS`, `PKINATIVE_MCP_MAX_PATHS_EXPLORED`.
- `limits.*` widen a bound for one call only and never above the operator ceilings (`LIMIT_CEILING_EXCEEDED` names the variable).
- `npm run lint` is `eslint src --max-warnings 0` — warnings fail the gate. CI runs the gate on Linux (Node 22 / 24), Windows and
  macOS with `PKINATIVE_INTEROP_REQUIRED=1`; the OpenSSL corpus runs on four images (interop.yml). Seven checks are required.

## Quality gate (all PRs)

`npm run gate` is THE quality gate (`scripts/gate.ts`; the step list is its `STEPS` table; logs in `test-output/.gate/<step>.log`).
Profiles: `npm run gate:fast` (typecheck:all, lint, test, code-tables, server-json, verify:docs) before every commit; `npm run gate` is the
CI profile (adds build, dist-check, dist-probe, smoke, verify:tool-shape, test:generate, test:coverage, verify:samples, corpus:pki,
validate:pki, interop — the OpenSSL steps skip without `openssl` on PATH unless `--require-all` or `PKINATIVE_INTEROP_REQUIRED=1`);
`npx tsx scripts/gate.ts --publish --require-all` on release branches adds lint:certs (zlint + pkilint; `--require-all` fails on a
skip). PowerShell swallows a bare
`--` after `npm run`: call `npx tsx scripts/gate.ts --fast` there. Drive the **built** server (`node dist/cli.js`, stdio) before
claiming a change works. Coverage thresholds (94 / 90 / 95 / 94) live once in `vitest.config.ts` — never lower them.
Run `npm run verify:docs` after touching a count, a version, a tool name, a code or an operator variable anywhere in the docs.

## Generated files — regenerate, never hand-edit

`.claude/rules/*.md` (`npm run agents:rules`, from `.github/instructions/*.instructions.md`), `tests/_fixtures/tool-shape.json`
(`npx tsx scripts/tool-shape.ts --write`), `tests/_fixtures/samples.sha256.json` (`npx tsx scripts/verify-samples.ts --update`, only with a
rebaseline declared in the release note), `dist/`, `coverage/`, `test-output/`, `package-lock.json`. The OpenSSL fixtures under
`tests/fixtures/pki/` are not generated files: they are never regenerated in place (tests/fixtures/PROVENANCE.md).

## Release process

- Follow CONTRIBUTING.md §Release and `scripts/release-prepare.ts` (mechanical bump + scaffolds; it never commits, tags or publishes).
- release-notes/vX.Y.Z.md is mandatory; CHANGELOG.md mirrors it; the Upgrade section declares every output change and rebaseline.
- The PR body is drafted at `.github/drafts/pr-vX.Y.Z.md` from `.github/drafts/TEMPLATE.md`.
- GitHub Release title: `vX.Y.Z - short description`.
- npm publish via GitHub Actions Trusted Publishing (OIDC), no NPM_TOKEN; the attest job attaches the tarball and the CycloneDX SBOM.
- Human-in-the-loop: agents draft and verify; the maintainer pushes, opens PRs / issues, tags and publishes
  (`.github/AGENT_RULES.md` rule 8; `.claude/hooks/guard.mjs` refuses those commands at the tool boundary). No `Co-Authored-By` trailer.

## Working efficiently (token-aware)

Optimize for minimal tokens in both planning and implementation, without lowering quality:

- Gather context in parallel, then act; don't re-read files already in context.
- Make targeted edits — don't reprint whole files or restate unchanged code.
- Keep replies concise: no preambles, no change-summary essays, no new markdown docs unless asked. Let the diff speak.
- Reuse the scoped `.github/instructions/*.md` rather than re-deriving conventions.
- Never read `dist/`, `coverage/`, `test-output/`, `node_modules/`, `package-lock.json`, the tool-shape fixtures or the sample
  baseline; `tools/list` is large — project it, never print it. Never print a fixture key or a PKCS#12 file, even a TEST-ONLY one.
