# AGENTS.md

Condensed, editor-agnostic guidance for AI coding agents working **on** pkinative-mcp.
Canonical detail: [.github/copilot-instructions.md](.github/copilot-instructions.md) + [.github/instructions/](.github/instructions/).
Claude Code loads [CLAUDE.md](CLAUDE.md), which imports this file. Keep the three consistent.
Agents that **use** the server read [docs/AGENT_CONTRACT.md](docs/AGENT_CONTRACT.md) (catalogue, decision tree, token economy, error codes) instead.

## Mission and constraints

pkinative-mcp is the official Model Context Protocol server of the pkinative engine: 34 tools over the PKI lifecycle
(encodings, certificates and requests, paths / CRLs / OCSP, CMS and time-stamps, keys and PKCS#12, meta), 7 prompts and resources, on stdio and Streamable HTTP.

- **Three runtime dependencies, no more.** `pkinative`, `@modelcontextprotocol/server`, `zod`. Another runtime package is a hard block (`npm run verify:issue`).
- **Faithful thin wrapper.** Every PKI operation lives in the engine; the server never parses DER or implements a signature and never over-promises
  (`describe_engine.refusals`). 117 / 117 runtime exports are reached by a named tool (`tests/coverage-matrix.test.ts`).
- **Validate at the boundary.** Zod `.strict()` at every depth, in step with the advertised JSON Schema (`tests/schema-lockstep.test.ts`); every failure is one documented code.
- **No network, ever.** No `fetch` / `https` / `dns` / socket code; `node:http` only in the loopback listener, `node:net` only for `isIPv4` / `isIPv6` (`tests/no-network.test.ts`). Evidence and tokens are inputs;
  no argument supplies a URL or an absolute path. File I/O stays under `PKINATIVE_MCP_OUTPUT_DIR` (`src/sandbox.ts`).
- **No secret in any output.** Never log or echo a password, a key byte, a scalar or an operator secret; keys are non-extractable Web Crypto handles,
  every key / PKCS#12 report is an allow-list view (`src/key-views.ts`), `assertResultClean` guards every key-bearing result.
- **Doctrine is not negotiable.** No key generation or export, no PKCS#8 / PKCS#12 / CRL / OCSP-response / time-stamp-response writer; SHA-1 opt-in;
  RSA scheme explicit; PBES2 / PBMAC1 only; limits never exceed the operator ceilings. Weakening a default is a human decision (AGENT_RULES rule 6).
- **Additive and byte-identical.** Default responses and the bytes written for pinned inputs do not change within a major; read `docs/API_STABILITY.md` first.
- **Operator knobs are read once at boot**, declared in `server.json` (nine); an invalid value refuses to start.
- **ESM-first TypeScript strict.** Relative imports carry `.js`; no `any`; no unused locals; on stdio, stdout carries JSON-RPC frames only.
- **Reproducible output.** Pin `at`, `notBefore`, `signingTime`, `serialNumber`, `nonce` (or `PKINATIVE_MCP_AT`); the sample set is held to `tests/_fixtures/samples.sha256.json`.
- **Human-in-the-loop.** Agents draft and verify; the maintainer pushes, opens PRs/issues, tags and publishes. **English everywhere** (`verify:docs` `prose-language`).

## The gate

`npm run gate` is THE quality gate (`scripts/gate.ts`; the step list is its `STEPS` table). Logs land in `test-output/.gate/<step>.log`; the summary is ≤ 20 lines.

| Profile | Command | Runs |
|---|---|---|
| Fast — before every commit | `npm run gate:fast` | typecheck:all, lint, test, code-tables, server-json, verify:docs |
| CI — the default | `npm run gate` | fast minus `test`, plus build, dist-check, dist-probe, smoke, verify:tool-shape, test:generate, test:coverage, verify:samples, corpus:pki, validate:pki, interop |
| Publish — release branches | `npx tsx scripts/gate.ts --publish --require-all` | everything, incl. lint:certs (zlint / pkilint); `--require-all` fails on a skip (CI passes it too) |

PowerShell swallows a bare `--`: call the script with `--fast`, `--only <step>`, `--from <step>`, `--json`. One suite: `npx vitest run tests/<name>.test.ts`.
Drive the **built** server (`node dist/cli.js`) before claiming a change works. OpenSSL 3.x on `PATH` is the external judge (`validate:pki`, `interop`).

## Where is what

| Path | Purpose | Read first |
|---|---|---|
| `src/cli.ts`, `src/http.ts`, `src/auth.ts`, `src/server.ts` | Entry, transports, boot-time knobs; request handlers, the cache gate, `SERVER_INSTRUCTIONS`, prompts, resources | `mcp-server.instructions.md` |
| `src/tools/` | One file per tool (JSON Schema, Zod twin, handler, `defineTool`); `_registry.ts` + `_group-*.ts` hold the catalogue order | `tools.instructions.md` |
| `src/*.ts` | Shared fragments: `pki-input`, `parse-context`, `limits`, `signer`, `trust`, `projection`, `output`, `secrets`, `key-views`, `sandbox`, `caps`, `pki-errors` | `security.instructions.md` |
| `scripts/` | gate, samples and baseline, the OpenSSL corpus and validator, tool-shape, verify-docs, release-prepare | `testing.instructions.md` |
| `tests/`, `examples/` | vitest suites, `_`-prefixed helpers, `fixtures/pki/` (42 TEST-ONLY files), `_fixtures/`, `interop/`, `tools/`; executable `tools/call` examples | `testing.instructions.md` |
| `docs/` | `AGENT_CONTRACT.md`, `KNOWLEDGE_BASE.md` (export ledger), `API_STABILITY.md`, `guides/`, `data/`, `assets/ecosystem.json` | — |

## Architecture

`JSON-RPC frame → src/server.ts → callToolDirect → tool handler (Zod parse → shared fragments → pkinative) → result by kind → content + structuredContent`.
Handlers are thin: parse, load inputs through the sandbox and the caps, call the engine under `guard()` (errors mapped in `src/pki-errors.ts` only),
return a report, a verdict (`valid` + `reasons[]`, never `isError`) or an artefact (delivered once).

Adding or changing a tool touches ALL of these (`verify:docs` rules `tool-parity`, `error-parity`, `env-var-parity` fail on a missed step):

1. `src/tools/<name>.ts` and its entry in `src/tools/_group-*.ts`; a new result shape also needs a dispatch branch in `src/server.ts`.
2. `tests/<name>.test.ts` (success, each code, file mode, `assertResultClean` when a key or password is involved) and `examples/<name>.json`.
3. `npm run build && npx tsx scripts/tool-shape.ts --write` — only for a deliberate structural change; `TOOL_API_VERSION` moves when a schema or a code changes.
4. README, `SERVER_INSTRUCTIONS`, `docs/AGENT_CONTRACT.md`, `docs/AI_GUIDE.md`, `docs/KNOWLEDGE_BASE.md`, `llms.txt`, `docs/assets/ecosystem.json`, `CHANGELOG.md`.

## Consumer contract in brief

A tool succeeds with `content` + `structuredContent` or fails with `isError: true`, `[CODE] message` and `_meta.error`, `CODE` being one of the 21 wrapper codes
or the 57 `PKI_*` engine codes of `docs/AGENT_CONTRACT.md` §6; a negative verdict is `valid: false` + `reasons[]` (43 `PKI_REASON_*`), never `isError`;
diagnostics (97 `PKI_DIAG_*`) are reported, not thrown, unless `strict: true`. An unknown tool is JSON-RPC `-32602` `[UNKNOWN_TOOL]`.
`outputMode: 'file'` writes under the sandbox; `verbosity: 'summary'` / `fields` shrink results; both MCP eras (2026-07-28 and the legacy handshake) are served.

## Never touch

- `tests/fixtures/pki/` + `SHA256SUMS` (foreign-provenance TEST-ONLY material), shipped `release-notes/v*.md`, the frozen `tests/_fixtures/tool-shape.v1.0.0.json`.
- `dist/`, `coverage/`, `test-output/`, `node_modules/`, `package-lock.json`, `src/data/pkinative/*.json` (vendored) and the generated files below: never hand-edit.
- Any figure in `docs/assets/ecosystem.json` without `npm run verify:docs` afterwards; the `pkinative` pin without a release note; the coverage thresholds downwards.

## Generated files

`.claude/rules/*.md` ← `npm run agents:rules`; `src/data/pkinative/code-tables.ts` ← `node scripts/build-code-tables.mjs`; `tests/_fixtures/tool-shape.json` ←
`npx tsx scripts/tool-shape.ts --write` (only with a declared schema change); `tests/_fixtures/samples.sha256.json` ← `npx tsx scripts/verify-samples.ts --update`
after `npm run build && npm run test:generate` (only with a declared rebaseline); `dist/`, `coverage/`, `test-output/` ← the build, coverage, samples and corpus scripts.

## Counts and versions

34 tools, 7 prompts, 21 wrapper codes, 57 `PKI_*` error codes, 43 `PKI_REASON_*` reasons, 97 `PKI_DIAG_*` diagnostics, 22 engine limits, 9 operator variables,
89 examples, 2275 tests, 98 samples in the baseline, 23 + 5 corpus entries, 42 fixtures. `docs/assets/ecosystem.json` is the source of every count and version.
Coverage thresholds: `vitest.config.ts` (94 / 90 / 95 / 94). Engine pkinative 1.0.0 (`^1.0.0`); Node ≥ 22; `tools/list` under 448 KiB, instructions under 8 KiB.

## Releasing and governance

Follow CONTRIBUTING.md §Release and `scripts/release-prepare.ts`; Conventional Commits, never with a `Co-Authored-By` trailer. Every runtime change gets a ROADMAP.md entry,
a CHANGELOG line and a line in the next `release-notes/vX.Y.Z.md`; the version moves in lock-step (`tests/metadata.test.ts`). Agents never push, never open PRs/issues/releases,
never publish, never tag: [.github/AGENT_RULES.md](.github/AGENT_RULES.md), [.github/ai-governance.json](.github/ai-governance.json). Issue drafts go to `.github/drafts/` (`npm run verify:issue`).

## Ecosystem

- [pkinative](https://github.com/Nizoka/pkinative) — the zero-dependency engine (`ROADMAP.md` lists what is upstream-blocked).
- [pkinative-cli](https://github.com/Nizoka/pkinative-cli) — the terminal wrapper of the same engine (`docs/data/core-exports.json` maps exports to commands).
- [pdfnative-mcp](https://github.com/Nizoka/pdfnative-mcp), [zipnative-mcp](https://github.com/Nizoka/zipnative-mcp) — the sibling servers this repository mirrors.

See also: [ROADMAP.md](ROADMAP.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [llms.txt](llms.txt).
