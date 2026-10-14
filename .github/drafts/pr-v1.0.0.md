# release: v1.0.0 — first stable release: 34 PKI tools on pkinative 1.0.0, OpenSSL-validated, no network, no key byte leaving

> **Branch:** `release/v1.0.0` → `main`
> **Type:** Major release (the first; the tool API starts at `1.0.0`)
> **pkinative pin:** `^1.0.0` (first pin)
> **Prepared:** 2026-10-13 — release note: `release-notes/v1.0.0.md`

> Human-in-the-loop: this draft was prepared on the branch and stops here (`.github/AGENT_RULES.md` rule 8). The maintainer reviews it, opens the pull request under their own identity, merges, tags and publishes. Nothing in this repository or in the server can do any of that.

## Summary

For a user of an MCP host, 1.0.0 gives a PKI toolbox that never touches the network and never lets a key byte out: inspect and verify X.509 certificates, CSRs, CRLs, OCSP responses, CMS SignedData and RFC 3161 time-stamps; build and validate certification paths with offline revocation evidence; issue certificates and requests from keys the caller brings; sign and counter-stamp CMS; open PKCS#8 and PKCS#12 files for description without ever returning the key; decode and encode ASN.1, PEM and OIDs. Every verdict is pinned to an instant, every refusal carries a frozen code and a remedy, every artefact is reproducible when serial, nonce and instants are pinned.

For an agent calling the tools, the server teaches its own doctrine: `SERVER_INSTRUCTIONS` is a decision tree (what is this object → is it trustworthy → does the name / purpose fit → is it revoked → sign / verify → time-stamps → issue → keys → raw bytes), 7 prompts carry the recipes, `describe_engine` lists the limits, ceilings, caps, vocabularies and refusals, `explain_code` explains any of the 21 wrapper codes, 57 `PKI_*` error codes, 43 `PKI_REASON_*` verdict reasons and 97 `PKI_DIAG_*` diagnostics, and `verbosity: 'summary'` / `fields` keep the answers small.

For the repository, this release ships with the engineering standard of its siblings (pdfnative-mcp 1.7.0, zipnative-mcp 1.0.0): one quality gate (`scripts/gate.ts`, fast / ci / publish profiles, the built server driven over stdio with stdout purity enforced), OpenSSL 3 as the blocking external judge of every artefact the server writes, a sample baseline, a pinned catalogue under a size budget, docs as code (`docs/assets/ecosystem.json` + `npm run verify:docs`, 27 rules), a committed agent layer (settings, fail-closed guard hook on Bash and PowerShell, generated rules, the release-audit skill), hardened workflows with Trusted Publishing, SBOM and attestation, and `scripts/release-prepare.ts`.

Counts (`docs/assets/ecosystem.json`): 34 tools, 7 prompts, 21 wrapper codes, 9 operator variables; 89 examples; 98 samples in the baseline (10 byte-exact, 3 `tbs`, 85 semantic); conformance corpus 23 + 5 corpus entries; 2275 tests across 107 files; 42 fixtures; 117 runtime exports reached 117 / 117.

## What changed

### Engine surface (`src/tools/`, shared fragments in `src/*.ts`)
- 34 tools in six groups (encodings 5, certificates and requests 8, paths / CRLs / OCSP 8, CMS and time-stamps 7, keys 3, meta 3), one module per tool with its JSON Schema and Zod `strictObject` twin in lock-step, ≤ 2 executable `_meta.examples` each; the shared fragments (PKI input `pem` / `derBase64` / `path`, the signer, the trust fragment, the 22 named limits, the projection inputs, the diagnostics report) inlined without `$ref` and kept terse (tools/list 427850 bytes under a 448 KiB budget).
- `src/pki-errors.ts` maps the 57 engine codes to 10 coarse classes with a remedy table phrased as MCP inputs; `src/wrapper-codes.ts` carries the 21 wrapper codes with a remedy each; `src/diagnostics.ts` installs a de-duplicating, capped sink on every engine call (no `console.warn` on a stdio server).
- `src/limits.ts` (the 22 limits under the three ceilings), `src/caps.ts` (the byte envelope), `src/sandbox.ts` (one boundary, extension allow-lists, realpath checks, exclusive writes), `src/secrets.ts` (the two password channels, redaction), `src/time.ts` (pinned instants), `src/key-views.ts` (allow-list key reports), `src/signer.ts` (non-extractable Web Crypto handles).

### Server (`src/server.ts`, transports, prompts, resources)
- Low-level `Server` + `setRequestHandler` on `@modelcontextprotocol/server` ^2.0.0: MCP 2026-07-28 stateless serving with `server/discover`, the `_meta` envelope, `resultType` and cache hints, and the automatic legacy `initialize` fallback for 2024-10-07, 2024-11-05, 2025-03-26, 2025-06-18 and 2025-11-25; stdio (256 MiB frame) and loopback Streamable HTTP with a bearer token.
- `SERVER_INSTRUCTIONS` (5469 bytes under an 8 KiB budget), 7 prompts, `pkinative://output/{+path}` resources (key-bearing extensions never listed nor served), the cache gate (`isCacheable`), `TOOL_API_VERSION = '1.0.0'` on every tool.
- `server.json` with the 9 operator variables (`PKINATIVE_MCP_OUTPUT_DIR`, `PKINATIVE_MCP_CACHE_DIR`, `PKINATIVE_MCP_PORT`, `PKINATIVE_MCP_HTTP_TOKEN`, `PKINATIVE_MCP_PASSWORD`, `PKINATIVE_MCP_AT`, `PKINATIVE_MCP_MAX_INPUT_BYTES`, `PKINATIVE_MCP_MAX_KDF_ITERATIONS`, `PKINATIVE_MCP_MAX_PATHS_EXPLORED`), registry name `io.github.Nizoka/pkinative-mcp`.

### Tooling (`scripts/`)
- `gate.ts` (fast / ci / publish, `--require-all`, inline `code-tables` / `dist-check` / `dist-probe` / `smoke` / `server-json`), `generate-samples.ts` + `verify-samples.ts` + `lib/sample-fingerprint.ts` (bytes / `tbs` / semantic modes), `generate-pki-corpus.ts` / `validate-pki.ts` + `lib/pki-corpus.ts` + `lib/interop-tools.ts` (levels 0 and 1, exit codes 0 / 1 / 2), `tool-shape.ts` + `lib/tool-shape.ts`, `verify-docs.ts` (27 rules: the 24 ported from pdfnative-mcp plus `no-secret-material`, `engine-data-parity`, `interop-counts`; `--json`, `--require-all`) + `lib/mcp-surface.ts` + `lib/secret-needles.ts`, `release-prepare.ts`, `build-claude-rules.ts`, `verify-issue.mjs`, `build-code-tables.mjs`; `scripts/README.md`.

### CI / repository (`.github/`, root)
- Ten workflows (`ci` on ubuntu Node 22 / 24 plus windows and macos running the gate `--ci --require-all`, `interop` on four legs and blocking on ubuntu-24.04 and windows, `sample-regression`, `publish` with the protected `npm-publish` environment, tag = version check, SBOM + attestation, `docs`, `codeql`, `scorecard`, `dependency-review`, `audit`, `node-current`); `harden-runner`, `persist-credentials: false`, `npm ci --ignore-scripts`, one SHA per action; `.github/rulesets/{main,tags}.json`; Dependabot; `CODEOWNERS`; the PR template mirrored in CONTRIBUTING; the issue templates.
- `.nvmrc` / `.node-version` (22), `.gitattributes` (LF), `.githooks/` + `hooks:install`, `tsconfig.scripts.json`, vitest under `TZ=UTC` with forks and the gate reporter; three runtime dependencies (`pkinative`, `@modelcontextprotocol/server`, `zod`); version lock-step (`package.json`, `src/version.ts`, `server.json` ×2, `CITATION.cff`).

### Agent layer
- `AGENTS.md` (repository rules), `CLAUDE.md` = `@AGENTS.md` + addendum, `docs/AGENT_CONTRACT.md` (§1 catalogue … §6 error reference — the consumer contract), `.claude/settings.json` (no commit attribution, Read denies, HITL denies for Bash and PowerShell), `.claude/hooks/guard.mjs`, `.claude/rules/` generated from `.github/instructions/`, `.claude/skills/release-audit/`, `.github/prompts/`, `.github/ai-governance.json`, `.github/AGENT_RULES.md`, `.github/copilot-instructions.md`.

### Tests, examples and samples
- 107 test files (2275 tests), among them `autonomy` (S0–S18 over stdio / HTTP × legacy / 2026-07-28), `secret-leak`, `pki-fuzz`, `prototype-pollution`, `coverage-matrix` (117 / 117 runtime exports), `schema-lockstep`, `schema-conformance`, `catalogue-parity`, `examples`, `cache-policy`, `protocol-revisions`, `diagnostics-inventory` (2 diagnostics from the fixtures, 30 from hand-built values, 65 listed as not reachable with the fixtures and why), `error-codes` (every wrapper code exercised, every `PKI_*` code reached or listed with the reason), `docs-consistency`, `tests/interop/*`, `tests/tools/*`.
- 89 examples under `examples/` executed by `tests/examples.test.ts`; 98 samples in `tests/_fixtures/samples.sha256.json`; 42 OpenSSL-made TEST-ONLY fixtures pinned by `SHA256SUMS` (password `test-only-password`), never regenerated in place.

### Documentation
- README, `llms.txt`, `docs/AGENT_CONTRACT.md`, `docs/AI_GUIDE.md`, `docs/API_STABILITY.md`, `docs/KNOWLEDGE_BASE.md` (the 117-export ledger), the nine guides (`AI_GOVERNANCE`, `LOCAL_TESTING`, `SECURITY`, `SIGNING`, `VERIFICATION`, `REVOCATION`, `TIMESTAMPS`, `KEYS`, `CONFORMANCE`), `SECURITY.md`, `CONTRIBUTING.md`, `SUPPORT.md`, `CODE_OF_CONDUCT.md`, `ROADMAP.md`, `THIRD-PARTY-NOTICES.md`, `CITATION.cff`, `CHANGELOG.md`, `docs/data/*.json` (the engine registries mirrored byte for byte, `interop.json`), `docs/assets/ecosystem.json`, `release-notes/v1.0.0.md`, `release-notes/{TEMPLATE,PR_TEMPLATE}.md`, this draft.

## Verification

What actually ran on the release branch (Windows 11, Node 22, OpenSSL 3.5.5). Every figure was measured on the release tree.

| Command | Result |
|---|---|
| `PKINATIVE_INTEROP_REQUIRED=1 npx tsx scripts/gate.ts --ci --require-all` | every step PASS, none skipped (the publish profile adds `lint:certs`; zlint and pkilint are installed by `publish.yml`, not on the dev host) |
| `npm run test` | 107 files, 2275 tests (2261 passed, 14 skipped) |
| `npm run test:coverage` — coverage | 98.41 / 92.04 / 99.46 / 98.97 (statements / branches / functions / lines), thresholds 94 / 90 / 95 / 94 |
| `npm run build && npm run test:generate && npm run verify:samples` | 98 samples in the baseline (10 byte-exact, 3 `tbs`, 85 semantic); `--strict`: 98 tracked samples match |
| `npm run corpus:pki && npm run validate:pki` | 23 PASS, 5 REFUSED, 0 FAIL, 0 XPASS, 0 SKIP — 57 engine checks, 30 OpenSSL checks, OpenSSL 3.5.5 |
| `npm run test:interop` | OpenSSL 3.5.5, `PKINATIVE_INTEROP_REQUIRED=1`: 51 passed, 1 skipped (the linters, publish profile only) |
| `npx tsx scripts/tool-shape.ts --check` | `tools/list matches tests/_fixtures/tool-shape.json (34 tools, 427850 bytes; instructions 5469 bytes)` |
| `npm run verify:docs` | 27 rules over 37 documents, 0 errors, 0 skipped |
| `npm audit --audit-level=high` | found 0 vulnerabilities |
| Built server over stdio (`node dist/cli.js`) | gate `smoke`: handshake, `tools/list` = 34 tools, `serverInfo.version` = 1.0.0, JSON-RPC frames only on stdout — PASS, 34 tools |

Independent audit: `/release-audit release-notes/v1.0.0.md` — PENDING (the first release has no previous tag to diff against; the audit runs over the whole tree).

### Release audit

Two auditors (security, hardening and protocol conformance; API coverage, doctrine and documentation parity) and an adversarial verifier ran over the release commit (`.claude/skills/release-audit/`): 107 rows, 102 confirmed, 2 rejected, 3 duplicates. One blocker (A-019: a PKCS#8 key under a harmless file name was listed and served by `resources/*`), three majors (A-031: the operator pin was not part of the cache key; B-009: `encode_asn1` accepted unknown spec members; B-011: a documented `remedy` member no verdict returned) and sixteen minors were fixed in the commits that carry their id (`fix(resources): … (A-019)`, `fix(cache): … (A-031)`, `fix(tools): … (B-009) … (B-010)`, `fix(tools): … (A-039, A-040) … (V-001)`, `test: … (A-009)`, `docs: … (B-011, …)`), each with a test named by the finding; five notes are recorded. Verdict: **GO** — the gate above was re-run green after the loop.

## API stability

- `TOOL_API_VERSION`: `1.0.0` — the first version; `docs/API_STABILITY.md` governs every change from here.
- Superset gate: `tests/_fixtures/tool-shape.v1.0.0.json` freezes this catalogue; the comparison against it starts with the first release that has something to compare. The parity gate against `tests/_fixtures/tool-shape.json` is active now (`tests/catalogue-parity.test.ts`, `npx tsx scripts/tool-shape.ts --check`).
- Accepted deltas: none (first release).
- `tests/_fixtures/tool-shape.json`: pinned at 1.0.0 with `npx tsx scripts/tool-shape.ts --write`.
- Error codes: 21 wrapper codes and the 57 `PKI_*` codes verbatim; documented in `docs/AGENT_CONTRACT.md` §6.

## Output changes and rebaseline

- Default artefacts: first release — the bytes of the deterministic tools (`encode_asn1`, `encode_x509_structure`, `convert_pem`, `create_ocsp_request` with a fixed nonce, `create_timestamp_request` with a fixed nonce, Ed25519 and RSA PKCS#1 signers with a fixed serial and instant) are the contract from here on.
- Bytes inherited from the engine: every artefact is written by pkinative 1.0.0; a change in the engine's bytes is a major of this server (`.github/AGENT_RULES.md` rule 5).
- `tests/_fixtures/samples.sha256.json`: first baseline — 98 entries anchored at 1.0.0 (10 byte-exact, 3 `tbs` for the randomised artefacts, 85 semantic); provenance note in the manifest. No earlier baseline existed to rebaseline from.
- Every item above is declared in the Upgrade section of `release-notes/v1.0.0.md`.

## Out of scope (tracked in ROADMAP.md)

- By doctrine, never: network retrieval of CRL / OCSP / AIA / TSA material, key generation, key export, writers for PKCS#8 / PKCS#12 / CRL / OCSP responses / time-stamp responses.
- Deferred: DSA / ML-DSA verification (parsed, never verified), per-tool HTTP page streaming, the superset gate (from 1.1.0), automated MCP registry publication.

## Maintainer steps after merge

Agents stop at this draft; everything below is done by the maintainer (`.github/AGENT_RULES.md` rule 8).

1. Push the branch, open the pull request with this body, wait for `ci (22)`, `ci (24)`, `os (windows-latest)`, `os (macos-latest)`, `sample-regression`, `interop (ubuntu-24.04)` and `interop (windows-latest)`, merge. First run of every workflow on GitHub: confirm `harden-runner` behaves on `windows-latest` (audit mode) and that the gate is green on `macos-latest`.
2. Tag `v1.0.0` on the merge commit and publish the GitHub Release — `publish.yml` runs on the Release publication, not on the tag push, and checks that the tag equals the version in `package.json` (title `v1.0.0 - First stable release`, body = `release-notes/v1.0.0.md`).
3. First npm publication: the Trusted Publishing binding cannot exist before the package does — record the chosen path here before tagging (the sibling convention: a placeholder `0.0.0` published with `--provenance=false`, Trusted Publishing bound to `publish.yml` / environment `npm-publish`, `0.0.0` deprecated, then `1.0.0` attested by `publish.yml`). Then approve the `npm-publish` environment and confirm with `npm view pkinative-mcp version`.
4. Validate and publish `server.json` to the MCP registry (`io.github.Nizoka/pkinative-mcp`).
5. Import the rulesets (`.github/rulesets/main.json`, `.github/rulesets/tags.json`) — CONTRIBUTING §Branch protection.
6. Update the `pkinative-mcp` entry of `docs/assets/ecosystem.json` in the sibling repositories (pkinative, pkinative-cli).

## Checklist

- [ ] `npm run gate` passes — the CI profile in one command (`npm run gate:fast` for a quick loop while iterating; PowerShell swallows a bare `--`, so call `npx tsx scripts/gate.ts --fast` there)
- [ ] All tests pass (`npm run test`)
- [ ] Type check passes (`npm run typecheck:all`)
- [ ] Lint passes (`npm run lint`)
- [ ] New code has tests (coverage thresholds in `vitest.config.ts` must not regress)
- [ ] No `any` types introduced
- [ ] No new runtime dependencies added (`pkinative`, `@modelcontextprotocol/server` and `zod` stay the only three)
- [ ] No secret in the diff: no private key, no PKCS#12 file, no password outside `tests/fixtures/` (whose keys are public TEST-ONLY material); every new key or password result is checked with `assertResultClean`
- [ ] A new or changed tool touches every wiring point: `src/tools/<name>.ts` (JSON Schema and the parallel Zod `strictObject` in lock-step), its group registry under `src/tools/_group-*.ts`, `tests/<name>.test.ts`, `examples/`, README, `docs/AGENT_CONTRACT.md`, `llms.txt`, `docs/API_STABILITY.md`
- [ ] If a tool schema, a wrapper code or a `PKI_*` mapping changed: `npm run build && npx tsx scripts/tool-shape.ts --write` refreshed `tests/_fixtures/tool-shape.json` deliberately, the live catalogue is still a superset of the frozen `tests/_fixtures/tool-shape.v1.0.0.json`, and `TOOL_API_VERSION` was reviewed under `docs/API_STABILITY.md`
- [ ] If samples, the conformance corpus or OpenSSL interoperability changed: `npm run build && npm run test:generate && npm run verify:samples && npm run corpus:pki && npm run validate:pki && npm run test:interop` passes locally with OpenSSL 3 on PATH (`PKINATIVE_INTEROP_REQUIRED=1` fails instead of skipping); an intended output change is rebaselined with `npx tsx scripts/verify-samples.ts --update` and declared in the release note; a randomised sample (`serialNumber: 'random'`, `nonce: 'random'`) is compared in `tbs` mode, never `bytes`
- [ ] If docs, README, llms.txt, AGENTS.md, CLAUDE.md, `.github/instructions/` or `.claude/` changed: `npm run agents:rules` regenerated `.claude/rules/` and `npm run verify:docs` passes
- [ ] CHANGELOG.md updated if user-facing changes
- [ ] For releases: `release-notes/vX.Y.Z.md` and this draft written, and `npx tsx scripts/gate.ts --publish --require-all` passes locally, which runs every individual gate: `typecheck:all`, `lint`, `code-tables`, `build`, `dist-check`, `dist-probe`, `smoke`, `verify:tool-shape`, `server-json`, `test:generate`, `test:coverage`, `verify:docs`, `verify:samples`, `corpus:pki`, `validate:pki`, `interop`, `lint:certs`
- [ ] Every figure above was produced by a command on this branch, not typed from memory
- [ ] `release-notes/vX.Y.Z.md` and the CHANGELOG entry for X.Y.Z say the same things as this body
- [ ] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch
