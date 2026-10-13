# scripts/ — the quality gate, the sample set, the OpenSSL corpus and the verifiers

Maintenance scripts run with `tsx` (no build step) and drive the **built** server
(`dist/server.js`, the same `callToolDirect()` the `tools/call` handler delegates to — never
`src/`) wherever an artefact is produced. The tool catalogue is discovered at run time
(`toolNames()`, `listToolsPayload()`): no script hard-codes a tool list, so the corpus and the
samples keep working while the catalogue grows (an entry whose tool is not registered is
SKIPPED with the reason, never failed). The npm aliases in `package.json` are the public
names; call a script directly to pass flags (PowerShell swallows a bare `--` after `npm run`).
`scripts/tsconfig.json` extends `../tsconfig.scripts.json` so an editor types these files as
`typecheck:scripts` does.

OpenSSL 3.x is the external judge of this server (the role veraPDF plays for pdfnative-mcp):
what the tools write, a foreign implementation must read and verify. It is found on PATH
(`OPENSSL_BIN` overrides); LibreSSL and OpenSSL < 3.0 are refused with the reason.

## Quick start

```bash
npx tsx scripts/gate.ts --fast     # typecheck:all, lint, test, code-tables, server-json, verify:docs — the loop while you work
npm run gate                       # the CI profile (default)
npm run build && npm run test:generate && npx tsx scripts/verify-samples.ts   # the sample baseline
npm run build && npm run corpus:pki && npm run validate:pki                   # the OpenSSL corpus
```

## Exit codes

Every script follows the same convention, so the gate can tell "the check failed" from "the
tool is missing":

| Code | Meaning |
|---|---|
| 0 | pass (or skipped with a reason printed — a skip is never silent) |
| 1 | a content failure: a check did not hold, a fingerprint moved, a canary was accepted |
| 2 | usage or infrastructure: bad flags, `dist/` missing, the corpus not generated, an external tool installed but unusable |
| 3 | a required external tool is missing (`validate-pki.ts` under `PKINATIVE_INTEROP_REQUIRED=1`) |

## The scripts

| Script | npm alias | Gate step | Purpose | Flags | Exit codes |
|---|---|---|---|---|---|
| `gate.ts` | `gate`, `gate:fast` | — (it is the gate) | Runs the STEPS table in order, one line per step, logs under `test-output/.gate/<id>.log`; profiles `--fast` / `--ci` (default) / `--publish`. Inline steps: `code-tables` (`build-code-tables.mjs --check`), `dist-check` (entry points, the shebang, the generated code tables), `dist-probe` (no `console.log` in emitted JavaScript, only `src/` under `dist/`, no secret needle — the test keys and the password recomputed from the fixtures), `smoke` (the built server over stdio: `initialize`, `tools/list`, `tools/call describe_engine` — stdout must carry JSON-RPC frames only, the tool count is read from `dist/server.js`), `server-json` (offline validation against the vendored registry schema). `verify:docs` SKIPs with "verify-docs.ts not present yet" until that script lands; `validate:pki` / `interop` SKIP without OpenSSL 3.x; `lint:certs` (publish only) SKIPs without zlint / pkilint | `--only <id>`, `--from <id>`, `--require-all` (a SKIP fails), `--json` | 0 green (or skipped with a reason), 1 a step failed / would have skipped under `--require-all`, 2 usage |
| `generate-samples.ts` | `test:generate` | `test:generate` | Runs every `examples/*.json` (`{ description, tool, arguments }` or `{ description, steps:[…] }`, placeholders `<fixture:NAME>`, `<content:NAME>`, `<base64 from step N>`, `<password:test-only>`; `expectError: CODE` asserts the refusal; `documentationOnly: true` is schema-checked only) through the built server into `test-output/samples/` under the hermetic env (UTC, every `PKINATIVE_MCP_*` scrubbed, then `PKINATIVE_MCP_AT=2027-01-01T00:00:00Z` and `PKINATIVE_MCP_OUTPUT_DIR` = a temp sandbox holding the fixtures under `fixtures/`). Writes `<example>.json` (the result without base64 blobs), `<example>.<ext>` (the artefact bytes) and `manifest.json` (the fingerprint mode of every file) | `--quiet`, `--verbose`, `--json` | 0 every sample written, 1 a tool call failed or an example is not hermetic, 2 `dist/` missing or bad usage |
| `verify-samples.ts` | `verify:samples` | `verify:samples` | Fingerprints the generated set in the mode the manifest recorded (`bytes` for deterministic artefacts — Ed25519 / RSA PKCS#1 signatures, requests, encodings; `tbs` for ECDSA / RSA-PSS certificates and requests — the signed part only; `semantic` for JSON results and randomised CMS — canonical JSON without `evaluatedAt` / `sha256` / `sizeBytes` / `filePath`) and holds it to `tests/_fixtures/samples.sha256.json`, a chained baseline (`since` per entry) | `--strict` (a new, unbaselined sample fails), `--update` (rewrite — only with a rebaseline declared in the release note), `--json` | 0 match, 1 a changed / removed (or, with `--strict`, new) sample or no baseline, 2 usage or missing samples |
| `generate-pki-corpus.ts` | `corpus:pki` | `corpus:pki` | Writes the OpenSSL interoperability corpus (`lib/pki-corpus.ts`: self-signed CAs and leaves per signature family, a pathLen-0 intermediate, CSRs, attached and detached CMS, TSP and OCSP requests, PEM re-encodings of the DER fixtures, five negative canaries) through the built server into `test-output/pki/` with `manifest.json` (status, sha256, the second digest of a deterministic entry). A canary that writes bytes is recorded as `xpass`; an entry whose tool is not registered is `skipped` | `--quiet`, `--verbose`, `--json` | 0 written / refused as expected / skipped, 1 a conformant entry was refused, 2 `dist/` missing or bad usage |
| `validate-pki.ts` | `validate:pki` | `validate:pki` | Level 0: every artefact fed back to its read / verify tool in-process (inspect + `verify_certificate_chain` to the corpus CA at the pinned instant, `inspect_csr` with the proof of possession, `verify_cms` with content and anchors, `decode_asn1` + an independent `node:crypto` reckoning of the OCSP CertID and the TSP imprint / nonce; a deterministic entry must hash the same twice). Level 1: the OpenSSL commands of `lib/interop-tools.ts` (`x509 -text`, `verify [-purpose sslserver] [-untrusted] -attime`, `req -verify`, `crl -text`, `cms -verify`, `asn1parse`, `ocsp -req_text`, `ts -query -text`), raw transcripts under `test-output/pki/reports/`. Coverage canary against `docs/data/interop.json` (`declared.conformant` / `declared.refused`); XPASS is fatal | `--quiet`, `--verbose`, `--json`; env `PKINATIVE_INTEROP_REQUIRED=1`, `OPENSSL_BIN` | 0 every expectation met (level 1 skipped with a reason when OpenSSL is absent), 1 a FAIL / XPASS / canary, 2 corpus or `dist/` missing, 3 OpenSSL required but absent |
| `tool-shape.ts` | `verify:tool-shape` | `verify:tool-shape` | Structural fingerprint of the built `tools/list` (descriptions stripped) against `tests/_fixtures/tool-shape.json`; `--check` also holds the catalogue under 448 KiB, the instructions (`__serverInstructions`) under 8 KiB, and `declared.toolsListBytes` of `docs/assets/ecosystem.json` (when present) within 2 % of the measurement | `--check` (exit 1 on drift), `--write` (refresh — only for a deliberate schema change, reviewed under docs/API_STABILITY.md §5) | 0 match or written, 1 drift or over budget, 2 `dist/` missing |
| `verify-docs.ts` | `verify:docs` | `verify:docs` | (lands later) every count, version, tool, error code, operator variable, link, anchor and agent file held to the source tree through `lib/mcp-surface.ts`, `lib/markdown-anchors.ts`, `lib/agent-config.ts`, `lib/prose-language.ts` | `--json` | 0 no error, 1 an error |
| `release-prepare.ts` | `release:prepare` | — | Applies a version bump in one pass: package manifests, `src/version.ts` (`PKINATIVE_MCP_VERSION`), `server.json` (twice), `docs/assets/ecosystem.json` (`packages["pkinative-mcp"].version`, `verifiedOn`), `CITATION.cff`, `SECURITY.md`, the README engine badge, `llms.txt`; scaffolds `release-notes/vX.Y.Z.md` from `release-notes/TEMPLATE.md` and `.github/drafts/pr-vX.Y.Z.md` from `.github/drafts/TEMPLATE.md`. A file not present yet is reported and skipped; a present file without its pattern is a problem. Never commits, tags or publishes | `--version X.Y.Z`, `--date`, `--previous vA.B.C`, `--dry-run` | 0 applied, 1 a present file's pattern was not found, 2 usage |
| `build-claude-rules.ts` | `agents:rules` | (`verify:docs` rule `claude-rules-sync`) | Projects `.github/instructions/*.instructions.md` into `.claude/rules/*.md` (scoped by `applyTo` → `paths:`), deleting orphans | `--check` (exit 1 on drift, no writes), `--json` | 0 in sync or generated, 1 drift / a source without `applyTo` |
| `build-code-tables.mjs` | — | `code-tables` | Regenerates `src/data/pkinative/code-tables.ts` from the vendored registries | `--check` | 0 in sync or written, 1 out of date |
| `verify-issue.mjs` | `verify:issue` | — | Policy check of an issue draft under `.github/drafts/` against `.github/ai-governance.json`; the offline twin of the `draft_governance_issue` tool | `<draft.md>` | 0 compliant, 1 a violation, 2 usage |
| `install-git-hooks.mjs` | `hooks:install`, `hooks:uninstall` | — | Sets `core.hooksPath` to `.githooks/` for this clone only | `--uninstall` | 0 done, 1 git unavailable |

## Libraries (`lib/`), helpers and data

| Module | Used by | What it holds |
|---|---|---|
| `lib/example-runner.ts` | generate-samples, tests | How `examples/*.json` parse, which `<placeholder>` inputs resolve (a fixture, a content fixture, an earlier step, the password), the driver over `callToolDirect()`, and the schema check of a documentation-only example |
| `lib/sample-fingerprint.ts` | verify-samples, generate-samples (`modeFor`) | The three fingerprint modes, the tiny DER reader behind `tbs` (`firstElementOfSequence`, `looksSigned`), the signer-randomness rule, the sample manifest, the baseline chain (`chainSince`), identical groups |
| `lib/pki-corpus.ts` | generate-pki-corpus, validate-pki, verify-docs, tests | The corpus table (entries, round trips, OpenSSL checks, determinism claims, negative canaries), the placeholder resolver, the `node:crypto` reckonings of the OCSP CertID and the TSP request |
| `lib/pki-corpus-manifest.ts` | generate-pki-corpus, validate-pki | The manifest types, loader and status counts |
| `lib/interop-tools.ts` | validate-pki, gate (skip condition), `tests/interop/openssl.test.ts` | `locateOpenssl()` (`OPENSSL_BIN`, PATH), the version gate (`opensslMissing()`: "openssl not on PATH" / "LibreSSL is not OpenSSL" / "OpenSSL < 3.0"), `runOpenssl()`, the command builders and outcome classifiers by id |
| `lib/tool-shape.ts` | tool-shape, tests | The structural projection of `tools/list` and the size budgets |
| `lib/json-schema-lite.ts` | gate (`server-json`), example-runner | A draft-07 subset validator that fails on a keyword it does not implement |
| `lib/mcp-surface.ts` | verify-docs, tests | The server surface read from text: the tools in registry order (`_registry.ts` + `_group-*.ts`), prompts, error codes, operator variables (`PKINATIVE_MCP_*`), the changelog ladder, the derived counts |
| `lib/markdown-anchors.ts` | verify-docs (`anchor-parity`) | GitHub heading slugs, the anchor inventory of a document, its fragment links |
| `lib/agent-config.ts`, `lib/prose-language.ts` | verify-docs, build-claude-rules, tests | `.claude/settings.json` / rules / skills / PR-template checks (the guarded shell tools Bash and PowerShell, the HITL deny families); the English-only prose detector |
| `helpers/hermetic.ts`, `helpers/tz.ts` | every generator, the gate | `TZ=UTC` and the removal of every inherited `PKINATIVE_MCP_*` variable — imported first |
| `helpers/io.ts`, `helpers/server.ts` | every generator | The pinned instant (`SAMPLE_AT`), the fixture inputs, the temporary sandbox, shared I/O; loading the built server and reading the artefact a result delivers |
| `data/lint-waivers.json`, `validators/pkilint-driver.py` | `tests/interop/lint.test.ts` | The reviewed zlint / pkilint waivers (none today) and the pkilint driver |

## Conventions

- Every script prints a one-line summary when stdout is not a terminal (CI, the gate, an
  agent) and a table under `--verbose`; `--json` is the machine-readable form.
- Exit 2 is always usage or infrastructure, never a content failure; exit 3 is a required
  external tool that is missing.
- Nothing here has a runtime dependency: `tsx` and `vitest` are dev tooling; the scripts
  load `dist/server.js` and never import `src/` (they may import `pkinative`, the engine the
  server pins, for the independent reckonings of the corpus checks).
- No script pushes, tags, publishes or opens anything on GitHub — those are the
  maintainer's steps.
- Tests for the pure parts live in `tests/tools/` (`gate`, `tool-shape`, `interop-tools`,
  `pki-corpus`, `json-schema-lite`, `markdown-anchors`, `hermetic-env`, `release-prepare`);
  the vitest form of the OpenSSL level is `tests/interop/openssl.test.ts`, the certificate
  linters `tests/interop/lint.test.ts`.
