---
description: "Use when writing tests, fixtures, extending coverage, debugging failures, or touching the sample baseline and the OpenSSL corpus."
applyTo: "tests/**,vitest.config.ts,scripts/**,examples/**"
---
# Testing Standards

## Framework
- vitest, `globals: false` (import `describe` / `it` / `expect`), `pool: 'forks'` (a leaked env var or ceiling cannot cross files), `TZ=UTC`, one `tests/<name>.test.ts` per tool or module, `_`-prefixed shared helpers, deterministic (`sequence.shuffle: false`), < 30 s per test.
- Commands:
  - npm run test · npm run test:watch · npm run test:coverage (thresholds 94 / 90 / 95 / 94 in vitest.config.ts — never lower them; raise them when a release lifts coverage)
  - npm run typecheck:all (src + tests, and scripts)
  - npm run examples:check (runs every examples/*.json live; multi-step examples are chained)
  - npm run test:interop (tests/interop/openssl.test.ts: OpenSSL 3 on PATH; `PKINATIVE_INTEROP_REQUIRED=1` fails instead of skipping — CI sets it on every leg)
  - npm run corpus:pki && npm run validate:pki (the OpenSSL conformance corpus, from dist/)
  - npm run lint (`eslint src --max-warnings 0` — warnings fail)
  - npm run gate / npm run gate:fast (THE gate; `npx tsx scripts/gate.ts --only <step>` re-runs one step)

## Fixtures doctrine
- `tests/fixtures/pki/` holds 42 files made by OpenSSL 3 (`tests/fixtures/make-test-pki.sh`), pinned by `tests/fixtures/SHA256SUMS` with a row each in `tests/fixtures/PROVENANCE.md`; `tests/fixtures.test.ts` fails on a changed checksum, a missing file or an unlisted one. They have FOREIGN provenance — neither the server nor the engine wrote them — so a defect cannot be baked into both a fixture and its reading. They are NEVER regenerated in place (re-running the script makes new keys, which are new fixtures with new checksums); a test never calls OpenSSL to make a fixture. Every private key there is public TEST-ONLY material (password `test-only-password`, `PASSWORD` in `tests/_pki-fixtures.ts`).
- Load through `tests/_pki-fixtures.ts` (`fixture`, `fixtureBytes`, `fixtureBase64`, `fixtureText`, `fixtureInput`), never with a hard-coded path; `tests/_fixtures/` holds the generated contracts (tool shape, sample baseline) — never edit them by hand, never regenerate `tool-shape.v1.0.0.json`.
- Hostile inputs (truncated DER, oversized lengths, deep nesting, a prototype-polluting spec, a symlinked path) are built in the test, never committed as a fixture that looks valid.

## Secrets and verdicts
- Call `assertResultClean(result)` (`tests/_pki-assert.ts`) on EVERY result of a tool that takes a key, a PKCS#12 file or a password, and `assertNoSecret` on stderr, cache files and the stdio transcript: the needles (`tests/_secrets.ts`) are computed from the fixtures — PEM bodies, DER hex / base64, private scalars in every encoding, encrypted-key bodies, the password. A needle found anywhere is a leak, and a blocker.
- Every verdict test pins the instant: `at: AT` (`2027-01-01T00:00:00Z`, inside the fixtures' validity) — never the wall clock; assert `valid` and the `reasons[]` codes, never the prose. A negative verdict is `valid: false`, not `isError`; assert both shapes where a tool can produce either (`errorCodeOf`, `codeOf`).
- Prefer `callToolDirect` for tool behaviour; use `tests/_mcp-harness.ts` (`connectLegacy`) / `tests/_http-fixture.ts` only for transport contracts; `tests/cli-stdio.test.ts` drives the BUILT binary.

## Catalogue parity
- `tests/catalogue-parity.test.ts` compares the live `tools/list` structure with `tests/_fixtures/tool-shape.json`. After a deliberate schema change: `npm run build && npx tsx scripts/tool-shape.ts --write`, then review the fixture diff. Never refresh it to silence an accidental change.
- `tests/_fixtures/tool-shape.v1.0.0.json` is the frozen baseline: no tool / property / enum value removed, no new `required`, no tighter bound. Never regenerate it.
- `tests/schema-lockstep.test.ts` holds the JSON Schema and the Zod twin together; `tests/metadata.test.ts` holds the version lock-step and the nine env vars of `server.json`; `tests/governance.test.ts` asserts `src/governance.ts` and `scripts/verify-issue.mjs` stay aligned.

## Samples and the byte baseline
- `npm run build && npm run test:generate` drives the BUILT server (`scripts/generate-samples.ts`) over every hermetic `examples/*.json` under the hermetic env (`TZ=UTC`, every `PKINATIVE_MCP_*` scrubbed, then `PKINATIVE_MCP_AT=2027-01-01T00:00:00Z` and a temporary sandbox holding the fixtures) and writes `test-output/samples/`; `npm run verify:samples` (`scripts/verify-samples.ts`) compares the set with `tests/_fixtures/samples.sha256.json`. The baseline is a chain: an unchanged entry keeps its `since`.
- Three fingerprint modes (`scripts/lib/sample-fingerprint.ts`), chosen per sample and recorded in the manifest: `bytes` (SHA-256 of the artefact — deterministic signers Ed25519 / RSA PKCS#1 v1.5, requests, encodings), `tbs` (the signed part only — ECDSA / RSA-PSS signatures are randomised), `semantic` (a canonical projection — reports, verdicts and artefacts drawn with `'random'`). A sample moved from `bytes` to `tbs` or `semantic` hides a byte change: diff the mode column, and prove a non-repeatable sample with a double run first (`npx tsx scripts/verify-samples.ts --strict` fails on an unbaselined sample).
- An intended output change is rebaselined with `npx tsx scripts/verify-samples.ts --update`, explained in the manifest's `provenance` note and declared in the release note (its `since` moves to that release). Never `--update` to silence a surprise; a default artefact's bytes changing for the same deterministic inputs is semver-major.
- Changing an example's `arguments` (a projection, a pin, a fixture) changes its sample: expect `verify:samples` to flag it and declare the rebaseline with the example change.

## Conformance corpus
- `npm run corpus:pki` drives the BUILT server (`scripts/generate-pki-corpus.ts`, the table in `scripts/lib/pki-corpus.ts`) under the pinned instant and writes `test-output/pki/` with its `manifest.json`; `npm run validate:pki` (`scripts/validate-pki.ts`) checks every entry at level 0 (in-process engine round trip through `dist/server.js`, always runs) and level 1 (OpenSSL 3.x on PATH or `OPENSSL_BIN`; LibreSSL and OpenSSL < 3.0 are refused with the reason). Exit codes 0 / 1 (an expectation not met, an XPASS, no canary, the coverage canary) / 2 (corpus or `dist/` missing) / 3 (OpenSSL required but absent).
- Every new entry bumps `declared.conformant` or `declared.refused` in `docs/data/interop.json` (the coverage canary) and gets a row in `docs/guides/CONFORMANCE.md`; a `deterministic: true` entry is produced twice and must hash the same. Negative canaries (`expectRefused`) must stay refused: a canary that writes bytes is an XPASS and fatal. A known engine limit is a tracked canary, not a dropped entry.
- Level 1 is never silently skipped: absent OpenSSL exits 0 locally with the reason, but `PKINATIVE_INTEROP_REQUIRED=1` (every CI leg) and the gate's `--require-all` turn the skip into a failure. The vitest form is `tests/interop/openssl.test.ts`; the linters (`tests/interop/lint.test.ts`, zlint + pkilint) run on the publish profile with the reviewed waivers under `scripts/data/`.

## Test focus and naming
- Validate tool success AND error paths (`isError`, `[CODE]` in the text, `_meta.error.code`), schema constraints (unknown keys at any depth → `VALIDATION_ERROR`; `pem` XOR `derBase64` XOR `path`), sandbox protections (`tests/sandbox.test.ts`: traversal, absolute / UNC paths, NUL bytes, extension allow-list, symlinked parent or file, never-overwrite, key-bearing names refused on write, file I/O disabled when the env var is unset), the ceilings (`tests/limits.test.ts`: each of the 22 limits bounded by its ceiling), the cache gate (`tests/cache-policy.test.ts`), stdout purity.
- A test that closes an audit finding carries the finding id in its name: `it('A-003: a PBES1 key is refused with PKI_CRYPTO_UNSUPPORTED_ALGORITHM and a remedy')`; the ledger under `.audit/<version>/` points at it.
- Windows dev host: use `path` helpers; tests must pass on win32, darwin and linux (CI runs all three).

## Style
- Use describe/it structure. One behavior per test.
- Avoid brittle snapshot tests for DER; assert structure (`assertValidDer`, fingerprints, the parsed-back view, OpenSSL's verdict in tests/interop/) and byte identity where determinism is the contract (`bytes` baseline mode); a randomised artefact (`serialNumber: 'random'`, `nonce: 'random'`) is compared through its TBS structure (`tbs` mode).

## Quality gate
- All tests must pass; coverage must not regress in touched modules; the gate is the only definition of green.
