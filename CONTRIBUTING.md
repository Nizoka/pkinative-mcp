# Contributing to pkinative-mcp

Thanks for considering a contribution! This project is intentionally small, focused, and high-quality — the bar is **exactly three runtime dependencies — `pkinative`, the MCP SDK (`@modelcontextprotocol/server` ^2.0.0) and `zod` — and no new one, ever**, **no PKI logic in `src/`** (every byte of ASN.1, every signature and every verdict belongs to the engine), and **no key byte in any output**.

## Quick start

```bash
git clone https://github.com/Nizoka/pkinative-mcp.git
cd pkinative-mcp
npm ci --ignore-scripts      # what CI runs; `.npmrc` sets ignore-scripts=true anyway
npm run build                # the gate's smoke step, the sample generator and the corpus drive dist/
npm run gate:fast            # typecheck, lint, tests, code tables, server.json, docs checks — the loop while you work
```

Requirements: Node.js ≥ 22 (CI runs the gate on Linux with Node 22 and 24, and on Windows and macOS with the pinned Node line — all four required checks); OpenSSL 3.x on `PATH` for the interoperability steps (see [OpenSSL interoperability](#openssl-interoperability)); optional: zlint and pkilint for the publish profile.

For the full local-verification workflow — quality gate, examples-as-tests, the sample baseline, checking that produced artefacts are actually valid (OpenSSL), driving the built server from Claude Code or the MCP Inspector — see [docs/guides/LOCAL_TESTING.md](docs/guides/LOCAL_TESTING.md).

Windows notes: the Bash one-liners run under Git Bash; PowerShell swallows a bare `--` after `npm run`, so pass script flags by calling the script directly (`npx tsx scripts/gate.ts --fast`). Every file the project writes uses LF line endings (`.gitattributes`); the binary fixtures (`*.der`, `*.p12`, `*.p7s`, …) are marked `text: unset`, and the opt-in pre-commit hook refuses a new CRLF text blob before it is committed — a CRLF PEM fixture would break its `SHA256SUMS` pin.

## Workflow

1. **Open an issue first** for non-trivial changes (new tools, breaking changes, dependency additions). The `draft_governance_issue` tool produces a compliant draft; a human submits it.
2. **Branch from `main`**: `git checkout -b feat/my-feature` (use Conventional Commit prefixes: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`). Commits carry no `Co-Authored-By` or "generated with" trailer.
3. **Keep diffs small and focused**. One logical change per PR.
4. **Add tests** for any new behaviour. CI runs [the gate](#the-gate) on every PR on Linux (Node 22 and 24), Windows and macOS; every one of those jobs is a required check, as are `sample-regression` and the two blocking `interop` legs.
5. **Never commit a secret.** The only private keys in the tree are the public TEST-ONLY fixtures under `tests/fixtures/pki/` (password `test-only-password`); a hostile key, a PKCS#12 or a password needed by a test is built in the test, never committed. Every result of a tool that takes a key, a PKCS#12 file or a password is checked with `assertResultClean`.
6. **Update the changelog** under the `## [Unreleased]` section.

## The gate

`npm run gate` is THE quality gate — one command, one summary of at most 20 lines, logs under `test-output/.gate/<step>.log`. The step table is `STEPS` in `scripts/gate.ts`:

| Profile | Command | Steps |
|---|---|---|
| Fast — before every commit | `npm run gate:fast` | `typecheck:all`, `lint`, `test`, `code-tables`, `server-json`, `verify:docs` |
| CI — the default | `npm run gate` | `typecheck:all`, `lint`, `code-tables`, `build`, `dist-check`, `dist-probe`, `smoke`, `verify:tool-shape`, `server-json`, `test:generate`, `test:coverage`, `verify:docs`, `verify:samples`, `corpus:pki`, `validate:pki`, `interop` — the build and the samples come before the coverage run, so the suites that need `dist/` execute (and fail, not skip, when their input is missing) |
| Publish — release branches | `npx tsx scripts/gate.ts --publish --require-all` | + `lint:certs` (zlint and pkilint over the corpus); `--require-all` turns any skipped step into a failure |

`--only <step>` runs one step, `--from <step>` resumes from one, `--json` emits a machine-readable result. PowerShell swallows a bare `--` after `npm run`, so call the script there: `npx tsx scripts/gate.ts --fast`. Five steps are inline: `code-tables` (the generated `src/data/pkinative/code-tables.ts` in sync with the vendored registries), `dist-check` (entry points, the shebang, the generated tables), `dist-probe` (no `console.log` in emitted JavaScript, only `src/` under `dist/`, and **no byte of a test key** — the needles are recomputed from the fixtures), `smoke` (the **built** server over stdio: handshake, `tools/list`, `describe_engine`, and stdout carrying JSON-RPC frames only) and `server-json` (offline validation against the vendored MCP registry schema). The gate is hermetic: `TZ=UTC`, every inherited `PKINATIVE_MCP_*` variable scrubbed. The individual scripts still exist — [scripts/README.md](scripts/README.md) has the full table with flags and exit codes:

```bash
npm run typecheck:all      # tsc over src/ + tests/, then scripts/
npm run lint               # eslint src --max-warnings 0 (a warning fails)
npm run test               # vitest run (dot reporter)
npm run test:coverage      # vitest with v8 coverage — thresholds in vitest.config.ts
npm run build              # tsc → dist/
npm run verify:tool-shape  # the built tools/list against tests/_fixtures/tool-shape.json (and the 448 KiB / 8 KiB budgets)
npm run verify:docs        # every count, version, link and parity rule (docs/assets/ecosystem.json)
npm run test:generate      # write the sample set to test-output/samples/ with the BUILT server
npm run verify:samples     # compare it with tests/_fixtures/samples.sha256.json
npm run corpus:pki         # write the OpenSSL interoperability corpus to test-output/pki/
npm run validate:pki       # level 0 (engine round trip) + level 1 (OpenSSL 3.x) over the corpus
npm run test:interop       # the vitest form of level 1 (PKINATIVE_INTEROP_REQUIRED=1 fails instead of skipping)
npm run test:lint-certs    # zlint + pkilint over the corpus (publish profile)
```

All new code must include tests. Coverage thresholds are enforced once, in `vitest.config.ts` (94 / 90 / 95 / 94), mirrored by `declared.coverageStatements` in `docs/assets/ecosystem.json`, re-measured at each release and **never lowered** to make a change pass — add tests.

Opt-in git hooks: `npm run hooks:install` sets `core.hooksPath` to `.githooks/` for this clone (pre-commit: lint + a CRLF guard; pre-push: the fast gate); `npm run hooks:uninstall` removes them. They are never activated automatically.

## Coding standards

- TypeScript **strict** mode is mandatory; ESM-first — relative imports carry `.js`.
- ESLint must pass with **zero warnings** — enforced: `npm run lint` is `eslint src --max-warnings 0`, so a warning fails the gate (no non-null assertions; narrow explicitly).
- No `any`. Use `unknown` + narrowing.
- **No `console.log` in `src/`.** On stdio, stdout is the JSON-RPC channel: logs go to stderr through the `[pkinative-mcp]` logger (the gate's `smoke` and `dist-probe` steps fail on a stray stdout line); every engine call runs with the diagnostics sink installed so the engine's `console.warn` fallback never fires.
- Public APIs (anything exported from `src/index.ts`) require TSDoc comments.
- All tool inputs MUST be validated with Zod inside the handler (defence in depth — the JSON Schema is for clients, the Zod schema is for safety). Every object schema is `.strict()` at every depth; every failure is a `ToolError` with a documented code.
- Every engine call goes through `guard` / `guardAsync` / `mapPkiError` (`src/pki-errors.ts`) — the only module allowed to read the engine's `err.code`; every byte in or out of the filesystem goes through `src/sandbox.ts` / `src/output.ts`; every size through `src/caps.ts`; every bound through `src/limits.ts`.
- **Never loosen a security default.** SHA-1 stays opt-in, the RSA scheme stays explicit, PBES2 / PBMAC1 stay the only password-based forms, no key is ever exported, no file is ever overwritten, `limits` never exceed the operator ceilings. A proposal to weaken one is a human decision recorded in the PR (`.github/AGENT_RULES.md` rule 6).
- **No network path.** No module may open a socket. Do not add one — not behind an environment variable either.
- English everywhere — code, comments, tests, examples, docs and release notes (`verify:docs` rule `prose-language`).

## Adding a tool

A new or changed tool touches **all** of these (`verify:docs` rules `tool-parity`, `error-parity` and `env-var-parity` fail on a missed step — the same four steps as [AGENTS.md](AGENTS.md) §Architecture):

1. `src/tools/<name>.ts` exporting the `<NAME>_NAME` constant, `<NAME>_INPUT_SCHEMA` (JSON Schema `as const`, served to clients, built from the shared fragments — `pkiInputSchema`, `pkiBundleSchema`, `contentInputSchema`, `PARSE_INPUT_PROPERTIES`, `LIMITS_INPUT_SCHEMA`, `SIGNER_INPUT_SCHEMA`, `TRUST_INPUT_PROPERTIES`, `PROJECTION_INPUT_PROPERTIES`, `outputInputProperties`), its Zod twin, `<NAME>_OUTPUT_SCHEMA` (projectable through `projectableOutputSchema` for a read or verdict tool, with the summary properties), the handler `(args: unknown) => Promise<…>` and the `defineTool` definition (`kind`, `title`, `description` — what it does, when to prefer another tool, the caps, the codes it raises —, annotations `READ_ONLY` / `WRITES` / `PRODUCES`, `cacheable` / `instantInputs`, one or two executable `_meta.examples`); then its entry in the group file `src/tools/_group-*.ts`, in catalogue order. A new result shape also needs a dispatch branch in `src/server.ts`.
2. `tests/<name>.test.ts` (success, each error code, a negative verdict where the tool has one, file mode, `assertResultClean` on every key- or password-bearing result, the instant pinned at `AT`), a worked example `examples/<name>.json` (executed by `tests/examples.test.ts` — `npm run examples:check` — and, when hermetic, rendered into the sample baseline), and for an engine export its row in `docs/data/core-exports.json` (`tests/coverage-matrix.test.ts` holds the 117 / 117). Every new wrapper code must appear in `src/wrapper-codes.ts` with a remedy, in `docs/AGENT_CONTRACT.md` §6 and be named by a test — `tests/error-codes.test.ts` enforces all three.
3. The catalogue fixture — only for a deliberate structural change: `npm run build && npx tsx scripts/tool-shape.ts --write` refreshes `tests/_fixtures/tool-shape.json`, which `tests/catalogue-parity.test.ts` and the gate step `verify:tool-shape` compare with the live `tools/list` (structure only — descriptions are stripped, so wording never trips it; the 448 KiB catalogue and 8 KiB instructions budgets are checked too). Any fixture diff is reviewed under [docs/API_STABILITY.md](docs/API_STABILITY.md), and `TOOL_API_VERSION` moves when a schema or an error code changes. The catalogue frozen at the 1.0.0 tag (`tests/_fixtures/tool-shape.v1.0.0.json`) is never regenerated: the live catalogue must stay a superset of it for the whole 1.x line.
4. The documents: README tool matrix and tool reference, `docs/AGENT_CONTRACT.md` (catalogue, decision tree, §6), `docs/AI_GUIDE.md` decision table, `docs/KNOWLEDGE_BASE.md` (the export ledger), `llms.txt`, `docs/API_STABILITY.md`, `docs/assets/ecosystem.json`, `CHANGELOG.md` — then `SERVER_INSTRUCTIONS` and the relevant MCP prompt in `src/server.ts`.

Drive the **built** server (`node dist/cli.js` over stdio; harnesses `tests/_mcp-harness.ts`, `tests/_agent-client.ts`) before claiming a change works — source tests alone do not prove the emitted package.

## Samples & byte baseline

`npm run build && npm run test:generate && npm run verify:samples` is the whole loop. `scripts/generate-samples.ts` runs every hermetic `examples/*.json` sequence (`{ description, tool, arguments }` or `{ description, steps: […] }`, placeholders `<fixture:NAME>`, `<content:NAME>`, `<base64 from step N>`, `<password:test-only>`; `expectError: CODE` asserts a refusal; `documentationOnly: true` is schema-checked only — the file-mode examples) through the **built** server into the git-ignored `test-output/samples/` — under the hermetic env (`TZ=UTC`, every `PKINATIVE_MCP_*` scrubbed, then `PKINATIVE_MCP_AT=2027-01-01T00:00:00Z` and a temporary sandbox holding the fixtures under `fixtures/`).

`scripts/verify-samples.ts` fingerprints the set in the mode the manifest recorded and compares it with the committed baseline `tests/_fixtures/samples.sha256.json` — **98 samples**: `bytes` for deterministic artefacts (Ed25519 and RSA PKCS#1 v1.5 signatures, requests, encodings — 10), `tbs` for ECDSA and RSA-PSS certificates and requests whose signature is randomised (the signed part only — 3), `semantic` for JSON results and randomised CMS (canonical JSON without `evaluatedAt`, `sha256`, `sizeBytes`, `filePath` — 85). The baseline is a chain: each entry records the release whose output it is (`since`), and an unchanged entry keeps it.

- A new sample: add the example, then `npm run build && npm run test:generate && npx tsx scripts/verify-samples.ts --update`. A sample listed as `tbs` or `semantic` is proven non-repeatable with a double run first (`npx tsx scripts/verify-samples.ts --strict` fails on an unbaselined sample).
- **An intended output change** (an engine bump, an encoder fix) is rebaselined the same way and **declared in the release note** (Upgrade section) — the `since` of every re-anchored entry moves to the release doing it, so the diff shows exactly what changed. A default artefact's bytes changing for the same deterministic inputs is semver-major (`.github/AGENT_RULES.md` rule 5).
- `--update` is never used to silence a surprise: an unexplained byte change is a regression until proven otherwise.
- The `sample-regression` workflow rebuilds and regenerates the set on every pull request and is a required status check (see [Branch protection](#branch-protection)).

## OpenSSL interoperability

The server's artefacts are checked against the reference implementation of the field, OpenSSL 3.x — the role veraPDF plays for pdfnative-mcp. `npm run corpus:pki` drives the **built** server (`scripts/generate-pki-corpus.ts`, corpus table in `scripts/lib/pki-corpus.ts`) to write the interoperability corpus to `test-output/pki/` with its `manifest.json`: **23 conformant artefacts** (self-signed CAs and leaves for Ed25519, RSA PKCS#1 v1.5, RSA-PSS and ECDSA P-256, a pathLen-0 intermediate and a leaf under it, three CSRs, attached and detached CMS, two time-stamp requests, two OCSP requests, three PEM re-encodings) and **5 refused canaries** (a SHA-1 signature, a legacy PKCS#12 signer, an RSA key without a scheme, an inverted validity, a URL member in a spec) that must be refused with their declared code. It is a representative sample, not an exhaustive feature matrix; it is reproducible (pinned instant, pinned serials and nonces, the TEST-ONLY fixture keys, a per-file SHA-256 and the second digest of every deterministic entry in the manifest).

`npm run validate:pki` (`scripts/validate-pki.ts`) validates every entry at two levels. **Level 0** (always runs, no external tool): every artefact fed back to its read / verify tool in-process — `inspect_certificate` + `verify_certificate_chain` to the corpus CA at the pinned instant, `inspect_csr` with the proof of possession, `verify_cms` with the anchors and the detached content, `decode_asn1` of the OCSP and time-stamp requests plus an independent `node:crypto` reckoning of the CertID and of the imprint / nonce, a deterministic entry hashing the same twice. **Level 1** (OpenSSL 3.x on `PATH`, `OPENSSL_BIN` overrides; LibreSSL and OpenSSL < 3.0 refused with the reason): the 12 command families of `scripts/lib/interop-tools.ts` — `x509 -text`, `verify [-purpose sslserver] [-untrusted] -attime`, `req -verify`, `crl -text`, `cms -verify` (attached and detached), `asn1parse`, `ocsp -req_text`, `ts -query -text` — with the raw transcripts under `test-output/pki/reports/`. Three guards keep the run honest:

- **Negative canaries** must be refused; a canary that writes bytes is an **XPASS**, always fatal, and a run without any canary fails.
- A **coverage canary** fails the run when the number of conformant or refused entries differs from `declared.conformant` / `declared.refused` in [docs/data/interop.json](docs/data/interop.json) — a silent regression cannot shrink the validated corpus.
- Level 1 is **never silently skipped**: absent OpenSSL prints the reason and exits 0 locally, but `PKINATIVE_INTEROP_REQUIRED=1` (set on every CI leg) and the gate's `--require-all` turn that skip into a failure.

Per file the validator reports `PASS` / `FAIL` / `XFAIL` / `XPASS` / `INFRA` / `SKIP`. Exit codes:

| Exit | Meaning |
|------|---------|
| 0 | Every expectation met — or OpenSSL is absent and level 1 was **skipped** with the reason (a skip is not a pass; the gate reports the step as **SKIP**, and `--require-all` turns it into a failure) |
| 1 | An expectation not met (`FAIL` or `XPASS`), no negative canary, or the coverage canary tripped |
| 2 | Infrastructure: corpus directory / manifest absent (run `corpus:pki` first), `dist/` missing, or OpenSSL installed but unusable |
| 3 | OpenSSL required (`PKINATIVE_INTEROP_REQUIRED=1`) but absent |

The vitest form of level 1 is `tests/interop/openssl.test.ts` (`npm run test:interop`); `tests/interop/lint.test.ts` (`npm run test:lint-certs`, the gate's `lint:certs` step, publish profile) runs the zlint and pkilint certificate linters over every certificate the corpus writes — a lint ERROR fixes the encoder, a WARNING or NOTICE is either fixed or waived with a reason in `scripts/data/lint-waivers.json` (none today); a stale waiver fails the test. `ZLINT` names the zlint binary and `PKILINT_PYTHON` the Python that imports `pkilint`; absent, the step skips with the reason (`REQUIRE_LINT=1` fails instead).

**CI is blocking**: the `ci` workflow runs the gate with `--require-all` and `PKINATIVE_INTEROP_REQUIRED=1` on Linux (Node 22 and 24), Windows and macOS; the `interop` workflow repeats the corpus on `ubuntu-22.04`, `ubuntu-24.04`, `windows-latest` and `macos-latest`, and `interop (ubuntu-24.04)` and `interop (windows-latest)` are required status checks; the publish workflow runs the whole `--publish --require-all` profile again before the package is published, installing zlint (pinned by the SHA-256 of its release archive) and pkilint (pinned by `--require-hashes`) when `scripts/data/lint-python-requirements.txt` is present. OpenSSL, zlint and pkilint are runner tools, never dependencies — the no-new-runtime-dependency policy is unchanged.

Installing OpenSSL 3 locally:

```bash
# Linux — the distribution package (openssl 3.x is the default on current releases)
openssl version            # must print "OpenSSL 3.x"

# macOS — the system /usr/bin/openssl is LibreSSL and is refused with the reason
brew install openssl@3
export OPENSSL_BIN="$(brew --prefix openssl@3)/bin/openssl"
```

```powershell
# Windows — an OpenSSL 3 build on PATH, or the one shipped with Git for Windows:
$env:OPENSSL_BIN = "C:\Program Files\Git\usr\bin\openssl.exe"
openssl version
```

## Documentation and the ecosystem manifest

`docs/assets/ecosystem.json` is the single source of every count and version quoted in the docs (`packages`, `declared`, `derived`, `assertions`). `npm run verify:docs` (`scripts/verify-docs.ts`) recomputes the derived counts from the source tree (the tool registry and the prompts, every wrapper code, `server.json`, `examples/`, `tests/`, the sample baseline, the corpus table, the vendored registries) and holds README, `docs/`, `llms.txt`, AGENTS.md, CLAUDE.md, the Copilot files, the changelog ladder, the rulesets, the workflows and the current release note to it: stale counts, stale versions, tool / error-code / operator-variable parity between `src/` and the docs, the registry mirrors under `docs/data/` byte-identical to `src/data/pkinative/`, the interop counts, Claude Code budgets and generated rules, the PR template, links and heading anchors, `Verified on` stamps, English-only prose — and **no secret material** (a fixture key body, a scalar or a password other than the documented `test-only-password` in any document fails the rule).

A line that legitimately quotes a superseded figure (release history) opts out with `verify-docs:allow <rule>` — an HTML comment at the end of that line, or on the line above when the line is a table row or a heading. The marker is for genuine history only, never to silence a stale current claim.

Touching a count or a version means editing the manifest **and** running `verify:docs`. `declared` holds the figures no filesystem walk can derive (measured at release); `derived` is recomputed and fails on drift.

## Agent contract

Two documents, two audiences:

- [AGENTS.md](AGENTS.md) — the **repository rules** for coding agents working *on* the server (mission and constraints, the gate, where is what, the four-step tool wiring, never-touch and generated files). It stays at 120 lines or fewer; [CLAUDE.md](CLAUDE.md) imports it and adds only what is specific to Claude Code; [.github/copilot-instructions.md](.github/copilot-instructions.md) carries the same conventions for Copilot. Keep the three consistent.
- [docs/AGENT_CONTRACT.md](docs/AGENT_CONTRACT.md) — the **consumer contract** for agents that *use* the server (tool catalogue, decision tree, token economy, error codes in §6). A tool input, output field or error-code change is a change to this contract and is reviewed under [docs/API_STABILITY.md](docs/API_STABILITY.md).

`.claude/rules/*.md` are generated from `.github/instructions/*.instructions.md` by `npm run agents:rules` (scoped by the source `applyTo`) and never edited by hand: edit the instruction file, regenerate, and `verify:docs` rule `claude-rules-sync` fails on drift. Agents never push, tag, open PRs or issues, or publish (`.github/AGENT_RULES.md`; enforced in Claude Code by `.claude/hooks/guard.mjs`); issue and PR drafts go to [.github/drafts/](.github/drafts/README.md) and a human submits them.

## Pull Request Checklist

The pull request template carries the same items, word for word (`verify:docs` rule `pr-template-parity` and `tests/tools/workflows.test.ts` hold the two together).

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
- [ ] For releases: follow [Release](#release) — `release-notes/vX.Y.Z.md` and `.github/drafts/pr-vX.Y.Z.md` written, and `npx tsx scripts/gate.ts --publish --require-all` passes locally, which runs every individual gate: `typecheck:all`, `lint`, `code-tables`, `build`, `dist-check`, `dist-probe`, `smoke`, `verify:tool-shape`, `server-json`, `test:generate`, `test:coverage`, `verify:docs`, `verify:samples`, `corpus:pki`, `validate:pki`, `interop`, `lint:certs`

## Release

A release is prepared on a `release/vX.Y.Z` branch by whoever drives it (a maintainer or an agent) and **merged, tagged and published by the maintainer only**:

1. `npx tsx scripts/release-prepare.ts --version X.Y.Z [--date YYYY-MM-DD] [--previous vA.B.C]` applies the mechanical bump in one pass — `package.json` / `package-lock.json`, `src/version.ts` (`PKINATIVE_MCP_VERSION`), `server.json` (twice), `docs/assets/ecosystem.json` (version + `verifiedOn`) and the `Verified on` stamps, `CITATION.cff`, the `SECURITY.md` support table, the README engine badge, `llms.txt` — and scaffolds `release-notes/vX.Y.Z.md` from [release-notes/TEMPLATE.md](release-notes/TEMPLATE.md) and `.github/drafts/pr-vX.Y.Z.md` from [release-notes/PR_TEMPLATE.md](release-notes/PR_TEMPLATE.md) (`--dry-run` previews; it never commits, tags or publishes). The version moves in lock-step (`tests/metadata.test.ts`).
2. Decide `TOOL_API_VERSION` (`src/version.ts`) under [docs/API_STABILITY.md](docs/API_STABILITY.md): it moves only when a tool schema, a wrapper code or a `PKI_*` mapping changes, which is a reviewed decision the script never takes.
3. Write the release note (the engine version shipped, the tool API version and the OpenSSL versions the corpus was validated with are named), mirror it into `CHANGELOG.md` (`## [X.Y.Z]` plus the compare link at the bottom — `verify:docs` rule `changelog-ladder` requires one per heading), update `ROADMAP.md`, and refresh every count the manifest governs (`declared.tests` and the coverage figures come from the last gate run, never from memory).
4. Every rebaseline of `tests/_fixtures/samples.sha256.json`, every output change and every new corpus entry is declared in the note's Upgrade section **before** publication.
5. `npx tsx scripts/gate.ts --publish --require-all` must pass locally with OpenSSL 3 on `PATH` (every step, no SKIP; `REQUIRE_LINT=1` when zlint and pkilint are installed); in Claude Code, `/release-audit release-notes/vX.Y.Z.md vA.B.C` runs the independent audit (two auditors, an adversarial verifier, an agent-autonomy pass, a GO / NO-GO ledger under `.audit/`) — fix what it confirms.
6. Fill every section of `.github/drafts/pr-vX.Y.Z.md`. The per-version bodies are committed — they are the auditable record of what each release claimed and what was run — and every figure in them comes from a command run on the branch. **Stop here.**
7. **Maintainer:** push the branch, open the PR with that body, wait for `ci (22)`, `ci (24)`, `os (windows-latest)`, `os (macos-latest)`, `sample-regression`, `interop (ubuntu-24.04)` and `interop (windows-latest)` (required by `.github/rulesets/main.json`), merge, tag `vX.Y.Z` on the merge commit, publish the GitHub Release with the note as body (title `vX.Y.Z - short description`), approve the `npm-publish` environment; `publish.yml` checks that the tag equals the package version, re-runs the publish gate with OpenSSL (and the certificate linters when their pinned requirements file is present), publishes with provenance through npm Trusted Publishing (OIDC, no long-lived token), and attaches the CycloneDX SBOM and the build-provenance attestation to the release. Afterwards: validate and publish `server.json` to the MCP registry (a manual, networked step — the gate validates `server.json` offline against the vendored schema), and update the `pkinative-mcp` entry of `docs/assets/ecosystem.json` in pkinative and pkinative-cli.

Rollback: never unpublish and never move a tag (`.github/rulesets/tags.json` makes release tags immutable) — cut a superseding patch release; within npm's 72 h window a truly broken version may be deprecated by the maintainer.

### Bumping the engine pin

Moving `pkinative` to a new release is adopting that release: every user-facing entry of its changelog must end up exercised through the server, or waived in writing. In the same change:

1. Read the engine's changelog entry; re-vendor the registries into `src/data/pkinative/` (`errors.json`, `reasons.json`, `diagnostics.json`, `limits.json`, `core-exports.json`) from the new tag, regenerate `code-tables.ts` (`node scripts/build-code-tables.mjs`) and mirror them under `docs/data/`. A new `PKI_*` code fails `tsc` in `src/pki-errors.ts` until it is classified; a new reason or diagnostic moves the counts in `docs/assets/ecosystem.json`.
2. A new runtime export gets a tool touchpoint or a written rationale in `describe_engine.unexposed` — `tests/coverage-matrix.test.ts` holds the ledger to the export list. A new diagnostic the fixtures can reach gets a trigger in `tests/diagnostics-inventory.test.ts`; a new engine option gets an example that sets it.
3. Re-run the corpus and the interop suite with the new engine; a canary that starts writing bytes (XPASS) or an artefact OpenSSL stops accepting is a blocker, not a rebaseline.
4. Regenerate the samples, declare any rebaseline in the release note (the engine pin never moves without one), and update `packages.pkinative` in `docs/assets/ecosystem.json`. A bump that adds no code is a patch of this server; one that adds a code, a reason or a diagnostic is a minor with docs updates and a `TOOL_API_VERSION` review.

### Branch protection

The rules for `main` are versioned in [.github/rulesets/main.json](.github/rulesets/main.json), GitHub's ruleset format: no deletion, no force-push, pull request required (single maintainer, so zero approvals — but every review thread resolved, stale reviews dismissed on push, merge or squash only), and the status checks `ci (22)`, `ci (24)`, `os (windows-latest)`, `os (macos-latest)`, `sample-regression`, `interop (ubuntu-24.04)` and `interop (windows-latest)` required and up to date with `main` — the gate on Linux (Node 22 and 24), Windows and macOS, the byte baseline, and the OpenSSL judge on the two platforms whose runner images carry it reliably. The Docs workflow and the other path-filtered or scheduled workflows are deliberately **not** required: a required check that never reports leaves a pull request stuck on "Expected — waiting for status to be reported". The repository Admin role may bypass the ruleset through a pull request only — never by pushing to `main` directly. Release tags are protected by [.github/rulesets/tags.json](.github/rulesets/tags.json) (`refs/tags/v*`: no deletion, no force-update, no update; creation stays with the maintainer). `verify:docs` (rule `ruleset-parity`) fails when a required check names no workflow job.

The JSON files are the committed copies; they take effect only once the maintainer imports them: Settings → Rules → Rulesets → New ruleset → Import a ruleset. Agents never import or edit a ruleset on GitHub (the Claude Code guard hook refuses every writing GitHub API call).

## Reporting bugs

Use [GitHub Issues](https://github.com/Nizoka/pkinative-mcp/issues) with:
- Reproduction steps (ideally a JSON-RPC payload sent to the stdio server) built from **TEST material only** — never a real private key, a real PKCS#12 file or a password.
- Expected vs. actual output (the `_meta.error` block verbatim, or the `reasons[]` of a verdict).
- Node version (`node -v`), OS, and `openssl version` when OpenSSL disagrees with the server.

An engine limit found through the server is drafted locally (`draft_governance_issue`, or a copy of [.github/drafts/TEMPLATE.md](.github/drafts/TEMPLATE.md)), checked with `npm run verify:issue`, and submitted upstream by a human.

## Security issues

**Do not open public issues for security problems.** See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions will be licensed under the [MIT License](LICENSE).
