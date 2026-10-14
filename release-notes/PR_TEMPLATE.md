# Release Pull Request Template

The body of a release pull request. `npx tsx scripts/release-prepare.ts --version X.Y.Z` scaffolds
`.github/drafts/pr-vX.Y.Z.md` from the block below (same mechanism as [TEMPLATE.md](TEMPLATE.md): it resolves
`vX.Y.Z`, `X.Y.Z`, the previous tag `vX.Y.Z-1` and `YYYY-MM-DD`, and unescapes the inner code fences). Whoever
prepares the release fills every section; the maintainer pastes the result into the GitHub pull request verbatim.
The per-version bodies are committed (the `pr-*.md` exception of `.gitignore`): they are the auditable record of
what each release claimed and what was run.

Every figure quoted in the body comes from a command run on the release branch — the gate summary, `npm run test:coverage`,
`npm run verify:samples`, `npm run validate:pki`, `npx tsx scripts/tool-shape.ts --check` — never from memory.
`<…>` marks what to fill in.

```markdown
# release: vX.Y.Z — <headline>

> **Branch:** `release/vX.Y.Z` → `main`
> **Type:** <Major | Minor | Patch> release (<additive, fully backward-compatible with vX.Y.Z-1 | breaking: …>)
> **pkinative pin:** `^A.B.C` → `^D.E.F` (or "unchanged")
> **Prepared:** YYYY-MM-DD — release note: `release-notes/vX.Y.Z.md`

## Summary

<Two or three paragraphs: what the release does for a user of an MCP host, what it does for an agent calling the
tools, what the repository adopted. Name the engine version and every ROADMAP item delivered.>

Counts (`docs/assets/ecosystem.json`): <N> tools, <N> prompts, <N> wrapper codes, <N> operator variables
<unchanged | X → Y>; examples <X → Y>; samples in the baseline <X → Y>; conformance corpus <X → Y> entries;
tests <X → Y> across <N> files.

## What changed

### Engine surface (`src/tools/`, shared fragments in `src/*.ts`)
- <One bullet per input, enum value, output field, wrapper code or `PKI_*` mapping added — with the tools that carry it.>

### Server (`src/server.ts`, transports, prompts, resources)
- <Registry, instructions, prompts, handlers, operator variables, cache gate.>

### Tooling (`scripts/`)
- <Gate steps, generators, validators, verifiers added or changed.>

### CI / repository (`.github/`, root)
- <Workflows, rulesets, templates, dotfiles, package.json, server.json.>

### Agent layer
- <AGENTS.md / CLAUDE.md / `.claude/`, `docs/AGENT_CONTRACT.md`, instruction files, prompts.>

### Tests, examples and samples
- <New suites, new `examples/*.json`, new corpus entries, new baseline entries, new fixtures (never regenerated in place).>

### Documentation
- <README, docs/, llms.txt, SECURITY, CONTRIBUTING, ROADMAP, CHANGELOG, CITATION, the release note.>

## Verification

What actually ran on the release branch (<OS>, Node <version>, OpenSSL <version>):

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | <N passed, 0 skipped in N s — the summary line as printed> |
| `npm run test:coverage` — tests | <N / N passing across N files> |
| `npm run test:coverage` — coverage | <S % statements / B % branches / F % functions / L % lines (thresholds S / B / F / L)> |
| `npm run build && npm run test:generate && npm run verify:samples` | <N samples match the baseline (N byte-exact, N tbs, N semantic)> |
| `npm run corpus:pki && npm run validate:pki` | <N PASS, N XFAIL, 0 FAIL, 0 XPASS — OpenSSL version> |
| `npm run test:interop` | <N passed — OpenSSL version> |
| `npx tsx scripts/tool-shape.ts --check` | <tools/list N bytes, instructions N bytes, matches the pinned shape> |
| `npm run verify:docs` | <N rules, 0 errors, 0 skipped> |
| `npm audit --audit-level=high` | <clean> |
| Built server over stdio (`node dist/cli.js`) | <handshake, tools/list count, server version, stdout carries JSON-RPC frames only> |

Independent audit: `/release-audit release-notes/vX.Y.Z.md vX.Y.Z-1` — <PENDING | the ledger: tally per severity, every
confirmed finding with its fix commit, every waiver with its reason>.

## API stability

- `TOOL_API_VERSION`: <`A.B.C` → `X.Y.Z` because … | unchanged because no schema, no wrapper code and no `PKI_*` mapping changed> (docs/API_STABILITY.md).
- Superset gate: the live catalogue is still a superset of the frozen `tests/_fixtures/tool-shape.v1.0.0.json` —
  no tool, property or enum value removed, no new `required`, no tighter bound.
- Accepted deltas: <every widening (a new optional input, a new enum value, a widened bound), or "none">.
- `tests/_fixtures/tool-shape.json`: <refreshed deliberately with `npx tsx scripts/tool-shape.ts --write` — what moved | unchanged>.
- Error codes: <new wrapper codes and the only calls that can return them | unchanged>; documented in `docs/AGENT_CONTRACT.md` §6.

## Output changes and rebaseline

- Default artefacts of existing tools: <byte-identical | the list of what changed and why the previous output was wrong>.
- Bytes inherited from the engine: <which artefacts change, which stay identical>.
- `tests/_fixtures/samples.sha256.json`: <N entries re-anchored at X.Y.Z with `npx tsx scripts/verify-samples.ts --update`, N new, N unchanged — reason in the manifest's `provenance` note | not rebaselined>.
- Every item above is declared in the Upgrade section of `release-notes/vX.Y.Z.md`.

## Out of scope (tracked in ROADMAP.md)

- <Upstream-blocked items (each pinned by an `it.fails` test, each with its draft under `.github/drafts/`) and deferred work, with the ROADMAP entry.>

## Maintainer steps after merge

Agents stop at this draft; everything below is done by the maintainer (`.github/AGENT_RULES.md` rule 8).

1. Push the branch, open the pull request with this body, wait for `ci (22)`, `ci (24)`, `os (windows-latest)`, `os (macos-latest)`, `sample-regression`, `interop (ubuntu-24.04)` and `interop (windows-latest)`, merge.
2. Tag `vX.Y.Z` on the merge commit and publish the GitHub Release (title `vX.Y.Z - <short description>`, body = `release-notes/vX.Y.Z.md`).
3. Approve the `npm-publish` environment: `publish.yml` re-runs the publish gate and publishes through npm Trusted Publishing, then attaches the SBOM and the attestation to the release. Confirm with `npm view pkinative-mcp version`.
4. Validate and publish `server.json` to the MCP registry.
5. Import or update the rulesets (`.github/rulesets/main.json`, `.github/rulesets/tags.json`) if they changed — CONTRIBUTING §Branch protection.
6. Update the `pkinative-mcp` entry of `docs/assets/ecosystem.json` in the sibling repositories (pkinative, pkinative-cli).
7. <Submit the upstream issue drafts under `.github/drafts/issue-*.md`, if any.>

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
```

## Conventions

- Keep the section order; omit nothing — write "none" or "unchanged" where a section has no entry, so a reader sees it was considered.
- The Verification table quotes results as printed; a command that was not run is marked "not run", never guessed.
- The checklist carries the items of [.github/pull_request_template.md](../.github/pull_request_template.md) (the one link of that template is dropped here, because a pull request body has no stable base path), plus three release items.
- English everywhere; no `Co-Authored-By` trailer and no mention of an AI assistant.
