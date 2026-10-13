<!--
Thank you for contributing to pkinative-mcp. Describe the change, then walk
the checklist. The items mirror CONTRIBUTING.md §Pull Request Checklist word
for word; keep the two in step when you change either (verify:docs rule
pr-template-parity and tests/tools/workflows.test.ts both check it).
-->

## What and why

<!-- One paragraph: what changes, why, and which issue it closes (`Closes #…`). -->

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
- [ ] For releases: follow [Release](../CONTRIBUTING.md#release) — `release-notes/vX.Y.Z.md` and `.github/drafts/pr-vX.Y.Z.md` written, and `npx tsx scripts/gate.ts --publish --require-all` passes locally, which runs every individual gate: `typecheck:all`, `lint`, `code-tables`, `build`, `dist-check`, `dist-probe`, `smoke`, `verify:tool-shape`, `server-json`, `test:generate`, `test:coverage`, `verify:docs`, `verify:samples`, `corpus:pki`, `validate:pki`, `interop`, `lint:certs`

<!--
Runtime changes also need a ROADMAP.md entry and a line in the next
release-notes/vX.Y.Z.md; a tool input, output field or error-code change is a
change to the agent contract (docs/AGENT_CONTRACT.md, docs/API_STABILITY.md)
and is called out there. A default artefact's bytes changing for the same
deterministic inputs is semver-major (.github/AGENT_RULES.md rule 5). Pull
requests, tags and releases are submitted by the maintainer, never by an
agent (.github/AGENT_RULES.md rule 8).
-->
