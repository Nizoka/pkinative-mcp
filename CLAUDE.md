@AGENTS.md

# Claude Code addendum

Everything in AGENTS.md applies. This file adds only what is specific to Claude Code sessions in this repository.

## Token discipline

- Run tests through `npx tsx scripts/gate.ts --fast` or `npx vitest run <file>` (the dot reporter is configured); never paste a full test run into context.
- Never Read `dist/`, `coverage/`, `test-output/`, `package-lock.json`, `node_modules/`, `tests/_fixtures/tool-shape*.json` or `tests/_fixtures/samples.sha256.json`.
  The deny list in `.claude/settings.json` applies to Read and, at best effort, to Grep/Glob — ask the built server (`tools/list`, `prompts/get`, `describe_engine`) instead of reading `dist/`.
- A tool's inputs are in `src/tools/<name>.ts`; a shared fragment (`pki-input`, `signer`, `trust`, `limits`, `parse-context`, `output`, …) is one Grep away in `src/*.ts`. `tools/list` is about 428 kB: project it, never print it.
- Read README.md, ROADMAP.md, docs/KNOWLEDGE_BASE.md and docs/AGENT_CONTRACT.md by section: `grep -n "^## "` first, then a line range. CHANGELOG.md: only the top entry.
- `.github/instructions/*.md` are the per-area rules: open the ONE matching the area you touch (table in AGENTS.md §Where is what).
- Sample regeneration: `npm run build && npm run test:generate` then `npx tsx scripts/verify-samples.ts`. Any `--update` (rebaseline) must be justified in the release note.
- Never push, never open PRs/issues/releases, never tag (HITL policy, hook-enforced). No `Co-Authored-By` trailers (`attribution.commit` is `""`).

## Gate

- `npx tsx scripts/gate.ts --fast` before proposing a commit; `npm run gate` is the CI profile; `--publish --require-all` on release branches only.
- `--only <step>` for one step, `--from <step>` to resume, `--json` for machine output; logs in `test-output/.gate/<step>.log` — open only the failing step's log, through the shell.
- When the gate exceeds the shell timeout, run it in the background and read the result with `--json`.
- OpenSSL 3 is the external judge (the role veraPDF plays in pdfnative-mcp): `validate:pki` and `interop` SKIP without it and fail under `--require-all`. There is no veraPDF here.

## Where to look first

1. `src/tools/_registry.ts` and `src/tools/_group-*.ts` — the catalogue in `tools/list` order; `src/server.ts` — prompts, instructions, the cache gate;
   `tests/_fixtures/tool-shape.json` — every pinned schema shape (read it by tool, never whole).
2. AGENTS.md §Where is what — the path → purpose → instruction-file table.
3. `docs/assets/ecosystem.json` — every count and version; `npm run verify:docs` enforces it.
4. `src/tools/describe-engine.ts` — the doctrine (`DOCTRINE`) and the deliberately unexposed exports; `src/wrapper-codes.ts` and `src/pki-errors.ts` — every code with its remedy.

## Secrets gotcha

The fixtures under `tests/fixtures/pki/` are public TEST-ONLY material (password `test-only-password`), but the discipline is the real one:
never print a key body, a scalar or a password in a result, a log line, a test name or a document. `assertResultClean` (tests/_pki-assert.ts)
and the needle table (tests/_secrets.ts) hold every key-bearing result; the gate's `dist-probe` step refuses a build that carries a needle.
Write such strings through Edit, never through `echo` or a heredoc.

## Stdout gotcha

On stdio, stdout IS the protocol: one stray `console.log` in `src/` corrupts every session (the gate's `smoke` step fails on any non-JSON-RPC line).
Log to stderr through the `[pkinative-mcp]` logger; every engine call runs with the diagnostics sink installed, so the engine's `console.warn` fallback never fires.
Always drive the **built** server (`node dist/cli.js`; harness: `tests/_mcp-harness.ts`, `tests/_agent-client.ts`), not just source tests, before claiming a change works.

## Windows session notes

- The session shell is PowerShell, with Git Bash as the Bash tool. PowerShell swallows `--` after `npm run` — call `npx tsx scripts/<name>.ts` directly.
- Multi-line `node -e` payloads and heredocs break on backticks, `$` and backslashes: write a script to the scratchpad and run it.
- OpenSSL: an OpenSSL 3.x build on `PATH` (the one shipped with Git for Windows works), or `OPENSSL_BIN` pointing at `openssl.exe`; `openssl version` must say OpenSSL 3.x — LibreSSL is refused with the reason.
- zlint / pkilint (publish profile only): `ZLINT` names the binary, `PKILINT_PYTHON` the Python that imports `pkilint`.
- `npm install` under npm 10.9 can fail with an arborist `edgesOut` error on a fresh resolution; `npx npm@11.19.1 install` works, `npm ci` is unaffected.
- vitest sometimes reports "no tests" right after a file write: run it again.

## Hooks and permissions in force

- `.claude/hooks/guard.mjs` (PreToolUse on Bash **and** PowerShell) denies `npm publish`/`unpublish`/`deprecate`/`dist-tag`, `gh pr|issue create|edit|close|comment`,
  `gh pr merge`, `gh release`, writing `gh api` and any `git push` — in every shell segment, `$( )`/backticks and `sh -c`/`pwsh -Command`/`node -e` payloads
  (a quoted string holding one is refused too: write such strings with Edit). The maintainer submits those — prepare, then stop. `tests/tools/guard.test.ts` is the contract.
- `permissions.deny` blocks Read on the generated bulk files above and the same write commands, for both shells;
  `permissions.allow` pre-approves `npm run`, `npx vitest`, `npx tsx scripts/*`, `npx tsc`, `npx eslint`, `node scripts/*`, `node -e` and read-only git. `node dist/cli.js` is asked each time.

## Plan mode, rules and skills

- Use plan mode for multi-file changes; plans name the files, the commands and the expected gate outcome. Run `/code-review` on the branch diff before drafting a PR body.
- `.claude/rules/*.md` are generated from `.github/instructions/*.instructions.md` by `npm run agents:rules` (scoped by `paths:` = the source `applyTo`).
  Never edit a rule: edit the instruction file, then regenerate (`verify:docs` rule `claude-rules-sync` fails on drift).
- `/release-audit [release-notes/vX.Y.Z.md] [previous-tag]` (`.claude/skills/release-audit/`) is the maintainer-invoked pre-release audit:
  two auditors, an adversarial verifier, an agent-autonomy pass and a GO/NO-GO ledger under `.audit/`.

## Release

Follow CONTRIBUTING.md §Release and `scripts/release-prepare.ts`: prepare everything (version lock-step, changelog, release note, manifest,
PR draft under `.github/drafts/`, `npx tsx scripts/gate.ts --publish --require-all`) and stop before pushing.
