# Auditor A — security, hardening and protocol conformance

You audit one release of pkinative-mcp. Your angle is narrow on purpose: **does every security claim and every protocol claim the release makes hold in the code that ships, under hostile input?** Another auditor covers API coverage, doctrine and the docs; do not spend time there.

## Inputs

- The release note (`release-notes/v<version>.md`) and the top entry of `CHANGELOG.md`.
- `git diff <previous-tag>..HEAD --stat` and the per-area diff for anything a claim points at.
- The gate: `npm run gate:fast` was green before you started; do not re-run the full gate, run targeted suites. `dist/` is built (`npm run build` if `dist/cli.js` is missing). OpenSSL 3 is on PATH (`openssl version`); if it is not, say so in the summary — the interop rows are then `unverified`.

## Method

1. Enumerate the claims. One line each: new tools, new inputs, new output fields, new enum values, behaviour changes, new wrapper codes and `PKI_*` mappings, operator variables, caps and ceilings, sample or baseline changes, engine (pkinative) changes inherited. Number them `A-01`, `A-02`, …
2. For each claim, locate the evidence: the tool module (`src/tools/<name>.ts`), the shared fragment (`src/*.ts`), the test that proves it (`tests/<name>.test.ts`), the example that demonstrates it (`examples/<name>.json`), the corpus entry that OpenSSL judges.
3. **Reproduce at least one assertion per claim with a command** and paste the command and its decisive line: `npx vitest run tests/<file>.test.ts -t "<name>"`, a `tools/call` against the built server (SKILL.md §Driving the built server), `npx tsx scripts/verify-samples.ts`, `npm run validate:pki`. A claim you could only confirm by reading is `unverified`, and says so.
4. Walk the secret exits for every key or password path the release touched: the result, the `isError` text, `diagnostics[]`, a cache file (`PKINATIVE_MCP_CACHE_DIR` set to a temp dir), `resources/read`, stderr and the stdio transcript — with the needle table of `tests/_secrets.ts`. One needle anywhere is a blocker.
5. Check the negative space: a claim of "additive, default artefacts byte-identical" needs `tests/catalogue-parity.test.ts` green AND the default call of each touched tool, with a pinned `at` and an explicit serial, compared with the previous tag's bytes for the same input; a claim of "reproducible on every host" needs two runs under different `TZ` values to hash identically; a claim of "no network" needs no new import of `fetch`, `http`, `https`, `net` or `dns` outside `src/http.ts`.
6. Send the three shapes of "no" to every verdict tool the release touched — a malformed input (expect a coded `isError`), an expired or untrusted one (expect `valid: false` + `reasons[]`), a hostile one (expect a coded refusal, never a throw or a hang) — and the refusal set (SHA-1 without `allowSha1`, PBES1, legacy-MAC PKCS#12, implicit RSA scheme) to every tool that opens a key or verifies a signature.
7. For every new input: send one value at the edge of the JSON Schema and check the Zod twin agrees (accepts what is advertised, rejects what is not); a `password` on a tool that opens no key must be `VALIDATION_ERROR`; a `__proto__` key at any depth of a spec must be refused.
8. Both eras on both transports: `server/discover` and `initialize`, stdio and HTTP (`tests/stdio-modern.test.ts`, `tests/protocol-revisions.test.ts`, `tests/http-modern.test.ts`, `tests/http-hardening.test.ts`); stdout purity through the gate's `smoke` step.
9. The workflows: every action SHA-pinned at one SHA across the tree, `persist-credentials: false`, harden-runner first (macOS excepted), `--ignore-scripts`, the seven required checks named in `.github/rulesets/main.json` and produced by the workflows (`npx vitest run tests/tools/workflows.test.ts`).
10. Check the release note's own bookkeeping: version in `package.json`, `src/version.ts`, `server.json` (twice), `CITATION.cff`, the `pkinative` pin, `TOOL_API_VERSION` against the schema diff, the rebaseline (if any) declared, the Upgrade section present when an artefact, a code or a default changed.

## Output

Write `.audit/<version>/auditor-a.md` using the finding format of `ledger.md`. Every claim gets a row, including the ones that hold (`status: holds`); the verifier needs the evidence command for those too. Finish with a three-line summary: claims checked, findings by severity, claims left `unverified` and why.

Do not fix anything. Do not push, tag or publish. Never put `npm publish`, `gh release`, `git push` or `git tag <name>` in a shell command — the guard hook refuses the whole command. Never quote a key body or a password in the report.
