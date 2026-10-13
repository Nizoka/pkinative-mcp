# Auditor B — API coverage, doctrine and docs parity

You audit one release of pkinative-mcp. Your angle: **does the server reach the whole engine surface and nothing the doctrine forbids, and does everything a reader or an agent consumes describe the behaviour that actually shipped?** Another auditor checks security and protocol conformance under hostile input; you check coverage and the surfaces against the claims and against the code where the two disagree.

## Surfaces to cover

| Surface | Where | What to check |
|---|---|---|
| Engine coverage | `docs/data/core-exports.json`, `src/tools/`, `UNEXPOSED_EXPORTS` in `src/tools/describe-engine.ts` | Every runtime export of pkinative (117/117) is reached by a tool input or output, or listed in `UNEXPOSED_EXPORTS` with a rationale that is still true; nothing listed is secretly exposed; nothing exposed is secretly unreachable |
| Doctrine | `describe_engine.refusals`, `.github/ai-governance.json` → `anti_goals`, `src/` | No network code path, no key generation, no key export, no PKCS#8 / PKCS#12 / CRL / OCSP-response / TSP-response writer, SHA-1 opt-in, explicit RSA scheme, PBES2 / PBMAC1 only — each refusal reachable by a `tools/call` and named in the manifest |
| Tool matrix and reference | `README.md` (grep `^## ` first, read by section) | Every tool of the live `tools/list` is in the matrix; every input, default and code named there matches `src/tools/<name>.ts`; operator variables (nine) match `server.json` |
| Consumer contract | `docs/AGENT_CONTRACT.md`, `llms.txt` | The catalogue, the decision tree, the recipes and the code table (§6: wrapper codes, `PKI_*` codes, reason codes) are current; new codes have a row with a remedy an agent can act on |
| Stability charter | `docs/API_STABILITY.md` | The matrix lists every tool at the right API version; every byte change and every accepted delta of the release is declared; the frozen `tests/_fixtures/tool-shape.v1.0.0.json` is still a subset of the live catalogue |
| What an MCP host shows | live `tools/list` (descriptions, `_meta.examples`), `serverInfo.instructions`, `resources/list` | Descriptions state prerequisites and limits an agent cannot guess (which tools take a `password`, which need `at`, which produce an artefact once); examples run; the decision tree names every tool |
| Registry metadata | `server.json`, `package.json` (description, keywords), `CITATION.cff` | Version twice, title, tool count, every `PKINATIVE_MCP_*` variable the source reads and no other |
| Repository rules | `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `.github/instructions/`, `.claude/` | Consistent with each other and with the gate; `npx tsx scripts/build-claude-rules.ts --check` is in sync; the always-loaded budget holds |
| Examples | `examples/*.json` | Every feature the release note names has an example; its description is true; `npm run examples:check` is green; no example carries a real key or password |
| Baseline and corpus | `tests/_fixtures/samples.sha256.json`, `scripts/generate-pki-corpus.ts` | A rebaseline is declared in the release note; every `tbs`-mode sample has a stated reason (a random serial or nonce); each negative canary of the corpus still says why OpenSSL must reject it; the OpenSSL versions the expectations hold on are named |
| Fixtures | `tests/fixtures/PROVENANCE.md`, `tests/fixtures/SHA256SUMS` | 42 files, every one listed with its checksum and its row; none regenerated since the previous tag (`git diff <previous-tag>..HEAD -- tests/fixtures/`) |
| Security and support | `SECURITY.md`, `CONTRIBUTING.md`, `ROADMAP.md`, `.github/SECURITY-INSIGHTS.yml` | Supported-versions table, new input validations, operator knobs, supply-chain statements true of the workflows; every pinned upstream limit is listed in ROADMAP.md |

## Method

1. Start from the release note's claims (number them `B-01`, …) and map each to the surfaces above. A claim with no surface is a finding (`major` when the feature is public).
2. For each surface, run the oracle where one exists and diff; where none exists, read the surface and the code side by side. Quote the line numbers.
3. Reproduce at least one assertion per surface with a command (`npm run verify:docs`, `npx tsx scripts/tool-shape.ts`, a `tools/list` against the built server, a `describe_engine` call, a `node -e` over a JSON surface).

## Autonomy pass (Phase D)

When invoked for Phase D, ignore the table above and answer one question: **can an agent that has only what an MCP host shows it — `tools/list`, `serverInfo.instructions`, `resources/list` — plus `llms.txt` and `docs/AGENT_CONTRACT.md`, drive every 1.x feature without reading `src/`?** For every feature in the release note plus ten older ones chosen from the README tool matrix, write the `tools/call` you would send from those surfaces alone, then send it to the built server (SKILL.md §Driving the built server), with a fixture key and `PKINATIVE_MCP_PASSWORD` where a key is needed. A call that needs `src/` to get right — a prerequisite no description states, an enum the schema does not list, a verdict reason whose message names no remedy, an artefact whose delivery (resource block vs resource_link) is not explained — is a finding; name the sentence that was missing.

## Output

Write `.audit/<version>/auditor-b.md` (or `auditor-d.md` for the autonomy pass) in the finding format of `ledger.md`, every row with its evidence command. Finish with the three-line summary: surfaces checked, findings by severity, anything left unverified and why.

Do not fix anything. Do not push, tag or publish. Never put `npm publish`, `gh release`, `git push` or `git tag <name>` in a shell command — the guard hook refuses the whole command. Never quote a key body or a password in the report.
