# AI Governance & Human-In-The-Loop (HITL)

> How an AI agent may propose bugs and improvements for the pkinative project
> **without ever writing to GitHub**. The agent is a **draftsman**; a human is the
> only gate that submits.

This guide is the narrative companion to the machine-readable contract in
[`.github/ai-governance.json`](../../.github/ai-governance.json) and the
agent-and-human protocol in [`.github/AGENT_RULES.md`](../../.github/AGENT_RULES.md).
It is surfaced to agents through the `draft_governance_issue` **tool** and two MCP
**prompts**, `governance_contract` and `draft_issue_workflow` (prompts are read with
`prompts/get`, not called with `tools/call`).

Two audiences, two rule files: an agent that **uses** the server reads the consumer
contract, [docs/AGENT_CONTRACT.md](../AGENT_CONTRACT.md) (tool catalogue, decision tree,
token economy, the error codes in §6 — `GOVERNANCE_VIOLATION` among them); an agent that
works **on** the repository reads [AGENTS.md](../../AGENTS.md), the repository rule file.
The human-in-the-loop rule below binds both.

---

## 1. The one rule

**The pkinative-mcp server contains no code path that can write to GitHub, and makes
no outbound network call, ever.** It cannot open an issue, comment, PR, or release. It
produces a **local draft** plus a **compliance report** and stops. A human must review the
draft and submit it themselves, under their own GitHub identity.

This is a guarantee **by construction**, not merely by policy: there is no GitHub SDK
anywhere in the server, and there is **no network code path at all** — no CRL, OCSP, AIA
or TSA fetch, no telemetry, no URL taken from any tool argument, no operator-configurable
endpoint. The only filesystem boundary is the opt-in sandbox `PKINATIVE_MCP_OUTPUT_DIR`;
`describe_engine.network` is always `'none'`. Where the sibling PDF server makes an
exception for operator-configured time-stamp and revocation endpoints, this server makes
none: revocation evidence and time-stamp tokens are inputs the caller carries.

---

## 2. Why this exists

The pkinative project has two hard, non-negotiable properties that an
autonomously-filing agent would routinely break:

- **No new runtime dependencies.** The pkinative engine has zero; pkinative-mcp carries
  exactly three (pkinative, the MCP SDK, zod) and adds none. A well-meaning agent that
  "fixes" a bug by proposing `npm install some-lib` violates the core philosophy.
- **Signal over noise.** Auto-filed, unreproduced, or duplicate issues erode the tracker
  for human maintainers — and in a PKI project an issue that embeds a private key or a
  password is a leak published under the user's name.

Keeping a human in the loop preserves both, while still letting agents do the valuable
up-front work: reproduce, categorise, choose the right repository, and draft a
high-quality issue.

---

## 3. The contract (eight non-negotiable rules)

The `governance_contract` prompt returns these eight rules verbatim; `.github/AGENT_RULES.md`
spells out the mandatory pre-issue rules behind them (its rule 8 is the human-in-the-loop
gate the Claude Code guard hook enforces).

1. **No new runtime dependencies** — never propose adding an external runtime npm package
   beyond the three the server already has. (Enforced: a draft that suggests
   `npm install <pkg>`, a `yarn/pnpm/bun add`, or edits `"dependencies"` is rejected with
   `GOVERNANCE_VIOLATION`.)
2. **No duplicates** — search **open AND closed** issues/PRs before drafting.
   (`duplicateSearchPerformed` must be `true`.)
3. **Local reproduction** — run a minimal repro (an MCP tool call or a Node/TS snippet)
   first and capture the exact command + result, with **TEST material only**. (Enforced:
   the draft must contain a fenced ```` ``` ```` reproduction block.)
4. **Byte-identity / schema awareness** — keep default output byte-identical and keep the
   JSON Schema aligned with the Zod schema; a change to the bytes `create_certificate` /
   `create_csr` / `sign_cms` write with a deterministic key is the engine's semver contract
   and semver-major here.
5. **Security defaults are never weakened without a human** — no network, no key export,
   SHA-1 opt-in, RSA scheme explicit, PBES2 / PBMAC1 only, the 22 limits, the sandbox.
6. **No secret in a draft** — never paste a private key, a PKCS#12 file or a password into
   an issue. (Enforced: a `-----BEGIN … PRIVATE KEY-----` block or a `password: "…"` pair is
   rejected with `GOVERNANCE_VIOLATION`.)
7. **Human-in-the-loop gate** — produce a **local** draft only; a human reviews and
   submits.
8. **Identity integrity** — remind the user that the issue publishes under **their**
   GitHub identity and that they share responsibility for its content.

Where it goes (`targetRepo`): engine root causes — ASN.1 / PEM / X.509 / CRL / OCSP / CMS /
PKCS#12 parsing, verification, the 22 `PkiLimits`, a `PKI_*` code raised on a valid object
— belong upstream in `Nizoka/pkinative`; command-line behaviour in `Nizoka/pkinative-cli`;
wrapper behaviour — schemas, sandbox, output modes, transport, projections, caps, the
secrets policy — in `Nizoka/pkinative-mcp`. The label is documentation: the server never
contacts any of them.

---

## 4. The workflow

```
1. Detect a bug or improvement while working locally.
2. Reproduce it: run a minimal MCP tool call or Node/TS snippet and capture the exact command + result
   (with TEST material only — never a real key or password).
3. Confirm zero new runtime dependency is required (a hard blocker otherwise).
4. Search existing open AND closed issues/PRs for duplicates.
5. Decide the target: engine behaviour → 'pkinative'; CLI behaviour → 'pkinative-cli'; wrapper behaviour → 'pkinative-mcp'.
6. Call draft_governance_issue with the title, summary, issueType, targetRepo, reproduction, expected vs actual, and affected packages.
7. Present the returned draft markdown AND the compliance report to the user.
8. STOP. The user reviews, then manually opens the issue on GitHub under their own identity.
```

The `draft_issue_workflow` MCP prompt returns exactly these steps.

---

## 5. Using the `draft_governance_issue` tool

Minimal call — the shipped example [`examples/draft-governance-issue.json`](../../examples/draft-governance-issue.json),
drafting an engine report for the pkinative repository:

```json
{
  "title": "parseCertificateList refuses a delta CRL with an empty revokedCertificates list",
  "summary": "A delta CRL (deltaCRLIndicator present) whose revokedCertificates SEQUENCE is absent is refused with PKI_X509_STRUCTURE_INVALID although RFC 5280 makes the field OPTIONAL.",
  "issueType": "bug",
  "targetRepo": "pkinative",
  "reproduction": {
    "command": "inspect_crl { crl: { path: \"fixtures/empty-delta.crl\" } }",
    "result": "PKI_X509_STRUCTURE_INVALID at revokedCertificates"
  },
  "expectedBehavior": "The delta CRL parses with entryCount 0.",
  "affectedPackages": ["pkinative", "pkinative-mcp"],
  "duplicateSearchPerformed": true
}
```

Required inputs: `title` (8–160 characters), `summary` (≥ 16), `issueType` (`bug` | `feature`
| `security` | `docs` | `performance`), `reproduction { command, result }`, `expectedBehavior`,
`duplicateSearchPerformed`. Optional inputs:

| Field | Default | Notes |
|-------|---------|-------|
| `targetRepo` | `pkinative-mcp` | Documentation label only — the server never contacts it. `pkinative` (engine), `pkinative-cli`, `pkinative-mcp` (wrapper). |
| `actualBehavior` | the reproduction result | What actually happened. |
| `affectedPackages` | `['pkinative-mcp']` | Impacted packages (≤ 16). |
| `outputMode` | `inline` | `file` also writes the draft `.md` into `PKINATIVE_MCP_OUTPUT_DIR`. |
| `outputPath` | — | Relative `.md` path inside the sandbox (only when `outputMode: 'file'`; never overwritten). |

### What you get back

- `draftMarkdown` — the full issue, ready for a human to review and paste into GitHub
  (also delivered as the second text block of the result).
- `compliance` — a structured report the agent MUST present alongside the draft, exactly
  nine keys: `zeroDependencyConfirmed`, `noSecretConfirmed`, `reproductionCommand`,
  `reproductionResult`, `duplicateSearchPerformed`, `affectedPackages`,
  `identityReminderShown`, `humanGate` (the gate statement, carried verbatim) and the
  captured `environment` (`node`, `os`, `pkinativeMcp`). The snake_case names shared with
  the engine and the CLI are listed in `.github/ai-governance.json`
  (`cross_project_vocabulary`).
- `warnings` — advisory notes (e.g. a recommended field appears to be missing:
  `minimal_reproduction`, `environment`, `expected_behavior`).

### When it refuses (`GOVERNANCE_VIOLATION`)

The draft is rejected before you can submit it if it:

- proposes an external runtime dependency,
- embeds a private key or a password,
- omits a reproduction code block, or
- sets `duplicateSearchPerformed: false`.

Fix the draft and call again. This keeps the human from ever submitting a
contract-breaking issue — or a leaking one.

---

## 6. Verifying a draft on disk

When `outputMode: 'file'` is used, the draft `.md` lands in the sandbox; copy it to
[`.github/drafts/`](../../.github/drafts/README.md) (git-ignored work in progress, except the
README, the template and the curated release artefacts `pr-*.md` / `issue-*.md`). A human
(or CI) can re-check it with the same policy the tool applied:

```bash
npm run verify:issue -- .github/drafts/<draft>.md
# PowerShell swallows a bare `--` after `npm run`: call the script directly there
node scripts/verify-issue.mjs .github/drafts/<draft>.md
```

`scripts/verify-issue.mjs` mirrors `validateIssueMarkdown()` in
[`src/governance.ts`](../../src/governance.ts) — the dependency patterns, the secret
patterns and the reproduction-block rule — so the CLI and the tool never disagree;
`tests/governance.test.ts` asserts that alignment. Exit 0 on pass, 1 on a policy
violation, 2 on usage. A passing check is **necessary but not sufficient** — the human
review gate always applies, and no CI job runs the verifier over `.github/drafts/`.

---

## 7. Enforcement for agents working on the repository

The server cannot write to GitHub by construction (§1). A **coding agent** working in a
clone has a shell, so there the rule is enforced mechanically rather than by trust. The
facts are recorded in `capability_manifest` of
[`.github/ai-governance.json`](../../.github/ai-governance.json):

- **Committed settings** — `.claude/settings.json`: no commit attribution, `Read` denied
  on generated and bulk files (`dist/`, `coverage/`, `test-output/`, `package-lock.json`,
  `node_modules/`, the tool-shape and sample fixtures), and the human-in-the-loop commands
  denied for both shells (Bash and PowerShell): `npm publish` / `unpublish` / `deprecate` /
  `dist-tag`, every `git push`, `gh pr create` / `edit` / `close` / `merge` / `comment`,
  `gh issue create` / `edit` / `close` / `comment`, `gh release *`, writing `gh api` calls.
- **A fail-closed guard hook** — `.claude/hooks/guard.mjs` runs before every **Bash and
  PowerShell** command and refuses publishing to npm, creating / editing / closing /
  merging / commenting on PRs and issues, releases, writing GitHub API calls, any push,
  tag creation and the line-ending renormalisation commit — in the whole command, every
  shell segment, command substitutions and nested `-c` / `-Command` / `-e` payloads. It
  fails closed on input it cannot read; `tests/tools/guard.test.ts` is its contract.
- **Generated rules** — `.claude/rules/*.md` are projected from
  `.github/instructions/*.instructions.md` by `npm run agents:rules`, each scoped to the
  paths of its source; they are never edited by hand, and `npm run verify:docs` fails
  on drift (`claude-rules-sync`).
- **A maintainer-invoked release audit** — the `release-audit` skill
  (`.claude/skills/release-audit/`: two parallel auditors, an adversarial verifier, an
  agent-autonomy pass, a GO / NO-GO ledger under `.audit/<version>/`) runs the pre-release
  audit. It is `disable-model-invocation: true`: it cannot be invoked by the agent on its own
  initiative, and it publishes nothing.
- **Git hooks** — `npm run hooks:install` sets `core.hooksPath` to `.githooks/`: lint and a
  CRLF check on commit, the fast gate on push.

The division of labour is the same as for issues: the agent prepares — the version bump
(`npm run release:prepare`), the changelog, the release note, the PR draft under
`.github/drafts/`, a green `npx tsx scripts/gate.ts --publish --require-all` — and
**stops**. The maintainer pushes, opens the PR, tags and publishes
(`.github/workflows/publish.yml`: OIDC Trusted Publishing, SBOM, attestation).

---

## 8. What the server will never do

- Open, edit, comment on, or close a GitHub issue or PR.
- Trigger a release.
- Make any outbound network request, or emit telemetry — there is no code path for either.
- Fetch a CRL, an OCSP response or a time-stamp token; generate or export a key; write a
  PKCS#8, PKCS#12, CRL, OCSP response or time-stamp response (the doctrine of
  `describe_engine.refusals`).
- Persist your draft anywhere except the opt-in `PKINATIVE_MCP_OUTPUT_DIR` sandbox
  when you explicitly ask for `outputMode: 'file'`.

The agent drafts. The human decides. That is the whole contract.
