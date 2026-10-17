# Drafts (Human-In-The-Loop staging area)

This directory is the **draft staging area** mandated by the AI-governance
contract ([.github/ai-governance.json](../ai-governance.json),
[.github/AGENT_RULES.md](../AGENT_RULES.md)).

AI agents — and the `draft_governance_issue` MCP tool — write proposed GitHub
issues and pull-request bodies here as local Markdown files. Nothing in this
repository (and nothing in the `pkinative-mcp` server, which has no network
code path at all) can submit these drafts automatically: **a human submits
everything**, under their own identity.

## What lives here

| File | What it is | How it is produced | How it is checked |
|---|---|---|---|
| `issue-*.md` | An issue draft — an upstream engine gap (`issue-pkinative-<topic>.md`) or a tracking issue | The `draft_governance_issue` tool, or a filled copy of [TEMPLATE.md](TEMPLATE.md) | `npm run verify:issue` |
| `pr-vX.Y.Z.md` | The body of a release pull request | Scaffolded by `scripts/release-prepare.ts` from [release-notes/PR_TEMPLATE.md](../../release-notes/PR_TEMPLATE.md), then filled on the release branch | `npm run verify:docs` (links and anchors of the current release's draft) |
| `TEMPLATE.md` | The issue-draft template | — | `npm run verify:docs` |

## Workflow — issue drafts

1. An agent (or the `draft_governance_issue` tool) produces `issue-<target>-<topic>.md` here
   plus a compliance report (zero new dependency confirmed, no secret, reproduction command and
   result, duplicate search, affected packages, identity reminder).
2. Validate it: `npm run verify:issue -- .github/drafts/issue-<target>-<topic>.md`
   (PowerShell swallows the bare `--`: `node scripts/verify-issue.mjs .github/drafts/issue-<target>-<topic>.md`).
   A draft that proposes a new runtime dependency, embeds a key or a password, or has no fenced
   reproduction block is refused.
3. **You** review it, then manually open the issue on GitHub under your own
   identity. You share responsibility for the content.

**Where it goes:** engine root causes (ASN.1 / X.509 / CMS / PKCS#12 parsing, verification,
the 22 `PkiLimits` bounds, a `PKI_*` code raised on a valid object) are
filed in [Nizoka/pkinative](https://github.com/Nizoka/pkinative/issues/new/choose);
wrapper behaviour (schemas, sandbox, output modes, transport, projections, caps)
in [Nizoka/pkinative-mcp](https://github.com/Nizoka/pkinative-mcp/issues/new/choose).
The tool's `targetRepo` input records the decision in the draft.

## Workflow — release PR drafts

1. `npx tsx scripts/release-prepare.ts --version X.Y.Z` scaffolds `pr-vX.Y.Z.md` (it never overwrites an existing draft).
2. Whoever prepares the release fills every section; every figure comes from a command run on the release branch
   ([CONTRIBUTING.md](../../CONTRIBUTING.md#release)) — the gate summary, the sample baseline, the OpenSSL corpus
   and the audit verdict under `.audit/<version>/`.
3. **The maintainer** pushes the branch, opens the pull request with that body, merges, tags and publishes
   (`.claude/hooks/guard.mjs` refuses `git push`, `gh pr create` and `gh release` from an agent shell).

Ad-hoc files in this directory are git-ignored so work-in-progress proposals never
leak into the repository history; this README, `TEMPLATE.md`, `issue-*.md` and `pr-*.md`
are the exceptions — the per-version PR bodies and the submitted issue drafts are committed
as the auditable record of what was proposed.
