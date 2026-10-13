# Issue Drafts (Human-In-The-Loop staging area)

This directory is the **draft staging area** mandated by the AI-governance
contract ([.github/ai-governance.json](../ai-governance.json),
[.github/AGENT_RULES.md](../AGENT_RULES.md)).

AI agents — and the `draft_governance_issue` MCP tool — write proposed GitHub
issues here as local Markdown files (start from [TEMPLATE.md](TEMPLATE.md)).
Nothing in this repository (and nothing in the `pkinative-mcp` server, which has
no network code path at all) can submit these drafts automatically.

**Workflow:**

1. An agent (or the `draft_governance_issue` tool) produces `something.md` here
   plus a compliance report.
2. Validate it: `npm run verify:issue -- .github/drafts/something.md`
3. **You** review it, then manually open the issue on GitHub under your own
   identity. You share responsibility for the content.

**Where it goes:** engine root causes (ASN.1 / X.509 / CMS / PKCS#12 parsing, verification,
the 22 `PkiLimits` bounds, a `PKI_*` code raised on a valid object) are
filed in [Nizoka/pkinative](https://github.com/Nizoka/pkinative/issues/new/choose);
wrapper behaviour (schemas, sandbox, output modes, transport, projections, caps)
in [Nizoka/pkinative-mcp](https://github.com/Nizoka/pkinative-mcp/issues/new/choose).
The tool's `targetRepo` input records the decision in the draft.

Draft files are intentionally git-ignored (except this README and TEMPLATE.md;
curated release artifacts `pr-*.md` / `issue-*.md` stay tracked) so
work-in-progress proposals never leak into the repository history.
