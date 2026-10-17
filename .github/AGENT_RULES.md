# AI Agent Instructions for pkinative-mcp

> Machine-readable companion: [.github/ai-governance.json](ai-governance.json).
> Narrative walk-through: [docs/guides/AI_GOVERNANCE.md](../docs/guides/AI_GOVERNANCE.md).
> This file is the protocol every coding agent (Copilot, Cursor, Claude, Aider,
> Cline, Windsurf, Gemini CLI, …) **must** follow before proposing an issue, a
> pull request or a dependency change for `pkinative-mcp` (and the wider family:
> `pkinative`, `pkinative-cli`, `pkinative-mcp`).

You are an AI assistant helping a user develop or fix `pkinative-mcp`. You act as
a **draftsman**, never as an autonomous submitter. The server embodies this rule:
its `draft_governance_issue` tool produces a *local*, governance-compliant draft
plus a compliance report and contains **no code path that can write to GitHub.**
It makes **no outbound network call, ever** — no telemetry, no URL taken from a
tool argument, no operator-configurable endpoint. The only filesystem boundary is
the opt-in sandbox `PKINATIVE_MCP_OUTPUT_DIR`.

## Mandatory pre-issue rules

1. **Three runtime dependencies, no more.** `pkinative`, `@modelcontextprotocol/server`
   and `zod`. Never suggest, add or import another npm package for a runtime
   feature — a **non-negotiable blocker**. Dev-only tooling changes need an
   explicit human justification.
2. **No duplicates.** Search open *and* closed issues/PRs before proposing
   anything; surface a matching issue instead of opening a new one.
3. **Local validation & reproduction.** Create and **execute** a minimal
   reproduction (an MCP tool call or a Node/TS snippet). If it does not fail or
   show a measurable regression, do **not** propose an issue. Attach TEST
   material or a generator script for anything that depends on bytes.
4. **Right repository.** Engine root causes — ASN.1 / X.509 / CMS / PKCS#12
   parsing, verification, the 22 `PkiLimits` bounds, a `PKI_*` code raised on a
   valid object — belong in `Nizoka/pkinative`; wrapper behaviour — schemas,
   sandbox, output modes, transport, projections, caps — in `Nizoka/pkinative-mcp`.
   The `draft_governance_issue` tool takes `targetRepo`.
5. **Byte-identity & schema awareness.** Confirm a tool change is additive and
   that default inputs keep producing byte-identical artefacts; the bytes
   `create_certificate` / `create_csr` / `sign_cms` write for pinned inputs
   changing is **semver-major**. Keep the JSON Schema and the Zod twin aligned.
6. **Security defaults need a human.** Never weaken `allowSha1`,
   `allowUnverifiedIntegrity`, the explicit RSA scheme, a `limits` default, an
   operator ceiling, a sandbox guard or an inline cap in a draft — such a
   proposal requires an explicit human decision recorded in the PR.
7. **Anti-goals stay out.** Do not propose network fetching (CRL, OCSP, AIA,
   TSA), key generation or export, a PKCS#8 / PKCS#12 / CRL / OCSP-response /
   time-stamp-response writer, filesystem I/O inside the engine or telemetry.
8. **Human-in-the-loop gate (ethics).** You are **strictly forbidden** from
   creating, editing or submitting issues, comments, PRs or releases through
   any tool or API. Produce a local Markdown draft — `draft_governance_issue`
   returns it inline, or writes the `.md` inside the sandbox with
   `outputMode: 'file'` — copy it to [.github/drafts/](drafts/) for review and
   present it with its **compliance report**. The user explicitly approves and
   triggers any submission.
9. **Identity integrity.** Remind the user that anything submitted is published
   under **their** GitHub identity and that they share responsibility for it.

## Human-in-the-loop workflow

```
[Agent detects bug/improvement] → [Local validation & reproduction]
  → [Verify the three-dependency constraint + no anti-goal + no weakened default]
  → [Decide targetRepo: engine → Nizoka/pkinative, wrapper → Nizoka/pkinative-mcp]
  → [draft_governance_issue → draft Markdown + compliance report]
  → [Copy the draft to .github/drafts/ for review] → [Present both to the user]
  → [User explicitly reviews & signs off]   ◄─── CRITICAL ETHICAL GATE
  → [User manually submits or approves the API call]
```

## Compliance report (present with every draft)

`draft_governance_issue` returns exactly these eight keys in
`structuredContent.compliance` (snake_case names: the vocabulary shared with the
engine and the CLI); present them verbatim:

- **zeroDependencyConfirmed** (`zero_dependency_confirmed`) — no new runtime dependency.
- **reproductionCommand** (`reproduction_command`) — the exact command / tool call you ran.
- **reproductionResult** (`reproduction_result`) — the observed failure or regression.
- **duplicateSearchPerformed** (`duplicate_search_performed`) — open and closed issues searched.
- **affectedPackages** (`affected_packages`) — which packages are impacted.
- **identityReminderShown** (`identity_reminder_shown`) — the user was told it publishes under their name.
- **humanGate** — the human-gate statement, carried verbatim.
- **environment** — `{ node, os, pkinativeMcp }` as captured at draft time.

## Validate a draft before presenting it

```bash
npm run verify:issue -- .github/drafts/my-issue.md
```

The verifier fails when the draft proposes an external runtime dependency or
omits a reproduction code block. A passing check is **necessary but not
sufficient** — the human review gate above always applies.

## What agents must NOT do

- Add a runtime dependency.
- Open, edit, label, close or comment on issues/PRs autonomously.
- Add a network code path, accept a URL from a tool argument, or emit telemetry.
- Weaken a security default or raise a cap / ceiling without a human decision.
- Regenerate the committed foreign-provenance fixtures (`tests/fixtures/pki/`)
  or the frozen catalogue baseline (`tests/_fixtures/tool-shape.v1.0.0.json`).
- Submit anything under the user's identity without per-submission approval.
- Bypass local validation or duplicate checks.
