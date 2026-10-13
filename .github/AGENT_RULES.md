# AI Agent Instructions for pkinative-mcp

> Machine-readable companion: [.github/ai-governance.json](ai-governance.json).
> Narrative walk-through: [docs/guides/AI_GOVERNANCE.md](../docs/guides/AI_GOVERNANCE.md).
> This file is the human-and-agent-readable protocol every coding agent
> (Copilot, Cursor, Claude, Antigravity, Aider, Cline, Windsurf, Gemini CLI, …)
> **must** follow before proposing an issue, pull request, or dependency change
> for `pkinative-mcp` (and the wider `pkinative` family: `pkinative`,
> `pkinative-cli`, `pkinative-mcp`).

You are an AI assistant helping a user develop or fix `pkinative-mcp`. You act as
a **draftsman**, never as an autonomous submitter. The server itself embodies
this rule: it exposes a `draft_governance_issue` tool that produces a *local*,
governance-compliant draft plus a compliance report — and contains **no code
path that can write to GitHub.** It makes **no outbound network call, ever**:
there is no network code path in this server — no telemetry, no GitHub, no
URL taken from any tool argument, no operator-configurable endpoint. The only
filesystem boundary is the opt-in sandbox `PKINATIVE_MCP_OUTPUT_DIR`.

## Mandatory pre-issue rules

1. **Zero runtime dependencies.** Never suggest, add, or import an external npm
   package for a runtime feature. `pkinative-mcp` ships only `pkinative`, the MCP
   SDK (`@modelcontextprotocol/server`), and `zod`. Zero-additional-dependency is
   a **non-negotiable blocker** for any enhancement request. Dev-only tooling
   changes require explicit human justification.
2. **No duplicates.** Search open *and* closed issues/PRs before proposing
   anything. If a matching or overlapping issue exists, surface it instead of
   opening a new one.
3. **Local validation & reproduction.** Create and **execute** a minimal
   reproduction (an MCP tool call or a Node/TS snippet) locally. If it does not
   throw, fail, or show a measurable output/behaviour regression, do **not**
   propose an issue. Attach TEST material or a generator script for anything that
   depends on bytes.
4. **Right repository.** Engine root causes — ASN.1 / X.509 / CMS / PKCS#12 parsing, verification,
   the 22 `PkiLimits` bounds, verification, a `PKI_*` code raised on a valid
   object — belong upstream in `Nizoka/pkinative`; wrapper behaviour — schemas,
   sandbox, output modes, transport, projections, caps — belongs in
   `Nizoka/pkinative-mcp`. The `draft_governance_issue` tool takes `targetRepo`.
5. **Byte-identity & schema awareness.** For changes touching a tool, confirm the
   change is additive and that default inputs keep producing byte-identical
   artefacts; the bytes create_certificate / create_csr / sign_cms write with a deterministic key changing is
   **semver-major**. Keep the hand-written JSON Schema and the Zod schema
   aligned. Report any intentional byte/schema changes.
6. **Security defaults need a human.** Never weaken `rejectTraversal`,
   `rejectSymlinks`, `onDuplicate`, any `limits` default, the operator ceilings,
   the sandbox guards or the inline caps in a draft — a proposal to do so
   requires an explicit human decision recorded in the PR.
7. **Anti-goals stay out.** Do not propose encryption / decryption, other
   network fetching, key generation or export, PKCS#8 / PKCS#12 / CRL writers, filesystem I/O inside
   the engine, or any network capability.
8. **Human-in-the-loop gate (ethics).** You are **strictly forbidden** from
   automatically creating, editing, or submitting issues, comments, PRs, or
   releases via any tool or API. Produce a local markdown draft — the
   `draft_governance_issue` tool returns it inline, and with `outputMode: 'file'`
   writes the `.md` inside the `PKINATIVE_MCP_OUTPUT_DIR` sandbox (it never writes
   anywhere else) — copy it to [.github/drafts/](drafts/) for review, and present
   it to the user together with a **compliance report**. The user must explicitly
   approve and trigger any submission.
9. **Identity integrity.** Remind the user that anything submitted is published
   under **their** GitHub identity and that they share responsibility for the
   content.

## Human-in-the-loop workflow

```
[Agent detects bug/improvement]
            │
            ▼
 [Local validation & reproduction]
            │
            ▼
[Verify zero-dependency constraint + no anti-goal + no weakened default]
            │
            ▼
 [Decide targetRepo: engine → Nizoka/pkinative, wrapper → Nizoka/pkinative-mcp]
            │
            ▼
 [draft_governance_issue → draft markdown (inline, or a .md in the sandbox) + compliance report]
            │
            ▼
 [Copy the draft to .github/drafts/ for review]
            │
            ▼
[Present draft + compliance report to user]
            │
            ▼
 [User explicitly reviews & signs off]   ◄─── CRITICAL ETHICAL GATE
            │
            ▼
 [User manually submits or approves the API call]
```

## Compliance report (present with every draft)

The `draft_governance_issue` tool returns exactly these eight keys in
`structuredContent.compliance` (the snake_case names in parentheses are the
cross-project vocabulary shared with the engine and the CLI); present them verbatim:

- **zeroDependencyConfirmed** (`zero_dependency_confirmed`) — no new runtime dependency introduced.
- **reproductionCommand** (`reproduction_command`) — the exact command / tool call you ran.
- **reproductionResult** (`reproduction_result`) — the observed failure/regression.
- **duplicateSearchPerformed** (`duplicate_search_performed`) — you searched open and closed issues.
- **affectedPackages** (`affected_packages`) — which packages are impacted.
- **identityReminderShown** (`identity_reminder_shown`) — you told the user it publishes under their name.
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
- Open, edit, label, close, or comment on issues/PRs autonomously.
- Add any network code path to the server, accept a URL from a tool argument,
  or emit telemetry.
- Weaken a security default or raise a cap / ceiling without a human decision.
- Regenerate or modify committed foreign-provenance fixtures
  (`tests/fixtures/interop/`) or the frozen catalogue baseline
  (`tests/_fixtures/tool-shape.v1.0.0.json`).
- Submit anything under the user's identity without explicit, per-submission
  human approval.
- Bypass local validation or duplicate checks.
