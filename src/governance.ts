/**
 * AI-governance & Human-In-The-Loop (HITL) contract for pkinative-mcp.
 *
 * This module is the runtime-embedded, single source of truth for the
 * governance policy declared in `.github/ai-governance.json` and
 * `.github/AGENT_RULES.md`. It backs:
 *   - the `draft_governance_issue` tool (draft assembly + policy validation),
 *   - the `governance_contract` / `draft_issue_workflow` MCP prompts,
 *   - `tests/governance.test.ts` (which asserts alignment with the repo files
 *     and with `scripts/verify-issue.mjs`).
 *
 * CRITICAL: nothing here — and nothing anywhere in the server — can submit a
 * GitHub issue, comment, PR, or make any outbound network call, ever. This
 * server has no network code path at all. The agent is a DRAFTSMAN; the human
 * is the only gate.
 */

import { PKINATIVE_MCP_VERSION } from './version.js';

/** Result of validating a draft issue's markdown against the policy. */
export interface IssueValidationResult {
    readonly ok: boolean;
    readonly errors: readonly string[];
    readonly warnings: readonly string[];
}

/**
 * Patterns that indicate an external runtime dependency is being proposed.
 * Kept byte-identical to `scripts/verify-issue.mjs`.
 */
const DEPENDENCY_PATTERNS: readonly RegExp[] = [
    /\bnpm\s+(install|i|add)\s+(?!--)[a-z@]/i,
    /\b(yarn|pnpm|bun)\s+add\s+/i,
    /\bpnpm\s+install\s+[a-z@]/i,
    /add\s+[`"']?[\w@/-]+[`"']?\s+to\s+(the\s+)?(runtime\s+)?dependencies\b/i,
    /"dependencies"\s*:\s*\{[^}]*[\w-]+[^}]*\}/i,
];

/**
 * A draft that embeds a private key or a password is refused outright: an
 * issue publishes under the human's identity, on a public tracker.
 */
const SECRET_PATTERNS: readonly RegExp[] = [
    /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----/,
    /\bpassword\s*[:=]\s*["'][^"']{4,}["']/i,
];

/** Required issue fields (advisory — surfaced as warnings when missing). */
const REQUIRED_FIELDS: ReadonlyArray<{ readonly key: string; readonly re: RegExp }> = [
    { key: 'minimal_reproduction', re: /repro|reproduc/i },
    { key: 'environment', re: /environment|version|node|os\b/i },
    { key: 'expected_behavior', re: /expected/i },
];

/**
 * Validate the text of a draft issue against the zero-dependency +
 * reproduction + no-secret policy. Pure and filesystem-free so both the tool
 * and unit tests can use it.
 */
export function validateIssueMarkdown(content: string): IssueValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    for (const re of DEPENDENCY_PATTERNS) {
        if (re.test(content)) {
            errors.push('Proposing an external runtime dependency violates the zero-dependency policy.');
            break;
        }
    }

    for (const re of SECRET_PATTERNS) {
        if (re.test(content)) {
            errors.push('The draft embeds a private key or a password — strip the secret; a public issue must never carry one.');
            break;
        }
    }

    if (!/```[\s\S]*?```/.test(content)) {
        errors.push('No reproduction code block found — include a minimal repro inside a fenced ``` block.');
    }

    for (const field of REQUIRED_FIELDS) {
        if (!field.re.test(content)) {
            warnings.push(`Recommended field appears to be missing: ${field.key}.`);
        }
    }

    return { ok: errors.length === 0, errors, warnings };
}

/** The non-negotiable identity reminder shown with every draft. */
export const IDENTITY_REMINDER =
    'This draft, if submitted, is published under YOUR GitHub identity. You share ' +
    'responsibility for its content. Review it fully before you open the issue manually.';

/** The human-in-the-loop gate statement embedded in every compliance report. */
export const HUMAN_GATE =
    'DRAFT ONLY. The pkinative-mcp server never opens, edits, or submits GitHub ' +
    'issues, comments, PRs, or releases, and makes no outbound network call, ever ' +
    '(it has no network code path). A human MUST explicitly review this draft and submit it themselves.';

/**
 * Compact, agent-facing summary of the governance contract. Surfaced verbatim by
 * the `governance_contract` MCP prompt and echoed in server instructions.
 */
export const GOVERNANCE_CONTRACT_SUMMARY = `pkinative-mcp AI Governance & Human-In-The-Loop contract (v${PKINATIVE_MCP_VERSION})

ROLE: You are a DRAFTSMAN, never an autonomous submitter.

NON-NEGOTIABLE RULES
  1. Zero new runtime dependencies — never propose adding an external runtime npm package (pkinative, the MCP SDK and zod are the only three).
  2. No duplicates — search open AND closed issues/PRs before drafting.
  3. Local reproduction — run a minimal repro (tool call or Node/TS snippet) first.
  4. Byte-identity/schema awareness — keep default output byte-identical; keep JSON Schema + Zod aligned; a change to what create_certificate / create_csr / sign_cms write is the engine's semver contract.
  5. Security defaults are never weakened without a human — no network, no key export, SHA-1 opt-in, RSA scheme explicit, PBES2/PBMAC1 only, the 22 limits, the sandbox.
  6. No secret in a draft — never paste a private key, a PKCS#12 file or a password into an issue.
  7. Human-in-the-loop gate — produce a LOCAL draft only; a human reviews and submits.
  8. Identity integrity — remind the user the issue publishes under their GitHub identity.

THE SERVER ITSELF cannot write to GitHub and makes no outbound network call, ever — it has no network code path.
Engine root causes (ASN.1, X.509, CMS, PKCS#12 parsing, verification, limits) belong upstream in Nizoka/pkinative; CLI behaviour in Nizoka/pkinative-cli; wrapper issues (schemas, sandbox, transport) in Nizoka/pkinative-mcp.
Use the draft_governance_issue tool to produce a compliant local draft + compliance report,
then present both to the user and stop. The user is the only gate.`;

/**
 * Step-by-step HITL workflow. Surfaced by the `draft_issue_workflow` MCP prompt.
 */
export const DRAFT_ISSUE_WORKFLOW = `Human-In-The-Loop issue workflow for pkinative-mcp

1. Detect a bug or improvement while working locally.
2. Reproduce it: run a minimal MCP tool call or Node/TS snippet and capture the exact command + result (with TEST material only — never a real key or password).
3. Confirm zero new runtime dependency is required (a hard blocker otherwise).
4. Search existing open AND closed issues/PRs for duplicates.
5. Decide the target: engine behaviour (parsing, verification, limits, refusals) → 'pkinative'; CLI behaviour → 'pkinative-cli'; wrapper behaviour (schemas, sandbox, transport) → 'pkinative-mcp'.
6. Call draft_governance_issue with the title, summary, issueType, targetRepo, reproduction, expected vs actual, and affected packages.
7. Present the returned draft markdown AND the compliance report to the user.
8. STOP. The user reviews, then manually opens the issue on GitHub under their own identity.

The agent never submits. The server never touches GitHub and never touches the network.`;
