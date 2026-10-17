/**
 * Tool: draft_governance_issue
 *
 * Produces a LOCAL, governance-compliant GitHub issue draft plus a structured
 * compliance report — and never submits anything. This is the MCP-native
 * embodiment of the pkinative AI-governance / Human-In-The-Loop (HITL) contract
 * (`.github/ai-governance.json`, `.github/AGENT_RULES.md`): the agent is a
 * DRAFTSMAN, the human is the only gate.
 *
 * Guarantees (by construction, not by policy alone):
 *   - No outbound network call. No GitHub API. No filesystem access outside the
 *     opt-in sandbox (`PKINATIVE_MCP_OUTPUT_DIR`) when `outputMode='file'`.
 *   - The assembled draft is validated against the zero-dependency +
 *     reproduction + no-secret policy; a violation throws `GOVERNANCE_VIOLATION`
 *     so the human must fix the draft before they submit it under their own identity.
 *   - An identity reminder and the human-gate statement are always included.
 */
import os from 'node:os';
import { z } from 'zod';

import { GovernanceError, ToolError } from '../errors.js';
import { HUMAN_GATE, IDENTITY_REMINDER, validateIssueMarkdown } from '../governance.js';
import { writeSandboxedText } from '../output.js';
import { PKINATIVE_MCP_VERSION } from '../version.js';
import { defineTool, WRITES } from './_definition.js';
import { parseInput } from './_shared.js';

export const DRAFT_GOVERNANCE_ISSUE_NAME = 'draft_governance_issue';

const ISSUE_TYPES = ['bug', 'feature', 'security', 'docs', 'performance'] as const;
type IssueType = (typeof ISSUE_TYPES)[number];
const TARGET_REPOS = ['pkinative-mcp', 'pkinative', 'pkinative-cli'] as const;

export const DRAFT_GOVERNANCE_ISSUE_INPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['title', 'summary', 'issueType', 'reproduction', 'expectedBehavior', 'duplicateSearchPerformed'],
    properties: {
        title: { type: 'string', minLength: 8, maxLength: 160, description: 'Concise issue title (imperative, no trailing period).' },
        summary: { type: 'string', minLength: 16, description: 'One or two paragraphs describing the problem or proposal. Never a private key or a password.' },
        issueType: { type: 'string', enum: [...ISSUE_TYPES], description: "Issue category: 'bug' | 'feature' | 'security' | 'docs' | 'performance'." },
        targetRepo: {
            type: 'string',
            enum: [...TARGET_REPOS],
            default: 'pkinative-mcp',
            description: "Destination repository label for the draft (documentation only — the server never contacts it). 'pkinative-mcp' (wrapper: schemas, sandbox, transport), 'pkinative' (engine: parsing, verification, limits, refusals) or 'pkinative-cli'.",
        },
        reproduction: {
            type: 'object',
            additionalProperties: false,
            required: ['command', 'result'],
            description: 'The minimal, locally-executed reproduction that justifies this issue (test material only).',
            properties: {
                command: { type: 'string', minLength: 1, description: 'The exact command or MCP tool call you ran.' },
                result: { type: 'string', minLength: 1, description: 'The observed failure, error, or regression.' },
            },
        },
        expectedBehavior: { type: 'string', minLength: 4, description: 'What you expected to happen instead.' },
        actualBehavior: { type: 'string', description: 'What actually happened (defaults to the reproduction result when omitted).' },
        affectedPackages: { type: 'array', maxItems: 16, default: ['pkinative-mcp'], items: { type: 'string', minLength: 1 }, description: 'Packages impacted by this issue (e.g. ["pkinative-mcp"], ["pkinative"]).' },
        duplicateSearchPerformed: { type: 'boolean', description: 'MUST be true: confirms you searched open AND closed issues/PRs for duplicates before drafting.' },
        outputMode: { type: 'string', enum: ['inline', 'file'], default: 'inline', description: "'inline' (default) returns the draft markdown in the response. 'file' additionally writes it to the sandbox (requires PKINATIVE_MCP_OUTPUT_DIR); outputPath must be a relative .md path." },
        outputPath: { type: 'string', description: "Relative .md path inside the sandbox (only when outputMode='file')." },
    },
} as const;

export const DRAFT_GOVERNANCE_ISSUE_OUTPUT_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    required: ['title', 'issueType', 'targetRepo', 'outputMode', 'sizeBytes', 'draftMarkdown', 'warnings', 'compliance'],
    description: 'A local, unsubmitted issue draft plus its compliance report. The server NEVER opens the issue — a human must review and submit it.',
    properties: {
        title: { type: 'string' },
        issueType: { type: 'string', enum: [...ISSUE_TYPES] },
        targetRepo: { type: 'string', enum: [...TARGET_REPOS] },
        outputMode: { type: 'string', enum: ['inline', 'file'] },
        filePath: { type: 'string', description: "Sandboxed absolute path (when outputMode='file')." },
        sizeBytes: { type: 'integer', minimum: 0 },
        draftMarkdown: { type: 'string', description: 'The full draft, ready for a human to review and submit.' },
        warnings: { type: 'array', items: { type: 'string' } },
        compliance: {
            type: 'object',
            additionalProperties: false,
            required: ['zeroDependencyConfirmed', 'noSecretConfirmed', 'reproductionCommand', 'reproductionResult', 'duplicateSearchPerformed', 'affectedPackages', 'identityReminderShown', 'humanGate', 'environment'],
            properties: {
                zeroDependencyConfirmed: { type: 'boolean' },
                noSecretConfirmed: { type: 'boolean' },
                reproductionCommand: { type: 'string' },
                reproductionResult: { type: 'string' },
                duplicateSearchPerformed: { type: 'boolean' },
                affectedPackages: { type: 'array', items: { type: 'string' } },
                identityReminderShown: { type: 'boolean' },
                humanGate: { type: 'string' },
                environment: {
                    type: 'object',
                    additionalProperties: false,
                    required: ['node', 'os', 'pkinativeMcp'],
                    properties: { node: { type: 'string' }, os: { type: 'string' }, pkinativeMcp: { type: 'string' } },
                },
            },
        },
    },
} as const;

const InputSchema = z.strictObject({
    title: z.string().min(8).max(160),
    summary: z.string().min(16),
    issueType: z.enum(ISSUE_TYPES),
    targetRepo: z.enum(TARGET_REPOS).default('pkinative-mcp'),
    reproduction: z.strictObject({ command: z.string().min(1), result: z.string().min(1) }),
    expectedBehavior: z.string().min(4),
    actualBehavior: z.string().optional(),
    affectedPackages: z.array(z.string().min(1)).max(16).default(['pkinative-mcp']),
    duplicateSearchPerformed: z.boolean(),
    outputMode: z.enum(['inline', 'file']).default('inline'),
    outputPath: z.string().optional(),
});

export interface ComplianceReport {
    readonly zeroDependencyConfirmed: boolean;
    readonly noSecretConfirmed: boolean;
    readonly reproductionCommand: string;
    readonly reproductionResult: string;
    readonly duplicateSearchPerformed: boolean;
    readonly affectedPackages: readonly string[];
    readonly identityReminderShown: boolean;
    readonly humanGate: string;
    readonly environment: { readonly node: string; readonly os: string; readonly pkinativeMcp: string };
}

export interface DraftGovernanceIssueResult {
    readonly title: string;
    readonly issueType: IssueType;
    readonly targetRepo: (typeof TARGET_REPOS)[number];
    readonly outputMode: 'inline' | 'file';
    readonly filePath?: string;
    readonly sizeBytes: number;
    readonly draftMarkdown: string;
    readonly warnings: readonly string[];
    readonly compliance: ComplianceReport;
}

function buildDraftMarkdown(input: z.infer<typeof InputSchema>, environment: ComplianceReport['environment']): string {
    const actual = input.actualBehavior ?? input.reproduction.result;
    return [
        `# ${input.title}`, '',
        `> **Type:** ${input.issueType} · **Target:** ${input.targetRepo}`, '',
        '## Summary', '', input.summary, '',
        '## Minimal reproduction', '', 'Command / tool call:', '', '```', input.reproduction.command, '```', '', 'Result:', '', '```', input.reproduction.result, '```', '',
        '## Expected behavior', '', input.expectedBehavior, '',
        '## Actual behavior', '', actual, '',
        '## Environment', '', `- Node: ${environment.node}`, `- OS: ${environment.os}`, `- pkinative-mcp: ${environment.pkinativeMcp}`, `- Affected packages: ${input.affectedPackages.join(', ')}`, '',
        '## Compliance', '',
        '- [x] Zero new runtime dependency proposed',
        '- [x] No private key, PKCS#12 file or password in this draft',
        `- [${input.duplicateSearchPerformed ? 'x' : ' '}] Searched open and closed issues/PRs for duplicates`,
        '- [x] Minimal reproduction executed locally',
        '- [x] Expected vs actual documented', '',
        '---', '', `> ${IDENTITY_REMINDER}`, '', `> ${HUMAN_GATE}`, '',
    ].join('\n');
}

export async function draftGovernanceIssue(rawInput: unknown): Promise<DraftGovernanceIssueResult> {
    const input = parseInput(InputSchema, rawInput);
    if (!input.duplicateSearchPerformed) {
        throw new GovernanceError('duplicateSearchPerformed must be true — search open AND closed issues/PRs for duplicates before drafting.');
    }
    if (input.outputMode === 'file' && input.outputPath === undefined) {
        throw new ToolError('MISSING_OUTPUT_PATH', "outputPath is required when outputMode='file'.", { remedy: 'outputPath' });
    }
    const environment: ComplianceReport['environment'] = { node: process.version, os: `${process.platform} ${os.release()}`, pkinativeMcp: PKINATIVE_MCP_VERSION };
    const draftMarkdown = buildDraftMarkdown(input, environment);
    const validation = validateIssueMarkdown(draftMarkdown);
    if (!validation.ok) {
        throw new GovernanceError(`Draft violates the AI-governance contract: ${validation.errors.join(' ')} Fix the draft before it can be reviewed for submission.`);
    }
    const compliance: ComplianceReport = {
        zeroDependencyConfirmed: true,
        noSecretConfirmed: true,
        reproductionCommand: input.reproduction.command,
        reproductionResult: input.reproduction.result,
        duplicateSearchPerformed: input.duplicateSearchPerformed,
        affectedPackages: input.affectedPackages,
        identityReminderShown: true,
        humanGate: HUMAN_GATE,
        environment,
    };
    const sizeBytes = Buffer.byteLength(draftMarkdown, 'utf8');
    const base = { title: input.title, issueType: input.issueType, targetRepo: input.targetRepo, sizeBytes, draftMarkdown, warnings: validation.warnings, compliance };
    if (input.outputMode === 'file') {
        const { filePath } = await writeSandboxedText(draftMarkdown, input.outputPath as string, ['.md']);
        return { ...base, outputMode: 'file', filePath };
    }
    return { ...base, outputMode: 'inline' };
}

export const DRAFT_GOVERNANCE_ISSUE_TOOL = defineTool<DraftGovernanceIssueResult>({
    name: DRAFT_GOVERNANCE_ISSUE_NAME,
    title: 'Draft a governance-compliant GitHub issue (HITL)',
    kind: 'governance',
    description:
        "Produce a LOCAL GitHub issue draft + compliance report for pkinative / pkinative-cli / pkinative-mcp and NEVER submit it — the agent drafts, a human reviews and files it under their own identity (Human-In-The-Loop contract, .github/AGENT_RULES.md). No GitHub write path and no network path exist in this server. The draft is checked against the zero-dependency + reproduction + no-secret policy; a violation (new runtime dependency, an embedded private key or password, missing reproduction, duplicateSearchPerformed:false) throws GOVERNANCE_VIOLATION. targetRepo 'pkinative' for engine behaviour (parsing, verification, limits, refusals), 'pkinative-cli' for the CLI, 'pkinative-mcp' for wrapper behaviour (schemas, sandbox, transport). Returns markdown inline (outputMode:'file' also writes a .md inside the sandbox). Use it only after reproducing a defect with TEST material. Present the draft AND the report to the user, then STOP.",
    inputSchema: DRAFT_GOVERNANCE_ISSUE_INPUT_SCHEMA,
    outputSchema: DRAFT_GOVERNANCE_ISSUE_OUTPUT_SCHEMA,
    annotations: WRITES,
    cacheable: false,
    examples: [
        { title: 'Draft an engine bug report (never submitted)', input: { title: 'parseCertificateList refuses a delta CRL with an empty revokedCertificates list', summary: 'A delta CRL (deltaCRLIndicator present) whose revokedCertificates SEQUENCE is absent is refused with PKI_X509_STRUCTURE_INVALID although RFC 5280 makes the field OPTIONAL.', issueType: 'bug', targetRepo: 'pkinative', reproduction: { command: 'inspect_crl { crl: { path: "fixtures/empty-delta.crl" } }', result: 'PKI_X509_STRUCTURE_INVALID at revokedCertificates' }, expectedBehavior: 'The delta CRL parses with entryCount 0.', affectedPackages: ['pkinative', 'pkinative-mcp'], duplicateSearchPerformed: true } },
    ],
    handler: draftGovernanceIssue,
    text: (r) => `${DRAFT_GOVERNANCE_ISSUE_NAME}: DRAFT ONLY — not submitted${r.outputMode === 'file' ? ` and written to ${r.filePath ?? ''}` : ''}. ${r.compliance.humanGate} Present the draft and compliance report below to the user; they must review and submit it themselves under their own GitHub identity.`,
});
