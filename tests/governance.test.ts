/**
 * Tests for the AI-governance contract module and its alignment with the repo's
 * governance artifacts (.github/ai-governance.json, scripts/verify-issue.mjs).
 */
import { describe, it, expect } from 'vitest';
import { existsSync, promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';

import {
    validateIssueMarkdown,
    GOVERNANCE_CONTRACT_SUMMARY,
    DRAFT_ISSUE_WORKFLOW,
    IDENTITY_REMINDER,
    HUMAN_GATE,
} from '../src/governance.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(ROOT, 'scripts', 'verify-issue.mjs');
const GOVERNANCE_JSON = path.join(ROOT, '.github', 'ai-governance.json');
const AGENT_RULES = path.join(ROOT, '.github', 'AGENT_RULES.md');
const DRAFTS_README = path.join(ROOT, '.github', 'drafts', 'README.md');

/** Run the shipped CLI verifier on a draft and return its exit code (0 pass, 1 fail). */
async function runCliExitCode(draft: string): Promise<number> {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'pkinative-verify-'));
    const file = path.join(dir, 'draft.md');
    await fs.writeFile(file, draft, 'utf8');
    try {
        execFileSync(process.execPath, [CLI, file], { stdio: 'pipe' });
        return 0;
    } catch (err) {
        return (err as { status?: number }).status ?? 1;
    }
}

const GOOD_DRAFT = `# Something broke

## Reproduction
\`\`\`
node repro.mjs
\`\`\`
Environment: node v22, os windows.
Expected: it should work.
`;

const DEPENDENCY_DRAFT = `# Add a dependency

Please run npm install left-pad to fix this.

\`\`\`
repro here
\`\`\`
Expected + environment + node.
`;

const NO_REPRO_DRAFT = `# No repro provided

Expected behavior described but no fenced code block. environment node.
`;

describe('validateIssueMarkdown', () => {
    it('passes a well-formed draft', () => {
        const r = validateIssueMarkdown(GOOD_DRAFT);
        expect(r.ok).toBe(true);
        expect(r.errors).toHaveLength(0);
    });

    it('rejects a draft proposing a runtime dependency', () => {
        const r = validateIssueMarkdown(DEPENDENCY_DRAFT);
        expect(r.ok).toBe(false);
        expect(r.errors.join(' ')).toMatch(/dependency/i);
    });

    it('rejects every dependency-proposal spelling the CLI verifier knows', () => {
        for (const line of ['yarn add fflate', 'pnpm add jszip', 'bun add adm-zip', 'pnpm install yauzl', 'add `yazl` to the runtime dependencies', '"dependencies": { "fflate": "^0.8" }']) {
            expect(validateIssueMarkdown(`# t\n\n${line}\n\n\`\`\`\nrepro\n\`\`\`\n`).ok, line).toBe(false);
        }
        // Flags after `npm install` are not a package proposal.
        expect(validateIssueMarkdown('# t\n\nnpm install --ignore-scripts\n\n```\nrepro\n```\n').ok).toBe(true);
    });

    it('rejects a draft with no reproduction code block', () => {
        const r = validateIssueMarkdown(NO_REPRO_DRAFT);
        expect(r.ok).toBe(false);
        expect(r.errors.join(' ')).toMatch(/reproduction/i);
    });

    it('warns (advisory) when recommended fields are missing', () => {
        const r = validateIssueMarkdown('# Title\n\n```\nrepro\n```\n');
        expect(r.ok).toBe(true);
        expect(r.warnings.length).toBeGreaterThan(0);
    });

    it('stays aligned with the shipped CLI verifier (scripts/verify-issue.mjs)', async () => {
        expect(existsSync(CLI)).toBe(true);
        for (const draft of [GOOD_DRAFT, DEPENDENCY_DRAFT, NO_REPRO_DRAFT, '# x\n\n```\ny\n```\n']) {
            const module = validateIssueMarkdown(draft);
            const cliExit = await runCliExitCode(draft);
            expect(cliExit === 0).toBe(module.ok);
        }
    });

    it('keeps the dependency patterns byte-identical to scripts/verify-issue.mjs', async () => {
        const cli = await fs.readFile(CLI, 'utf8');
        const module = await fs.readFile(path.join(ROOT, 'src', 'governance.ts'), 'utf8');
        const patternsOf = (text: string): string[] => {
            const block = /DEPENDENCY_PATTERNS[^=]*=\s*\[([\s\S]*?)\];/.exec(text)?.[1] ?? '';
            return [...block.matchAll(/\/(?:\\.|[^/\n])+\/[a-z]*/g)].map((m) => m[0]);
        };
        const fromCli = patternsOf(cli);
        expect(fromCli.length).toBeGreaterThanOrEqual(5);
        expect(patternsOf(module)).toEqual(fromCli);
    });
});

describe('governance constants', () => {
    it('A-015: GOVERNANCE_CONTRACT_SUMMARY quotes the package version from src/version.ts (no hand-written version string)', async () => {
        const { PKINATIVE_MCP_VERSION } = await import('../src/version.js');
        expect(GOVERNANCE_CONTRACT_SUMMARY).toContain(`contract (v${PKINATIVE_MCP_VERSION})`);
        const source = await fs.readFile(path.join(ROOT, 'src', 'governance.ts'), 'utf8');
        expect(source).toContain('${PKINATIVE_MCP_VERSION}');
        expect(source).not.toMatch(/\(v\d+\.\d+\.\d+\)/);
    });

    it('surface the draftsman role, the human gate and the no-network guarantee', () => {
        expect(GOVERNANCE_CONTRACT_SUMMARY).toMatch(/DRAFTSMAN/);
        expect(GOVERNANCE_CONTRACT_SUMMARY).toMatch(/no outbound network call, ever/);
        expect(GOVERNANCE_CONTRACT_SUMMARY).toContain('Nizoka/pkinative');
        expect(GOVERNANCE_CONTRACT_SUMMARY).toContain('Nizoka/pkinative-mcp');
        expect(DRAFT_ISSUE_WORKFLOW).toMatch(/never submits/i);
        expect(DRAFT_ISSUE_WORKFLOW).toContain("'pkinative'");
        expect(DRAFT_ISSUE_WORKFLOW).toContain("'pkinative-mcp'");
        expect(IDENTITY_REMINDER).toMatch(/GitHub identity/i);
        expect(HUMAN_GATE).toMatch(/never opens/i);
        expect(HUMAN_GATE).toMatch(/no network code path/);
    });
});

describe('repo governance artifacts', () => {
    it.skipIf(!existsSync(GOVERNANCE_JSON))('.github/ai-governance.json encodes the non-negotiable HITL policy and the no-network posture', async () => {
        const raw = await fs.readFile(GOVERNANCE_JSON, 'utf8');
        const contract = JSON.parse(raw) as {
            policy: Record<string, unknown>;
            human_in_the_loop: Record<string, unknown>;
        };
        expect(contract.policy['autonomous_github_writes_allowed']).toBe(false);
        expect(contract.policy['runtime_dependencies_allowed']).toBe(false);
        expect(contract.human_in_the_loop['role_of_agent']).toBe('draftsman');
        if ('automatic_issue_reporting' in contract.policy) expect(contract.policy['automatic_issue_reporting']).toBe(false);
        if ('human_in_the_loop_mandatory' in contract.policy) expect(contract.policy['human_in_the_loop_mandatory']).toBe(true);
        // This server has no network code path at all: the policy must never allow egress.
        if ('outbound_network_allowed' in contract.policy) expect(contract.policy['outbound_network_allowed']).toBe(false);
        const net = contract.policy['outbound_network'] as Record<string, unknown> | undefined;
        if (net !== undefined) {
            expect(net['default']).toBe('none');
            expect(net['github']).toBe('never');
            expect(net['telemetry']).toBe('never');
        }
    });

    it.skipIf(!existsSync(AGENT_RULES))('ships the AGENT_RULES.md protocol', async () => {
        const rules = await fs.readFile(AGENT_RULES, 'utf8');
        expect(rules).toMatch(/draftsman/i);
        expect(rules).toMatch(/human-in-the-loop/i);
    });

    it.skipIf(!existsSync(DRAFTS_README))('ships a drafts staging area', async () => {
        const draftsReadme = await fs.readFile(DRAFTS_README, 'utf8');
        expect(draftsReadme).toMatch(/staging area/i);
    });
});
