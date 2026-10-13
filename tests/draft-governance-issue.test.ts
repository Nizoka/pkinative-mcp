/**
 * Tests for `draft_governance_issue` — the MCP-native Human-In-The-Loop
 * embodiment of the pkinative AI-governance contract. These tests assert the
 * server acts strictly as a DRAFTSMAN: it produces a compliant local draft plus
 * a compliance report and NEVER submits anything — and never embeds a secret.
 */
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { draftGovernanceIssue } from '../src/tools/draft-governance-issue.js';
import { ToolError } from '../src/errors.js';
import { callToolDirect } from '../src/server.js';
import { PKINATIVE_MCP_VERSION } from '../src/version.js';
import { fixtureText, PASSWORD } from './_pki-fixtures.js';
import { assertResultClean } from './_pki-assert.js';

const ENV_KEY = 'PKINATIVE_MCP_OUTPUT_DIR';

const validInput = {
    title: 'parseCertificateList refuses a delta CRL with an empty revokedCertificates list',
    summary: 'A delta CRL whose revokedCertificates SEQUENCE is absent is refused although RFC 5280 makes the field OPTIONAL.',
    issueType: 'bug' as const,
    targetRepo: 'pkinative' as const,
    reproduction: { command: 'inspect_crl { crl: { path: "fixtures/empty-delta.crl" } }', result: 'PKI_X509_STRUCTURE_INVALID at revokedCertificates' },
    expectedBehavior: 'The delta CRL parses with entryCount 0.',
    affectedPackages: ['pkinative', 'pkinative-mcp'],
    duplicateSearchPerformed: true,
};

describe('draft_governance_issue', () => {
    beforeAll(() => {
        delete process.env[ENV_KEY];
    });
    afterEach(() => {
        delete process.env[ENV_KEY];
        vi.restoreAllMocks();
    });

    it('produces a compliant draft with a reproduction block and identity reminder', async () => {
        const result = await draftGovernanceIssue(validInput);
        expect(result.outputMode).toBe('inline');
        expect(result.draftMarkdown).toContain(`# ${validInput.title}`);
        expect(result.draftMarkdown).toContain('**Target:** pkinative');
        expect(/```[\s\S]*?```/.test(result.draftMarkdown)).toBe(true);
        expect(result.draftMarkdown).toMatch(/GitHub identity/i);
        expect(result.draftMarkdown).toMatch(/DRAFT ONLY/i);
        expect(result.draftMarkdown).toContain('No private key, PKCS#12 file or password in this draft');
        expect(result.sizeBytes).toBe(Buffer.byteLength(result.draftMarkdown, 'utf8'));
        expect(result.targetRepo).toBe('pkinative');
    });

    it('defaults targetRepo to pkinative-mcp and affectedPackages to [pkinative-mcp]; actualBehavior defaults to the reproduction result', async () => {
        const { targetRepo: _t, affectedPackages: _a, ...rest } = validInput;
        void _t;
        void _a;
        const result = await draftGovernanceIssue(rest);
        expect(result.targetRepo).toBe('pkinative-mcp');
        expect(result.compliance.affectedPackages).toEqual(['pkinative-mcp']);
        expect(result.draftMarkdown).toContain('## Actual behavior\n\nPKI_X509_STRUCTURE_INVALID at revokedCertificates');
        const explicit = await draftGovernanceIssue({ ...rest, actualBehavior: 'The parser stops at the list.' });
        expect(explicit.draftMarkdown).toContain('## Actual behavior\n\nThe parser stops at the list.');
    });

    it('returns a complete, honest compliance report', async () => {
        const { compliance } = await draftGovernanceIssue(validInput);
        expect(compliance.zeroDependencyConfirmed).toBe(true);
        expect(compliance.noSecretConfirmed).toBe(true);
        expect(compliance.duplicateSearchPerformed).toBe(true);
        expect(compliance.identityReminderShown).toBe(true);
        expect(compliance.reproductionCommand).toBe(validInput.reproduction.command);
        expect(compliance.reproductionResult).toBe(validInput.reproduction.result);
        expect(compliance.affectedPackages).toEqual(['pkinative', 'pkinative-mcp']);
        expect(compliance.humanGate).toMatch(/never opens/i);
        expect(compliance.environment.node).toBe(process.version);
        expect(compliance.environment.pkinativeMcp).toBe(PKINATIVE_MCP_VERSION);
        expect(typeof compliance.environment.os).toBe('string');
    });

    it('makes NO outbound network call (fetch is never invoked)', async () => {
        const fetchSpy = vi.spyOn(globalThis, 'fetch');
        await draftGovernanceIssue(validInput);
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('rejects a draft that proposes a runtime dependency with GOVERNANCE_VIOLATION', async () => {
        await expect(draftGovernanceIssue({ ...validInput, summary: 'We should run npm install node-forge to fix this quickly.' })).rejects.toMatchObject({ code: 'GOVERNANCE_VIOLATION' });
    });

    it('rejects a draft that embeds a private key or a password with GOVERNANCE_VIOLATION, never echoing it', async () => {
        const withKey = await draftGovernanceIssue({ ...validInput, summary: `Here is my key:\n${fixtureText('leaf.key.pem')}` }).catch((e: unknown) => e as ToolError);
        expect(withKey).toBeInstanceOf(ToolError);
        expect((withKey as ToolError).code).toBe('GOVERNANCE_VIOLATION');
        expect((withKey as ToolError).message).not.toContain(fixtureText('leaf.key.pem').split('\n')[1]);
        const withPassword = await draftGovernanceIssue({ ...validInput, reproduction: { command: `open_pkcs12 with password: "${PASSWORD}"`, result: 'x' } }).catch((e: unknown) => e as ToolError);
        expect((withPassword as ToolError).code).toBe('GOVERNANCE_VIOLATION');
        const wire = await callToolDirect('draft_governance_issue', { ...validInput, summary: `A summary holding the key ${fixtureText('leaf.key.pem')}` });
        expect(wire.isError).toBe(true);
        assertResultClean(wire);
    });

    it('rejects duplicateSearchPerformed=false with GOVERNANCE_VIOLATION', async () => {
        await expect(draftGovernanceIssue({ ...validInput, duplicateSearchPerformed: false })).rejects.toMatchObject({ code: 'GOVERNANCE_VIOLATION' });
    });

    it('rejects invalid input with VALIDATION_ERROR (short title, unknown type, unknown repo)', async () => {
        await expect(draftGovernanceIssue({ title: 'too short' })).rejects.toMatchObject({ code: 'VALIDATION_ERROR' });
        await expect(draftGovernanceIssue({ ...validInput, issueType: 'wish' })).rejects.toMatchObject({ code: 'VALIDATION_ERROR' });
        await expect(draftGovernanceIssue({ ...validInput, targetRepo: 'zipnative' })).rejects.toMatchObject({ code: 'VALIDATION_ERROR' });
    });

    it('an unknown key is refused through parseInput with the uniform "Invalid arguments:" wording', async () => {
        const err = await draftGovernanceIssue({ ...validInput, submit: true }).catch((e: unknown) => e as ToolError);
        expect(err).toBeInstanceOf(ToolError);
        expect((err as ToolError).code).toBe('VALIDATION_ERROR');
        expect((err as ToolError).message).toMatch(/^Invalid arguments: /);
        expect((err as ToolError).message).toContain('submit');
        const r = await callToolDirect('draft_governance_issue', { ...validInput, githubToken: 'ghp_never' });
        expect(r.isError).toBe(true);
        expect((r.content[0] as { text: string }).text).toMatch(/^draft_governance_issue failed \[VALIDATION_ERROR\]: Invalid arguments: /);
        expect((r.content[0] as { text: string }).text).not.toContain('ghp_never');
        await expect(draftGovernanceIssue(undefined)).rejects.toMatchObject({ code: 'VALIDATION_ERROR', message: expect.stringMatching(/^Invalid arguments: /) });
    });

    it("requires outputPath when outputMode='file' (MISSING_OUTPUT_PATH)", async () => {
        await expect(draftGovernanceIssue({ ...validInput, outputMode: 'file' })).rejects.toMatchObject({ code: 'MISSING_OUTPUT_PATH' });
    });

    it('writes a .md draft to the sandbox when outputMode=file, never overwriting', async () => {
        const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'pkinative-gov-'));
        process.env[ENV_KEY] = dir;
        const result = await draftGovernanceIssue({ ...validInput, outputMode: 'file', outputPath: 'drafts/issue.md' });
        expect(result.outputMode).toBe('file');
        expect(result.filePath).toBe(path.join(dir, 'drafts', 'issue.md'));
        expect(await fs.readFile(result.filePath as string, 'utf8')).toBe(result.draftMarkdown);
        await expect(draftGovernanceIssue({ ...validInput, outputMode: 'file', outputPath: 'drafts/issue.md' })).rejects.toMatchObject({ code: 'OUTPUT_EXISTS' });
        await expect(draftGovernanceIssue({ ...validInput, outputMode: 'file', outputPath: 'issue.txt' })).rejects.toMatchObject({ code: 'INVALID_EXTENSION' });
        await expect(draftGovernanceIssue({ ...validInput, outputMode: 'file', outputPath: '../escape.md' })).rejects.toMatchObject({ code: 'SECURITY_VIOLATION' });
        await fs.rm(dir, { recursive: true, force: true });
    });

    it('through the server: the result says DRAFT ONLY, carries the markdown twice (text + structured) and no resource', async () => {
        const r = await callToolDirect('draft_governance_issue', validInput);
        expect(r.isError).not.toBe(true);
        const texts = r.content.map((c) => (c as { type: string; text?: string }).text ?? '');
        expect(r.content.every((c) => c.type === 'text')).toBe(true);
        expect(texts[0]).toContain('DRAFT ONLY — not submitted');
        expect(texts[0]).toContain('under their own GitHub identity');
        expect(texts[1]).toBe((r.structuredContent as { draftMarkdown: string }).draftMarkdown);
        expect(r.structuredContent).toMatchObject({ title: validInput.title, issueType: 'bug', targetRepo: 'pkinative', outputMode: 'inline' });
        const violation = await callToolDirect('draft_governance_issue', { ...validInput, duplicateSearchPerformed: false });
        expect(violation.isError).toBe(true);
        expect((violation._meta as { error: { code: string } }).error.code).toBe('GOVERNANCE_VIOLATION');
    });
});
