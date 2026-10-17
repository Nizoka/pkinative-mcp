/**
 * Tests for `check_certificate_purpose` — names, OIDs and `any`, the issuer
 * restriction, the explicit-purpose rule, negative verdicts without
 * isError, projection, path inputs, every code.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { ToolError } from '../src/errors.js';
import { callToolDirect } from '../src/server.js';
import { checkCertificatePurpose, checkCertificatePurposeSummary, CHECK_CERTIFICATE_PURPOSE_TOOL } from '../src/tools/check-certificate-purpose.js';
import { codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureInput } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const leaf = (): Record<string, unknown> => ({ certificate: fixtureInput('leaf.crt.pem') });

describe('check_certificate_purpose', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('verdicts', () => {
        it('the leaf serves TLS (name, OID and any), under its issuer', async () => {
            const r = await checkCertificatePurpose({ ...leaf(), chain: [fixtureInput('inter.crt.pem')], purpose: 'serverAuth' });
            expect(r).toMatchObject({ valid: true, reasons: [], purpose: 'serverAuth', purposeOid: '1.3.6.1.5.5.7.3.1', purposeName: 'serverAuth', pathLength: 2 });
            expect(r.subject).toContain('CN=example.test');
            expect(r.diagnostics).toEqual([]);
            expect((await checkCertificatePurpose({ ...leaf(), purpose: '1.3.6.1.5.5.7.3.4' })).valid).toBe(true);
            expect((await checkCertificatePurpose({ ...leaf(), purpose: 'clientAuth' })).valid).toBe(true);
            const root = await checkCertificatePurpose({ certificate: fixtureInput('root.crt.pem'), purpose: 'any' });
            expect(root).toMatchObject({ valid: true, purposeOid: '2.5.29.37.0', pathLength: 1 });
        });

        it('refuses a purpose the leaf does not name (path[0]) — a verdict, not an error', async () => {
            const r = await checkCertificatePurpose({ ...leaf(), chain: [fixtureInput('inter.crt.pem')], purpose: 'codeSigning' });
            expect(r.valid).toBe(false);
            expect(r.reasons).toEqual([expect.objectContaining({ code: 'PKI_REASON_PURPOSE_NOT_PERMITTED', path: 'path[0].extKeyUsage', standard: expect.stringContaining('RFC 5280') })]);
            expect(r.purposeOid).toBe('1.3.6.1.5.5.7.3.3');
            const result = await callToolDirect('check_certificate_purpose', { ...leaf(), purpose: 'codeSigning' });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toMatchObject({ valid: false, reasons: [{ code: 'PKI_REASON_PURPOSE_NOT_PERMITTED' }] });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('check_certificate_purpose: NOT OK — PKI_REASON_PURPOSE_NOT_PERMITTED') });
        });

        it('holds the issuers to the purpose unless restrictIssuers:false (tsa.crt.pem carries timeStamping only)', async () => {
            const restricted = await checkCertificatePurpose({ ...leaf(), chain: [fixtureInput('tsa.crt.pem')], purpose: 'serverAuth' });
            expect(restricted.valid).toBe(false);
            expect(restricted.reasons).toEqual([expect.objectContaining({ code: 'PKI_REASON_PURPOSE_NOT_PERMITTED', path: 'path[1].extKeyUsage' })]);
            const free = await checkCertificatePurpose({ ...leaf(), chain: [fixtureInput('tsa.crt.pem')], purpose: 'serverAuth', restrictIssuers: false });
            expect(free).toMatchObject({ valid: true, reasons: [], pathLength: 2 });
        });

        it('requireExplicitPurpose refuses a certificate with no extKeyUsage', async () => {
            const root = { certificate: fixtureInput('root.crt.pem') };
            expect((await checkCertificatePurpose({ ...root, purpose: 'serverAuth' })).valid).toBe(true);
            const strict = await checkCertificatePurpose({ ...root, purpose: 'any', requireExplicitPurpose: true });
            expect(strict.valid).toBe(false);
            expect(strict.reasons[0]?.['code']).toBe('PKI_REASON_PURPOSE_NOT_PERMITTED');
            expect((await checkCertificatePurpose({ ...leaf(), purpose: 'serverAuth', requireExplicitPurpose: true })).valid).toBe(true);
        });

        it('the OK text names the subject and the purpose', async () => {
            const result = await callToolDirect('check_certificate_purpose', { ...leaf(), purpose: 'emailProtection' });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('check_certificate_purpose: OK — CN=example.test,O=pkinative-cli test,C=FR may be used for emailProtection (1.3.6.1.5.5.7.3.4); path of 1') });
        });
    });

    describe('projection', () => {
        it('summary keeps the scalars; fields project over the wire', async () => {
            const r = await checkCertificatePurpose({ ...leaf(), purpose: 'codeSigning' });
            expect(checkCertificatePurposeSummary(r)).toEqual({ valid: false, reasonCodes: ['PKI_REASON_PURPOSE_NOT_PERMITTED'], purpose: 'codeSigning', purposeOid: '1.3.6.1.5.5.7.3.3', subject: r.subject, pathLength: 1, diagnosticCount: 0 });
            const result = await callToolDirect('check_certificate_purpose', { ...leaf(), purpose: 'serverAuth', verbosity: 'summary', fields: ['valid', 'purposeOid', 'nope'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ valid: true, purposeOid: '1.3.6.1.5.5.7.3.1' });
            expect(result._meta).toEqual({ unmatchedFields: ['nope'], availableFields: expect.arrayContaining(['valid', 'reasonCodes', 'pathLength']) });
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads the certificate and the chain from the sandbox and refuses escapes', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.crt.der'), path.join(sandbox, 'leaf.crt.der'));
            await fs.copyFile(fixture('inter.crt.pem'), path.join(sandbox, 'inter.crt.pem'));
            const r = await checkCertificatePurpose({ certificate: { path: 'leaf.crt.der' }, chain: [{ path: 'inter.crt.pem' }], purpose: 'serverAuth' });
            expect(r.valid).toBe(true);
            expect(r.pathLength).toBe(2);
            expect(await codeOf(checkCertificatePurpose({ certificate: { path: '../leaf.crt.der' }, purpose: 'serverAuth' }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(checkCertificatePurpose({ certificate: { path: 'missing.crt.pem' }, purpose: 'serverAuth' }))).toBe('INPUT_NOT_FOUND');
            expect(await codeOf(checkCertificatePurpose({ certificate: { path: 'leaf.exe' }, purpose: 'serverAuth' }))).toBe('INVALID_EXTENSION');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(checkCertificatePurpose({ certificate: { path: 'leaf.crt.der' }, purpose: 'serverAuth' }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it('VALIDATION_ERROR: an unknown purpose (naming the choices), missing inputs, an unknown key', async () => {
            try {
                await checkCertificatePurpose({ ...leaf(), purpose: 'frob' });
                expect.unreachable();
            } catch (e) {
                expect(e).toBeInstanceOf(ToolError);
                expect((e as ToolError).code).toBe('VALIDATION_ERROR');
                expect((e as ToolError).message).toContain('unknown purpose "frob" (serverAuth, clientAuth');
                expect((e as ToolError).data).toEqual({ path: 'purpose' });
            }
            expect(await codeOf(checkCertificatePurpose({ ...leaf() }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificatePurpose({ purpose: 'serverAuth' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificatePurpose({ ...leaf(), purpose: '' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificatePurpose({ ...leaf(), purpose: 'serverAuth', chain: [] }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificatePurpose({ ...leaf(), purpose: 'serverAuth', bogus: 1 }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificatePurpose({}))).toBe('VALIDATION_ERROR');
        });

        it('PKI_PEM_UNEXPECTED_LABEL for a non-certificate PEM (certificate or chain), PKI_* for non-certificate DER', async () => {
            expect(await codeOf(checkCertificatePurpose({ certificate: fixtureInput('leaf.csr.pem'), purpose: 'serverAuth' }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(checkCertificatePurpose({ ...leaf(), purpose: 'serverAuth', chain: [fixtureInput('leaf.key.pem')] }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            const result = await callToolDirect('check_certificate_purpose', { certificate: fixtureInput('leaf.csr.der'), purpose: 'serverAuth' });
            expect(errorCodeOf(result)).toMatch(/^PKI_/);
        });
    });

    describe('definition', () => {
        it('is a read-only cacheable verdict with two validating examples', () => {
            expect(CHECK_CERTIFICATE_PURPOSE_TOOL.kind).toBe('verdict');
            expect(CHECK_CERTIFICATE_PURPOSE_TOOL.annotations.readOnlyHint).toBe(true);
            expect(CHECK_CERTIFICATE_PURPOSE_TOOL.cacheable).toBe(true);
            expect(CHECK_CERTIFICATE_PURPOSE_TOOL.examples?.length).toBe(2);
        });
    });
});
