/**
 * Tests for `check_certificate_name` — the certificate form (host / IP,
 * wildcards, the commonName fallback with and without a path), the match
 * form, negative verdicts without isError, projection, path inputs, codes.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { checkCertificateName, checkCertificateNameSummary, CHECK_CERTIFICATE_NAME_TOOL } from '../src/tools/check-certificate-name.js';
import { codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureInput } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const leaf = (): Record<string, unknown> => ({ certificate: fixtureInput('leaf.crt.pem') });

describe('check_certificate_name', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('certificate form', () => {
        it.each([
            ['example.test', undefined, true],
            ['EXAMPLE.test.', undefined, true],
            ['a.wild.example.test', undefined, true],
            ['wild.example.test', undefined, false],
            ['evil.test', undefined, false],
            [undefined, '192.0.2.1', true],
            [undefined, '::ffff:192.0.2.1', false],
            [undefined, '192.0.2.2', false],
            [undefined, '2001:db8::1', false],
        ])('host %s / ip %s → %s', async (host, ip, valid) => {
            const r = await checkCertificateName({ ...leaf(), ...(host !== undefined ? { host } : {}), ...(ip !== undefined ? { ip } : {}) });
            expect(r.form).toBe('certificate');
            expect(r.valid).toBe(valid);
            expect(r.reference).toEqual({ kind: host !== undefined ? 'dns' : 'ip', value: host ?? ip });
            expect(r.subject).toContain('CN=example.test');
            expect(r.reasons.map((x) => x['code'])).toEqual(valid ? [] : ['PKI_REASON_NAME_MISMATCH']);
            if (!valid) expect(r.reasons[0]).toMatchObject({ standard: expect.stringContaining('RFC 6125'), path: 'certificate.subjectAltName' });
            expect(r.diagnostics).toEqual([]);
        });

        it('allowWildcards:false refuses the wildcard match', async () => {
            const r = await checkCertificateName({ ...leaf(), host: 'a.wild.example.test', allowWildcards: false });
            expect(r.valid).toBe(false);
            expect(r.reasons[0]?.['code']).toBe('PKI_REASON_NAME_MISMATCH');
        });

        it('the commonName fallback needs the path (chain) to apply name constraints', async () => {
            const base = { certificate: fixtureInput('ed25519.crt.pem'), host: 'Test Ed25519 Root' };
            expect((await checkCertificateName(base)).valid).toBe(false);
            expect((await checkCertificateName({ ...base, allowCommonNameFallback: true })).valid).toBe(false);
            const withPath = await checkCertificateName({ ...base, allowCommonNameFallback: true, chain: [fixtureInput('root.crt.pem')] });
            expect(withPath.valid).toBe(true);
            expect(withPath.reasons).toEqual([]);
        });

        it('a chain of several certificates is accepted (DER and PEM mixed)', async () => {
            const r = await checkCertificateName({ ...leaf(), host: 'example.test', chain: [fixtureInput('inter.crt.der'), fixtureInput('root.crt.pem')] });
            expect(r.valid).toBe(true);
        });

        it('a negative verdict is not isError through the server', async () => {
            const result = await callToolDirect('check_certificate_name', { ...leaf(), host: 'evil.test' });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toMatchObject({ form: 'certificate', valid: false, reasons: [{ code: 'PKI_REASON_NAME_MISMATCH' }] });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('check_certificate_name: NOT OK — PKI_REASON_NAME_MISMATCH') });
            const ok = await callToolDirect('check_certificate_name', { ...leaf(), host: 'example.test' });
            expect(ok.content[0]).toEqual({ type: 'text', text: expect.stringContaining('check_certificate_name: OK — CN=example.test') });
        });
    });

    describe('match form', () => {
        it('matches a wildcard, refuses it without wildcards, and compares plain names', async () => {
            const yes = await checkCertificateName({ presented: '*.example.test', reference: 'a.example.test' });
            expect(yes).toMatchObject({ form: 'match', valid: true, match: true, reasons: [], presented: '*.example.test', reference: { kind: 'dns', value: 'a.example.test' } });
            expect(yes.subject).toBeUndefined();
            const noWild = await checkCertificateName({ presented: '*.example.test', reference: 'a.example.test', allowWildcards: false });
            expect(noWild).toMatchObject({ valid: false, match: false });
            expect((await checkCertificateName({ presented: 'a.test', reference: 'b.test' })).match).toBe(false);
            expect((await checkCertificateName({ presented: 'A.TEST', reference: 'a.test' })).match).toBe(true);
            expect((await checkCertificateName({ presented: '*.example.test', reference: 'b.a.example.test' })).match).toBe(false);
        });

        it('text and projection', async () => {
            const result = await callToolDirect('check_certificate_name', { presented: 'a.test', reference: 'b.test', verbosity: 'summary' });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ form: 'match', valid: false, reasonCodes: [], reference: { kind: 'dns', value: 'b.test' }, presented: 'a.test', match: false, diagnosticCount: 0 });
            expect(result.content[0]).toEqual({ type: 'text', text: 'check_certificate_name: NOT OK — "a.test" does not match "b.test".' });
        });
    });

    describe('projection', () => {
        it('summary keeps the scalars; fields project over the wire', async () => {
            const r = await checkCertificateName({ ...leaf(), host: 'evil.test' });
            expect(checkCertificateNameSummary(r)).toEqual({ form: 'certificate', valid: false, reasonCodes: ['PKI_REASON_NAME_MISMATCH'], reference: { kind: 'dns', value: 'evil.test' }, subject: r.subject, diagnosticCount: 0 });
            const result = await callToolDirect('check_certificate_name', { ...leaf(), ip: '192.0.2.1', fields: ['valid', 'reference.kind', 'nope'] });
            expect(result.structuredContent).toEqual({ valid: true, reference: { kind: 'ip' } });
            expect(result._meta).toEqual({ unmatchedFields: ['nope'], availableFields: expect.arrayContaining(['valid', 'reasons', 'subject']) });
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads the certificate and the chain from the sandbox and refuses escapes', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.crt.der'), path.join(sandbox, 'leaf.crt.der'));
            await fs.copyFile(fixture('inter.crt.pem'), path.join(sandbox, 'inter.crt.pem'));
            const r = await checkCertificateName({ certificate: { path: 'leaf.crt.der' }, host: 'example.test', chain: [{ path: 'inter.crt.pem' }] });
            expect(r.valid).toBe(true);
            expect(await codeOf(checkCertificateName({ certificate: { path: '../leaf.crt.der' }, host: 'example.test' }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(checkCertificateName({ certificate: { path: 'missing.crt.pem' }, host: 'example.test' }))).toBe('INPUT_NOT_FOUND');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(checkCertificateName({ certificate: { path: 'leaf.crt.der' }, host: 'example.test' }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it('VALIDATION_ERROR: the two forms mixed, host + ip, neither, half a match form, a bad address', async () => {
            expect(await codeOf(checkCertificateName({ ...leaf() }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificateName({ ...leaf(), host: 'a', ip: '192.0.2.1' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificateName({ host: 'example.test' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificateName({ presented: 'a.test' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificateName({ reference: 'a.test' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificateName({ ...leaf(), host: 'a.test', presented: 'a.test', reference: 'a.test' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificateName({ presented: 'a.test', reference: 'a.test', chain: [fixtureInput('inter.crt.pem')] }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificateName({ ...leaf(), ip: '999.1.1.1' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificateName({ ...leaf(), host: '' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificateName({ ...leaf(), host: 'a.test', bogus: 1 }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(checkCertificateName({}))).toBe('VALIDATION_ERROR');
        });

        it('PKI_PEM_UNEXPECTED_LABEL for a non-certificate PEM (certificate or chain), PKI_* for non-certificate DER', async () => {
            expect(await codeOf(checkCertificateName({ certificate: fixtureInput('leaf.csr.pem'), host: 'a.test' }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(checkCertificateName({ ...leaf(), host: 'a.test', chain: [fixtureInput('inter.crl.pem')] }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            const result = await callToolDirect('check_certificate_name', { certificate: fixtureInput('leaf.csr.der'), host: 'a.test' });
            expect(errorCodeOf(result)).toMatch(/^PKI_/);
        });
    });

    describe('definition', () => {
        it('is a read-only cacheable verdict with two validating examples', () => {
            expect(CHECK_CERTIFICATE_NAME_TOOL.kind).toBe('verdict');
            expect(CHECK_CERTIFICATE_NAME_TOOL.annotations.readOnlyHint).toBe(true);
            expect(CHECK_CERTIFICATE_NAME_TOOL.cacheable).toBe(true);
            expect(CHECK_CERTIFICATE_NAME_TOOL.examples?.length).toBe(2);
        });
    });
});
