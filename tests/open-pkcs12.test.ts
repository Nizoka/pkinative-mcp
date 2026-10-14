/**
 * Tests for `open_pkcs12` — the positive verdict (keys imported
 * non-extractable, certificates, CRLs), every negative verdict as a report
 * (never isError), the RSA scheme rule, the PEM bundle artefact (inline and
 * file mode, never from a file that did not open), every error code,
 * projection, and the secret-leak matrix.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { decodePem } from 'pkinative';

import { callToolDirect } from '../src/server.js';
import { openPkcs12Tool, openPkcs12Summary, OPEN_PKCS12_TOOL, pemBundle } from '../src/tools/open-pkcs12.js';
import { assertNoSecret, assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureBase64, fixtureInput, PASSWORD } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const WRONG = 'definitely-wrong';
const KEY_FIXTURES = ['leaf.key.pem', 'leaf.key.der', 'rsa.key.pem', 'ed25519.key.pem', 'leaf.key.enc.pem', 'rsa.key.enc.pem'] as const;
const P12_FIXTURES = ['leaf.p12', 'rsa.p12', 'ed25519.p12', 'legacy.p12', 'plain-keybag.p12', 'nomac.p12', 'certs-only.p12'] as const;
const handle = (algorithm: string): Record<string, unknown> => ({ type: 'private', algorithm, extractable: false, usages: ['sign'] });

const p12 = (name: string): { derBase64: string } => ({ derBase64: fixtureBase64(name) });
const codes = (r: { reasons: ReadonlyArray<Record<string, string>> }): string[] => [...new Set(r.reasons.map((x) => x['code']))];

describe('open_pkcs12', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_PASSWORD'];
    });

    afterEach(async () => {
        delete process.env['PKINATIVE_MCP_PASSWORD'];
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('positive verdicts', () => {
        it('opens leaf.p12: MAC verified, the EC key imported non-extractable, two certificates', async () => {
            const r = await openPkcs12Tool({ pkcs12: p12('leaf.p12'), password: PASSWORD });
            expect(r).toMatchObject({ valid: true, integrity: 'verified', reasons: [], keyCount: 1, certificateCount: 2, crlCount: 0, diagnostics: [] });
            expect(r.keys[0]).toEqual({
                path: 'authSafe[1].bags[0]',
                friendlyName: 'test leaf',
                localKeyId: expect.stringMatching(/^[0-9a-f]+$/),
                certificate: { subject: 'CN=example.test,O=pkinative-cli test,C=FR', issuer: 'CN=Test Intermediate CA,O=pkinative-cli test,C=FR', serialNumber: '1001', notAfter: '2046-01-01T00:00:00.000Z' },
                signingKey: { algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }, key: handle('ECDSA') },
            });
            expect(r.certificates.map((c) => c.subject)).toEqual(['CN=example.test,O=pkinative-cli test,C=FR', 'CN=Test Intermediate CA,O=pkinative-cli test,C=FR']);
            expect(r.artefact).toBeUndefined();
            expect(r.exportSkipped).toBeUndefined();
            assertResultClean(r);
        });

        it.each([
            ['ed25519.p12', {}, { name: 'Ed25519' }],
            ['rsa.p12', { rsaScheme: 'pkcs1' }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }],
            ['rsa.p12', { rsaScheme: 'pss', hash: 'SHA-384' }, { name: 'RSA-PSS', hash: 'SHA-384' }],
        ])('%s with %j signs %j', async (name, extra, algorithm) => {
            const r = await openPkcs12Tool({ pkcs12: p12(name), password: PASSWORD, ...extra });
            expect(r.valid).toBe(true);
            expect(r.keys[0]?.signingKey).toEqual({ algorithm, key: handle(algorithm.name) });
            assertResultClean(r);
        });

        it('imports an unencrypted keyBag without printing a byte of it', async () => {
            const r = await openPkcs12Tool({ pkcs12: p12('plain-keybag.p12'), password: PASSWORD });
            expect(r).toMatchObject({ valid: true, integrity: 'verified', keyCount: 1, certificateCount: 1 });
            expect(r.keys[0]).toMatchObject({ friendlyName: null, signingKey: { algorithm: { name: 'ECDSA' }, key: handle('ECDSA') } });
            assertResultClean(r);
        });

        it('a certificates-only file has no key; a file without a MAC opens only under allowUnverifiedIntegrity', async () => {
            const certs = await openPkcs12Tool({ pkcs12: p12('certs-only.p12'), password: PASSWORD });
            expect(certs).toMatchObject({ valid: true, keys: [], certificateCount: 1 });
            const waived = await openPkcs12Tool({ pkcs12: p12('nomac.p12'), password: PASSWORD, allowUnverifiedIntegrity: true });
            expect(waived).toMatchObject({ valid: true, integrity: 'unverified', reasons: [], certificateCount: 1 });
        });
    });

    describe('A-039 / A-040: every PKCS#12 reason names the MCP remedy', () => {
        it('A-039: the RSA-scheme reason names rsaScheme; A-040: the legacy and no-MAC reasons name the OpenSSL conversion', async () => {
            const rsa = await callToolDirect('open_pkcs12', { pkcs12: fixtureInput('rsa.p12'), password: PASSWORD });
            const rsaReasons = (rsa.structuredContent as { reasons: Array<{ code: string; message: string }> }).reasons;
            expect(rsaReasons.find((r) => r.code === 'PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED')?.message).toContain("rsaScheme:'pkcs1' | 'pss'");
            const legacy = await callToolDirect('open_pkcs12', { pkcs12: fixtureInput('legacy.p12'), password: PASSWORD });
            const legacyReasons = (legacy.structuredContent as { reasons: Array<{ code: string; message: string }> }).reasons;
            expect(legacyReasons.find((r) => r.code === 'PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED')?.message).toContain('openssl pkcs12');
            expect(legacyReasons.find((r) => r.code === 'PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED')?.message).toContain('allowUnverifiedIntegrity');
            assertResultClean(rsa);
            assertResultClean(legacy);
        });
    });

    describe('negative verdicts are reports, never isError', () => {
        it('a wrong password: integrity mismatch, nothing decrypted, the password never echoed', async () => {
            const result = await callToolDirect('open_pkcs12', { pkcs12: p12('leaf.p12'), password: WRONG });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toMatchObject({ valid: false, integrity: 'mismatch', keys: [], certificates: [], reasons: [{ code: 'PKI_REASON_PKCS12_MAC_MISMATCH' }] });
            expect((result.content[0] as { text: string }).text).toContain('open_pkcs12: NOT OK — PKI_REASON_PKCS12_MAC_MISMATCH (integrity mismatch');
            expect(JSON.stringify(result)).not.toContain(WRONG);
            assertResultClean(result);
        });

        it('an RSA key without rsaScheme: valid false, that key not imported', async () => {
            const r = await openPkcs12Tool({ pkcs12: p12('rsa.p12'), password: PASSWORD });
            expect(r).toMatchObject({ valid: false, integrity: 'verified', keyCount: 1, certificateCount: 1 });
            expect(codes(r)).toEqual(['PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED']);
            expect(r.keys[0]?.signingKey).toBeNull();
            expect(r.keys[0]?.certificate?.subject).toContain('rsa.example.test');
        });

        it('a legacy file: integrity unverified and the cipher refused, even with the waiver', async () => {
            const r = await openPkcs12Tool({ pkcs12: p12('legacy.p12'), password: PASSWORD });
            expect(r).toMatchObject({ valid: false, integrity: 'unverified' });
            expect(codes(r)).toEqual(['PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED', 'PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED']);
            expect(r.keys[0]?.signingKey).toBeNull();
            const waived = await openPkcs12Tool({ pkcs12: p12('legacy.p12'), password: PASSWORD, allowUnverifiedIntegrity: true });
            expect(waived.valid).toBe(false);
            expect(codes(waived)).toEqual(['PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED']);
            assertResultClean(r);
        });

        it('no MAC: PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED', async () => {
            const r = await openPkcs12Tool({ pkcs12: p12('nomac.p12'), password: PASSWORD });
            expect(r).toMatchObject({ valid: false, integrity: 'unverified', certificateCount: 1 });
            expect(codes(r)).toEqual(['PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED']);
        });

        it('a limit the file exceeds and a non-PKCS#12 input are reasons too', async () => {
            const limited = await openPkcs12Tool({ pkcs12: p12('leaf.p12'), password: PASSWORD, limits: { maxPkcs12KdfIterations: 1000 } });
            expect(limited.valid).toBe(false);
            expect(limited.reasons[0]).toMatchObject({ code: 'PKI_REASON_INPUT_MALFORMED', errorCode: 'PKI_LIMIT_EXCEEDED' });
            const cert = await openPkcs12Tool({ pkcs12: { derBase64: fixtureBase64('leaf.crt.der') }, password: PASSWORD });
            expect(cert.valid).toBe(false);
            expect(codes(cert)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
        });
    });

    describe('password sources', () => {
        it('SECRET_REQUIRED without a password; PKINATIVE_MCP_PASSWORD works; two sources are refused', async () => {
            expect(await codeOf(openPkcs12Tool({ pkcs12: p12('leaf.p12') }))).toBe('SECRET_REQUIRED');
            process.env['PKINATIVE_MCP_PASSWORD'] = PASSWORD;
            expect((await openPkcs12Tool({ pkcs12: p12('leaf.p12') })).valid).toBe(true);
            expect(await codeOf(openPkcs12Tool({ pkcs12: p12('leaf.p12'), password: PASSWORD }))).toBe('VALIDATION_ERROR');
        });
    });

    describe('exportCertificates (PEM bundle, never a key)', () => {
        it('attaches the bundle inline as an embedded PEM resource, delivered once', async () => {
            const result = await callToolDirect('open_pkcs12', { pkcs12: p12('leaf.p12'), password: PASSWORD, exportCertificates: true });
            expect(result.isError).toBeUndefined();
            const structured = result.structuredContent as { artefact: Record<string, unknown>; valid: boolean };
            expect(structured.valid).toBe(true);
            expect(structured.artefact).toEqual({ mode: 'base64', encoding: 'pem', sizeBytes: expect.any(Number), sha256: expect.stringMatching(/^[0-9a-f]{64}$/), summary: { certificates: 2, crls: 0 } });
            expect(structured.artefact['base64']).toBeUndefined();
            const block = result.content.find((c) => c['type'] === 'resource') as { resource: { text: string; mimeType: string } };
            expect(block.resource.mimeType).toBe('application/x-pem-file');
            const blocks = decodePem(block.resource.text);
            expect(blocks.map((b) => b.label)).toEqual(['CERTIFICATE', 'CERTIFICATE']);
            expect(block.resource.text).not.toContain('PRIVATE KEY');
            const first = block.resource.text.slice(0, block.resource.text.indexOf('-----END CERTIFICATE-----') + 25);
            const back = await callToolDirect('inspect_certificate', { certificate: { pem: first }, verbosity: 'summary' });
            expect(back.structuredContent).toMatchObject({ serialNumberHex: '1001' });
            expect((result.content[0] as { text: string }).text).toContain('2 certificate(s) + 0 CRL(s) exported as a PEM bundle (embedded resource below)');
            assertResultClean(result);
        });

        it('writes the bundle to a sandbox .pem file once, never overwriting', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.p12'), path.join(sandbox, 'leaf.p12'));
            const result = await callToolDirect('open_pkcs12', { pkcs12: { path: 'leaf.p12' }, password: PASSWORD, exportCertificates: true, outputMode: 'file', outputPath: 'out/leaf-bundle.pem' });
            expect(result.isError).toBeUndefined();
            const filePath = (result.structuredContent as { artefact: { filePath: string; mode: string } }).artefact.filePath;
            expect(path.resolve(filePath).startsWith(path.resolve(sandbox))).toBe(true);
            const text = await fs.readFile(filePath, 'utf8');
            expect(text.startsWith('-----BEGIN CERTIFICATE-----')).toBe(true);
            expect(text.match(/BEGIN CERTIFICATE/g)).toHaveLength(2);
            expect(result.content.some((c) => c['type'] === 'resource_link')).toBe(true);
            expect(await codeOf(openPkcs12Tool({ pkcs12: { path: 'leaf.p12' }, password: PASSWORD, exportCertificates: true, outputMode: 'file', outputPath: 'out/leaf-bundle.pem' }))).toBe('OUTPUT_EXISTS');
            expect(await codeOf(openPkcs12Tool({ pkcs12: { path: 'leaf.p12' }, password: PASSWORD, exportCertificates: true, outputMode: 'file', outputPath: 'out/bundle.der' }))).toBe('INVALID_EXTENSION');
            expect(await codeOf(openPkcs12Tool({ pkcs12: { path: 'leaf.p12' }, password: PASSWORD, exportCertificates: true, outputMode: 'file' }))).toBe('MISSING_OUTPUT_PATH');
            assertResultClean(result);
        });

        it('exports nothing from a file that did not open, and says so', async () => {
            sandbox = await makeSandbox();
            const r = await openPkcs12Tool({ pkcs12: p12('leaf.p12'), password: WRONG, exportCertificates: true, outputMode: 'file', outputPath: 'never.pem' });
            expect(r).toMatchObject({ valid: false, exportSkipped: true });
            expect(r.artefact).toBeUndefined();
            expect(OPEN_PKCS12_TOOL.text(r as unknown as Record<string, unknown>)).toContain('certificates NOT exported: the file did not open');
            await expect(fs.access(path.join(sandbox, 'never.pem'))).rejects.toThrow();
            const nomac = await openPkcs12Tool({ pkcs12: p12('nomac.p12'), password: PASSWORD, exportCertificates: true });
            expect(nomac).toMatchObject({ valid: false, exportSkipped: true });
        });

        it('pemBundle writes certificates then CRLs', () => {
            expect(pemBundle([new Uint8Array([0x30, 0x00])], [new Uint8Array([0x30, 0x00])])).toBe('-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n-----BEGIN X509 CRL-----\nMAA=\n-----END X509 CRL-----\n');
        });
    });

    describe('projection', () => {
        it('summary keeps the verdict scalars; fields project over the wire', async () => {
            const r = await openPkcs12Tool({ pkcs12: p12('rsa.p12'), password: PASSWORD });
            expect(openPkcs12Summary(r)).toEqual({ valid: false, integrity: 'verified', reasonCodes: ['PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED'], keyCount: 1, certificateCount: 1, crlCount: 0, diagnosticCount: 0 });
            const result = await callToolDirect('open_pkcs12', { pkcs12: p12('leaf.p12'), password: PASSWORD, verbosity: 'summary', fields: ['valid', 'integrity', 'nope'] });
            expect(result.structuredContent).toEqual({ valid: true, integrity: 'verified' });
            expect(result._meta).toEqual({ unmatchedFields: ['nope'], availableFields: expect.arrayContaining(['reasonCodes', 'keyCount']) });
            expect(result.content[0]).toEqual({ type: 'text', text: 'open_pkcs12: OK — integrity verified, 1 key(s) imported (non-extractable), 2 certificate(s), 0 CRL(s); 0 diagnostic(s).' });
            const keys = await callToolDirect('open_pkcs12', { pkcs12: p12('leaf.p12'), password: PASSWORD, fields: ['keys.signingKey.key.extractable'] });
            expect(keys.structuredContent).toEqual({ keys: [{ signingKey: { key: { extractable: false } } }] });
            assertResultClean(result);
        });
    });

    describe('refusals', () => {
        it('VALIDATION_ERROR: unknown key, hash without rsaScheme, non-PEM encodings, file mode without export, empty password', async () => {
            const base = { pkcs12: p12('leaf.p12'), password: PASSWORD };
            expect(await codeOf(openPkcs12Tool({ ...base, bogus: 1 }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(openPkcs12Tool({ ...base, hash: 'SHA-384' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(openPkcs12Tool({ ...base, exportCertificates: true, encoding: 'der' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(openPkcs12Tool({ ...base, exportCertificates: true, encoding: 'hex' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(openPkcs12Tool({ ...base, outputMode: 'file', outputPath: 'x.pem' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(openPkcs12Tool({ ...base, password: '' }))).toBe('VALIDATION_ERROR');
            const result = await callToolDirect('open_pkcs12', { ...base, rsaScheme: 'rsa' });
            expect(errorCodeOf(result)).toBe('VALIDATION_ERROR');
            expect(JSON.stringify(result)).not.toContain(PASSWORD);
            expect(await codeOf(openPkcs12Tool({}))).toBe('VALIDATION_ERROR');
        });

        it('a sandbox escape and a missing file are refused before anything is read', async () => {
            expect(await codeOf(openPkcs12Tool({ pkcs12: { path: '../leaf.p12' }, password: PASSWORD }))).toBe('SECURITY_VIOLATION');
            sandbox = await makeSandbox();
            expect(await codeOf(openPkcs12Tool({ pkcs12: { path: 'missing.p12' }, password: PASSWORD }))).toBe('INPUT_NOT_FOUND');
        });
    });

    describe('secret-leak matrix (every fixture, every password, every verbosity)', () => {
        it('never writes a key byte, a bag value or the password anywhere', async () => {
            const stderr: string[] = [];
            const spy = vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: unknown) => { stderr.push(String(chunk)); return true; }) as typeof process.stderr.write);
            try {
                for (const name of [...P12_FIXTURES, ...KEY_FIXTURES]) {
                    for (const password of [PASSWORD, WRONG, undefined]) {
                        for (const verbosity of ['full', 'summary']) {
                            const args = { pkcs12: fixtureInput(name), verbosity, allowUnverifiedIntegrity: true, rsaScheme: 'pkcs1', exportCertificates: password === PASSWORD, ...(password !== undefined ? { password } : {}) };
                            const result = await callToolDirect('open_pkcs12', args);
                            assertResultClean(result, `${name} / ${password ?? 'no password'} / ${verbosity}`);
                            expect(JSON.stringify(result)).not.toContain(WRONG);
                        }
                    }
                }
            } finally {
                spy.mockRestore();
            }
            assertNoSecret(stderr.join(''), 'stderr');
        });
    });

    describe('definition', () => {
        it('is a verdict tool that writes a deterministic bundle, never cached, with two examples', () => {
            expect(OPEN_PKCS12_TOOL.kind).toBe('verdict');
            expect(OPEN_PKCS12_TOOL.annotations).toEqual({ readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false });
            expect(OPEN_PKCS12_TOOL.cacheable).toBe(false);
            expect(OPEN_PKCS12_TOOL.examples?.length).toBe(2);
        });
    });
});
