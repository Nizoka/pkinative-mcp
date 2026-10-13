/**
 * Tests for `sign_cms` — attached / detached / digest signing with a PKCS#8
 * key (plain and encrypted) and PKCS#12 files, every option, the round trip
 * through verify_cms and inspect_cms, the sandbox file mode, every error
 * code, and no secret in any result.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { parseSignedData } from 'pkinative';

import { callToolDirect } from '../src/server.js';
import { signCmsTool, SIGN_CMS_TOOL } from '../src/tools/sign-cms.js';
import { inspectCms } from '../src/tools/inspect-cms.js';
import { verifyCmsTool } from '../src/tools/verify-cms.js';
import { artefactBytes, assertResultClean, assertValidDer, codeOf, errorCodeOf } from './_pki-assert.js';
import { AT, fixture, fixtureBase64, fixtureInput, PASSWORD } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const CONTENT = { base64: fixtureBase64('content.txt') };
const CONTENT_SHA256 = 'b1a1c762480b580288e0737422f01130e824c8014422371ae571880dfc642533';
const ATTRIBUTE = '300d06032a0304310606042a030405';
const LEAF = { certificate: fixtureInput('leaf.crt.pem'), signer: { key: fixtureInput('leaf.key.pem') } };
const ROOT = [fixtureInput('root.crt.pem')];

function derOf(base64: string | undefined): Uint8Array {
    return new Uint8Array(Buffer.from(base64 ?? '', 'base64'));
}

describe('sign_cms', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_PASSWORD'];
        delete process.env['PKINATIVE_MCP_AT'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('signing', () => {
        it('signs detached content with a chain, pinned time, and the message verifies under the root', async () => {
            const r = await signCmsTool({ content: CONTENT, detached: true, chain: [fixtureInput('inter.crt.pem')], signingTime: AT, ...LEAF });
            assertResultClean(r);
            expect(r.mode).toBe('base64');
            expect(r.encoding).toBe('der');
            expect(r.mimeType).toBe('application/pkcs7-signature');
            expect(r.summary).toEqual({
                detached: true,
                contentType: '1.2.840.113549.1.7.1',
                signerSubject: expect.stringContaining('CN=example.test'),
                signerSerial: '1001',
                sid: 'issuerAndSerialNumber',
                digestAlgorithm: { oid: '2.16.840.1.101.3.4.2.1', name: 'sha256', hasParameters: false },
                signatureAlgorithm: { oid: '1.2.840.10045.4.3.2', name: 'ecdsa-with-SHA256', hasParameters: false },
                signingTime: '2027-01-01T00:00:00.000Z',
                signingTimeSource: 'input',
                certificatesEmbedded: 2,
                crlsEmbedded: 0,
                signedAttributes: 5,
                unsignedAttributes: 0,
                signatureVerified: true,
                contentBytes: 27,
            });
            const der = derOf(r.base64);
            assertValidDer(der);
            expect(der.length).toBe(r.sizeBytes);
            const verdict = await verifyCmsTool({ signedData: { derBase64: r.base64 as string }, content: CONTENT, trustAnchors: ROOT, requireSigningCertificate: true, requireAlgorithmProtection: true, at: AT });
            expect(verdict.valid).toBe(true);
            const report = await inspectCms({ signedData: { derBase64: r.base64 as string } });
            expect(report.signerInfos[0]?.signingCertificate).toMatchObject({ version: 2 });
            expect(report.signerInfos[0]?.algorithmProtection).not.toBeNull();
        });

        it('signs attached content from a PKCS#12 (bag certificate + chain), signingTime none, ESS and protection off', async () => {
            const r = await signCmsTool({ content: { text: 'hello' }, signingTime: 'none', signingCertificateV2: false, algorithmProtection: false, signer: { p12: fixtureInput('leaf.p12'), password: PASSWORD }, encoding: 'pem' });
            assertResultClean(r);
            expect(r.summary).toMatchObject({ detached: false, signingTime: null, signingTimeSource: 'none', certificatesEmbedded: 2, signedAttributes: 2, contentBytes: 5 });
            const pem = Buffer.from(r.base64 ?? '', 'base64').toString('utf8');
            expect(pem).toMatch(/^-----BEGIN CMS-----/);
            const report = await inspectCms({ signedData: { pem } });
            expect(report.contentLength).toBe(5);
            expect(report.signerInfos[0]?.signingTime).toBeNull();
            expect(report.signerInfos[0]?.signingCertificate).toBeNull();
            expect((await verifyCmsTool({ signedData: { pem }, trustAnchors: ROOT, at: AT })).valid).toBe(true);
        });

        it('signs with every option: SKI identifier, content type, CRL, extra attributes, encrypted key, fractional time truncated', async () => {
            const r = await signCmsTool({
                content: CONTENT, detached: true, sid: 'subjectKeyIdentifier', contentType: '1.2.840.113549.1.9.16.1.4', crls: [fixtureInput('inter.crl.pem')],
                signedAttributes: [ATTRIBUTE], unsignedAttributes: ['300d06032a0306310606042a030607'], signingTime: '2027-01-01T00:00:00.500Z',
                certificate: fixtureInput('leaf.crt.pem'), signer: { key: fixtureInput('leaf.key.enc.pem'), password: PASSWORD },
            });
            assertResultClean(r);
            expect(r.summary).toMatchObject({ sid: 'subjectKeyIdentifier', contentType: '1.2.840.113549.1.9.16.1.4', crlsEmbedded: 1, signedAttributes: 6, unsignedAttributes: 1, signingTime: '2027-01-01T00:00:00.000Z' });
            const sd = parseSignedData(derOf(r.base64));
            expect(sd.signerInfos[0]?.sid.kind).toBe('subjectKeyIdentifier');
            expect(sd.signerInfos[0]?.signedAttributes?.map((a) => a.oid)).toContain('1.2.3.4');
            expect(sd.signerInfos[0]?.unsignedAttributes?.map((a) => a.oid)).toEqual(['1.2.3.6']);
        });

        it('signs a precomputed digest (detached), verifiable against the content', async () => {
            const r = await signCmsTool({ contentDigest: CONTENT_SHA256, detached: true, signingTime: AT, ...LEAF });
            expect(r.summary.contentBytes).toBeNull();
            expect((await verifyCmsTool({ signedData: { derBase64: r.base64 as string }, content: CONTENT, trustAnchors: ROOT, candidates: [fixtureInput('inter.crt.pem')], at: AT })).valid).toBe(true);
        });

        it('signs with an Ed25519 PKCS#12 and an RSA-PSS PKCS#12', async () => {
            const ed = await signCmsTool({ content: { text: 'x' }, signingTime: AT, signer: { p12: fixtureInput('ed25519.p12'), password: PASSWORD } });
            assertResultClean(ed);
            expect(ed.summary.signatureAlgorithm.name).toBe('Ed25519');
            expect(ed.summary.digestAlgorithm.name).toBe('sha512');
            const pss = await signCmsTool({ content: { text: 'x' }, signingTime: AT, signer: { p12: fixtureInput('rsa.p12'), password: PASSWORD, rsaScheme: 'pss', saltLength: 20 } });
            assertResultClean(pss);
            expect(pss.summary.signatureAlgorithm.name).toBe('RSASSA-PSS');
        });

        it('defaults the signing time to the operator pin, else the clock (whole seconds)', async () => {
            process.env['PKINATIVE_MCP_AT'] = '2027-06-01T12:34:56.789Z';
            try {
                const pinned = await signCmsTool({ content: { text: 'x' }, ...LEAF });
                expect(pinned.summary).toMatchObject({ signingTime: '2027-06-01T12:34:56.000Z', signingTimeSource: 'pinned' });
            } finally {
                delete process.env['PKINATIVE_MCP_AT'];
            }
            const clock = await signCmsTool({ content: { text: 'x' }, ...LEAF });
            expect(clock.summary.signingTimeSource).toBe('clock');
            expect(clock.summary.signingTime).toMatch(/\.000Z$/);
        });
    });

    describe('through the server', () => {
        it('delivers the DER once as an embedded resource, never a key byte', async () => {
            const result = await callToolDirect('sign_cms', { content: CONTENT, detached: true, signingTime: AT, ...LEAF });
            expect(result.isError).toBeUndefined();
            assertResultClean(result);
            const bytes = artefactBytes(result);
            assertValidDer(bytes);
            expect((result.structuredContent as Record<string, unknown>)['base64']).toBeUndefined();
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('sign_cms: detached SignedData by CN=example.test') });
        });
    });

    describe('file mode (sandbox)', () => {
        it('writes a .p7s inside the sandbox, never overwrites, and reads inputs from it', async () => {
            sandbox = await makeSandbox();
            for (const name of ['content.txt', 'leaf.crt.pem', 'leaf.key.pem']) await fs.copyFile(fixture(name), path.join(sandbox, name));
            const input = { content: { path: 'content.txt' }, detached: true, signingTime: AT, certificate: { path: 'leaf.crt.pem' }, signer: { key: { path: 'leaf.key.pem' } }, outputMode: 'file', outputPath: 'out/content.p7s' };
            const result = await callToolDirect('sign_cms', input);
            expect(result.isError).toBeUndefined();
            assertResultClean(result);
            const structured = result.structuredContent as Record<string, unknown>;
            expect(structured['mode']).toBe('file');
            expect(await fs.stat(structured['filePath'] as string)).toBeTruthy();
            expect(result.content.some((c) => c['type'] === 'resource_link')).toBe(true);
            expect(await codeOf(signCmsTool(input))).toBe('OUTPUT_EXISTS');
            expect(await codeOf(signCmsTool({ ...input, outputPath: 'out/content.key' }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(signCmsTool({ ...input, outputPath: 'out/content.pem' }))).toBe('INVALID_EXTENSION');
            expect(await codeOf(signCmsTool({ ...input, outputPath: undefined }))).toBe('MISSING_OUTPUT_PATH');
            expect(await codeOf(signCmsTool({ ...input, outputPath: 'out/h.p7s', encoding: 'hex' }))).toBe('VALIDATION_ERROR');
        });
    });

    describe('refusals', () => {
        it.each([
            ['neither content nor contentDigest', { ...LEAF }],
            ['both content and contentDigest', { content: CONTENT, contentDigest: CONTENT_SHA256, detached: true, ...LEAF }],
            ['contentDigest without detached', { contentDigest: CONTENT_SHA256, ...LEAF }],
            ['no signer certificate with a key', { content: CONTENT, signer: { key: fixtureInput('leaf.key.pem') } }],
            ['SHA-1 without allowSha1', { content: CONTENT, certificate: fixtureInput('leaf.crt.pem'), signer: { key: fixtureInput('leaf.key.pem'), hash: 'SHA-1' } }],
            ['a bad content type', { content: CONTENT, contentType: 'data', ...LEAF }],
            ['a bad signing time', { content: CONTENT, signingTime: 'yesterday', ...LEAF }],
            ['password twice', { content: CONTENT, certificate: fixtureInput('leaf.crt.pem'), signer: { key: fixtureInput('leaf.key.enc.pem'), password: PASSWORD }, env: true }],
            ['unknown key', { content: CONTENT, bogus: 1, ...LEAF }],
        ])('VALIDATION_ERROR: %s', async (_label, input) => {
            const { env, ...rest } = input as Record<string, unknown> & { env?: boolean };
            if (env === true) process.env['PKINATIVE_MCP_PASSWORD'] = PASSWORD;
            try {
                expect(await codeOf(signCmsTool(rest))).toBe('VALIDATION_ERROR');
            } finally {
                delete process.env['PKINATIVE_MCP_PASSWORD'];
            }
        });

        it.each([
            ['KEY_MISMATCH', { content: CONTENT, certificate: fixtureInput('rsa.crt.pem'), signer: { key: fixtureInput('leaf.key.pem') } }],
            ['RSA_SCHEME_REQUIRED', { content: CONTENT, certificate: fixtureInput('rsa.crt.pem'), signer: { key: fixtureInput('rsa.key.pem') } }],
            ['SECRET_REQUIRED', { content: CONTENT, certificate: fixtureInput('leaf.crt.pem'), signer: { key: fixtureInput('leaf.key.enc.pem') } }],
            ['KEY_TYPE_REQUIRED', { content: CONTENT, signer: { key: fixtureInput('leaf.key.enc.pem'), password: PASSWORD } }],
            ['PKI_API_MISUSE', { contentDigest: '00', detached: true, ...LEAF }],
            ['PKI_API_MISUSE', { content: CONTENT, signedAttributes: ['0500'], ...LEAF }],
            ['PKI_CRYPTO_DECRYPTION_FAILED', { content: CONTENT, certificate: fixtureInput('leaf.crt.pem'), signer: { key: fixtureInput('leaf.key.enc.pem'), password: 'wrong' } }],
            ['PKI_KEY_ENCRYPTION_UNSUPPORTED', { content: CONTENT, signer: { p12: fixtureInput('legacy.p12'), password: PASSWORD } }],
            ['PKI_PEM_UNEXPECTED_LABEL', { content: CONTENT, certificate: fixtureInput('leaf.csr.pem'), signer: { key: fixtureInput('leaf.key.pem') } }],
        ])('%s', async (code, input) => {
            const result = await callToolDirect('sign_cms', input);
            expect(errorCodeOf(result)).toBe(code);
            assertResultClean(result);
        });
    });

    describe('definition', () => {
        it('produces, is never cached, declares its instant, with two examples', () => {
            expect(SIGN_CMS_TOOL.kind).toBe('artefact');
            expect(SIGN_CMS_TOOL.annotations.idempotentHint).toBe(false);
            expect(SIGN_CMS_TOOL.cacheable).toBe(false);
            expect(SIGN_CMS_TOOL.instantInputs).toEqual(['signingTime']);
            expect(SIGN_CMS_TOOL.examples?.length).toBe(2);
        });
    });
});
