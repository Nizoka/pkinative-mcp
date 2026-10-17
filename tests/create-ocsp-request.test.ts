/**
 * Tests for `create_ocsp_request` — the request bytes (SHA-1 / SHA-256
 * CertID, nonce, random nonce), the bare CertID, every encoding, file mode
 * in the sandbox, cacheability, every error code.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { decodeAsn1, encodeOcspCertId, parseCertificate } from 'pkinative';

import { callToolDirect, isCacheable } from '../src/server.js';
import { CREATE_OCSP_REQUEST_TOOL, createOcspRequestTool } from '../src/tools/create-ocsp-request.js';
import { toHex } from '../src/wire.js';
import { artefactBytes, assertValidDer, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureBase64, fixtureBytes, fixtureInput, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const LEAF = fixtureInput('leaf.crt.pem');
const INTER = fixtureInput('inter.crt.pem');
const SHA1_CERT_ID = '303b300906052b0e03021a0500';
const SHA256_CERT_ID = '3057300d060960864801650304020105000420';

/** The CertID of a request: OCSPRequest { tbsRequest { requestList { Request { reqCert } } } }. */
function requestCertId(der: Uint8Array): string {
    const node = decodeAsn1(der);
    const certId = node.children[0]?.children[0]?.children[0]?.children[0];
    expect(certId).toBeDefined();
    return toHex((certId as { bytes: Uint8Array }).bytes);
}

describe('create_ocsp_request', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('requests', () => {
        it('builds the default SHA-1 request as DER, delivered once as an embedded resource', async () => {
            const result = await callToolDirect('create_ocsp_request', { certificate: LEAF, issuer: INTER });
            expect(result.isError).toBeUndefined();
            const bytes = artefactBytes(result);
            assertValidDer(bytes);
            const sc = result.structuredContent as { summary: Record<string, unknown>; encoding: string; sizeBytes: number; base64?: string };
            expect(sc.base64).toBeUndefined();
            expect(sc.encoding).toBe('der');
            expect(sc.sizeBytes).toBe(bytes.length);
            expect(sc.summary).toEqual({
                certIdHex: expect.stringMatching(new RegExp(`^${SHA1_CERT_ID}`)),
                hashAlgorithm: 'SHA-1',
                randomNonce: false,
                certIdOnly: false,
                serialNumber: '1001',
                subject: expect.stringContaining('CN=example.test'),
                issuer: expect.stringContaining('CN=Test Intermediate CA'),
                sizeBytes: bytes.length,
            });
            // Round trip: the CertID inside the request is the one the summary announces, and the engine's own.
            expect(requestCertId(bytes)).toBe(sc.summary['certIdHex']);
            expect(sc.summary['certIdHex']).toBe(toHex(encodeOcspCertId(parseCertificate(fixtureBytes('leaf.crt.der')), parseCertificate(fixtureBytes('inter.crt.der')))));
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringMatching(/^create_ocsp_request: OCSP request for serial 1001 .*SHA-1 CertID, no nonce/) });
        });

        it('SHA-256 CertID with a given nonce, as hex', async () => {
            const r = await createOcspRequestTool({ certificate: LEAF, issuer: { derBase64: fixtureBase64('inter.crt.der') }, hashAlgorithm: 'SHA-256', nonce: 'a1:b2', encoding: 'hex' });
            expect(r.mode).toBe('base64');
            expect(r.hex).toMatch(/^30/);
            expect(r.hex).toContain('0402a1b2');
            expect(r.summary).toMatchObject({ hashAlgorithm: 'SHA-256', nonceHex: 'a1b2', randomNonce: false, certIdHex: expect.stringMatching(new RegExp(`^${SHA256_CERT_ID}`)) });
            expect(r.summary.certIdHex).toBe(toHex(encodeOcspCertId(parseCertificate(fixtureBytes('leaf.crt.der')), parseCertificate(fixtureBytes('inter.crt.der')), 'SHA-256')));
            expect(r.diagnostics).toEqual([]);
        });

        it("nonce:'random' draws 16 bytes from node:crypto, reported and never cached", async () => {
            const a = await createOcspRequestTool({ certificate: LEAF, issuer: INTER, nonce: 'random' });
            const b = await createOcspRequestTool({ certificate: LEAF, issuer: INTER, nonce: 'random' });
            expect(a.summary.nonceHex).toMatch(/^[0-9a-f]{32}$/);
            expect(a.summary.randomNonce).toBe(true);
            expect(a.summary.nonceHex).not.toBe(b.summary.nonceHex);
            expect(a.sha256).not.toBe(b.sha256);
            expect(isCacheable(CREATE_OCSP_REQUEST_TOOL, { certificate: LEAF, issuer: INTER, nonce: 'random' })).toBe(false);
            expect(isCacheable(CREATE_OCSP_REQUEST_TOOL, { certificate: LEAF, issuer: INTER, nonce: 'a1b2' })).toBe(true);
        });

        it('PEM output carries the OCSP REQUEST label', async () => {
            const result = await callToolDirect('create_ocsp_request', { certificate: LEAF, issuer: INTER, encoding: 'pem' });
            const block = result.content.find((c) => c['type'] === 'resource') as { resource: { text?: string } };
            expect(block.resource.text).toMatch(/^-----BEGIN OCSP REQUEST-----/);
            assertValidDer(artefactBytes(result));
        });

        it('certIdOnly returns the bare CertID (der or hex, never pem)', async () => {
            const r = await createOcspRequestTool({ certificate: LEAF, issuer: INTER, certIdOnly: true, hashAlgorithm: 'SHA-256', encoding: 'hex' });
            expect(r.hex).toBe(r.summary.certIdHex);
            expect(r.summary.certIdOnly).toBe(true);
            expect(r.sizeBytes).toBe(0x59);
            expect(CREATE_OCSP_REQUEST_TOOL.text(r as unknown as Record<string, unknown>)).toMatch(/^create_ocsp_request: CertID for serial 1001/);
            expect(await codeOf(createOcspRequestTool({ certificate: LEAF, issuer: INTER, certIdOnly: true, encoding: 'pem' }))).toBe('VALIDATION_ERROR');
        });
    });

    describe('file mode (sandbox)', () => {
        it('writes the .orq once, links it, and never overwrites', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.crt.der'), path.join(sandbox, 'leaf.crt.der'));
            const result = await callToolDirect('create_ocsp_request', { certificate: { path: 'leaf.crt.der' }, issuer: INTER, outputMode: 'file', outputPath: 'ocsp/leaf.orq' });
            expect(result.isError).toBeUndefined();
            const sc = result.structuredContent as { mode: string; filePath: string; base64?: string };
            expect(sc.mode).toBe('file');
            expect(sc.base64).toBeUndefined();
            const written = new Uint8Array(await fs.readFile(path.join(sandbox, 'ocsp', 'leaf.orq')));
            assertValidDer(written);
            expect(requestCertId(written)).toMatch(new RegExp(`^${SHA1_CERT_ID}`));
            expect(result.content.some((c) => c['type'] === 'resource_link')).toBe(true);
            expect(await codeOf(createOcspRequestTool({ certificate: LEAF, issuer: INTER, outputMode: 'file', outputPath: 'ocsp/leaf.orq' }))).toBe('OUTPUT_EXISTS');
            expect(await codeOf(createOcspRequestTool({ certificate: LEAF, issuer: INTER, outputMode: 'file', outputPath: 'ocsp/leaf.key' }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(createOcspRequestTool({ certificate: LEAF, issuer: INTER, outputMode: 'file', outputPath: '../leaf.orq' }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(createOcspRequestTool({ certificate: LEAF, issuer: INTER, outputMode: 'file', outputPath: 'leaf.pem' }))).toBe('INVALID_EXTENSION');
            expect(await codeOf(createOcspRequestTool({ certificate: LEAF, issuer: INTER, outputMode: 'file', outputPath: 'leaf.orq', encoding: 'pem' }))).toBe('INVALID_EXTENSION');
            expect(await codeOf(createOcspRequestTool({ certificate: LEAF, issuer: INTER, outputMode: 'file' }))).toBe('MISSING_OUTPUT_PATH');
            expect(await codeOf(createOcspRequestTool({ certificate: LEAF, issuer: INTER, outputMode: 'file', outputPath: 'leaf.orq', encoding: 'hex' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(createOcspRequestTool({ certificate: { path: '../leaf.crt.der' }, issuer: INTER }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(createOcspRequestTool({ certificate: { path: 'missing.crt.der' }, issuer: INTER }))).toBe('INPUT_NOT_FOUND');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(createOcspRequestTool({ certificate: LEAF, issuer: INTER, outputMode: 'file', outputPath: 'leaf.orq' }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('B2-043: the PEM label', () => {
        it('B2-043: label names the PEM block of a pem artefact; a private-key label is SECURITY_VIOLATION', async () => {
            const ok = await callToolDirect('create_ocsp_request', { certificate: fixtureInput('leaf.crt.pem'), issuer: fixtureInput('inter.crt.pem'), nonce: '0a0b', encoding: 'pem', label: 'MY OCSP REQUEST' });
            expect(ok.isError).not.toBe(true);
            const block = ok.content.find((c) => c.type === 'resource') as { resource: { text?: string } };
            expect(block.resource.text).toContain('-----BEGIN MY OCSP REQUEST-----');
            expect(errorCodeOf(await callToolDirect('create_ocsp_request', { certificate: fixtureInput('leaf.crt.pem'), issuer: fixtureInput('inter.crt.pem'), encoding: 'pem', label: 'EC PRIVATE KEY' }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it.each([
            ['nothing', {}],
            ['no issuer', { certificate: LEAF }],
            ['unknown key', { certificate: LEAF, issuer: INTER, at: '2027-01-01' }],
            ['two input forms', { certificate: { pem: fixtureText('leaf.crt.pem'), derBase64: fixtureBase64('leaf.crt.der') }, issuer: INTER }],
            ['unknown hash', { certificate: LEAF, issuer: INTER, hashAlgorithm: 'SHA-512' }],
            ['nonce not hex', { certificate: LEAF, issuer: INTER, nonce: 'zz' }],
            ['nonce empty', { certificate: LEAF, issuer: INTER, nonce: '' }],
            ['nonce of 33 bytes', { certificate: LEAF, issuer: INTER, nonce: 'ab'.repeat(33) }],
            ['bad encoding', { certificate: LEAF, issuer: INTER, encoding: 'base64' }],
        ])('VALIDATION_ERROR: %s', async (_what, input) => {
            expect(await codeOf(createOcspRequestTool(input))).toBe('VALIDATION_ERROR');
        });

        it('PKI_PEM_UNEXPECTED_LABEL for a non-certificate PEM, PKI_* for non-certificate DER, and no key echo', async () => {
            expect(await codeOf(createOcspRequestTool({ certificate: LEAF, issuer: fixtureInput('inter.crl.pem') }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(createOcspRequestTool({ certificate: { derBase64: fixtureBase64('leaf.csr.der') }, issuer: INTER }))).toMatch(/^PKI_/);
            const result = await callToolDirect('create_ocsp_request', { certificate: LEAF, issuer: fixtureInput('leaf.key.pem') });
            expect(errorCodeOf(result)).toBe('PKI_PEM_UNEXPECTED_LABEL');
        });
    });

    describe('definition', () => {
        it('produces a non-idempotent artefact, cacheable unless random, with two validating examples', () => {
            expect(CREATE_OCSP_REQUEST_TOOL.kind).toBe('artefact');
            expect(CREATE_OCSP_REQUEST_TOOL.annotations).toEqual({ readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false });
            expect(CREATE_OCSP_REQUEST_TOOL.cacheable).toBe(true);
            expect(CREATE_OCSP_REQUEST_TOOL.instantInputs).toBeUndefined();
            expect(CREATE_OCSP_REQUEST_TOOL.examples?.length).toBe(2);
        });
    });
});
