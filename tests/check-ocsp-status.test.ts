/**
 * Tests for `check_ocsp_status` — the good and the revoked verdict, the
 * responder's authorisation (delegate, CA itself, out-of-band trust),
 * nonces, freshness, the CertID hash, a non-successful response,
 * projection, sandbox paths, every error code.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { CHECK_OCSP_STATUS_TOOL, checkOcspStatusSummary, checkOcspStatusTool } from '../src/tools/check-ocsp-status.js';
import { assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { AT, fixture, fixtureBase64, fixtureInput, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const GOOD = fixtureInput('leaf.ocsp.der');
const REVOKED = fixtureInput('revoked.ocsp.der');
const LEAF = fixtureInput('leaf.crt.pem');
const INTER = fixtureInput('inter.crt.pem');
const ROOT = fixtureInput('root.crt.pem');
const RESPONDER = fixtureInput('ocsp.crt.pem');
/** The nonce of fixtures/leaf.ocsp-req.der, echoed by leaf.ocsp.der. */
const NONCE = '1538349c433373ed058c291909df5b3e';
const TRY_LATER = { derBase64: Buffer.from('30030a0103', 'hex').toString('base64') };
const BASE = { response: GOOD, certificate: LEAF, issuer: INTER, at: AT };

describe('check_ocsp_status', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_AT'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('verdicts', () => {
        it('the leaf is good according to the delegated responder embedded in the response', async () => {
            const r = await checkOcspStatusTool(BASE);
            expect(r).toMatchObject({
                valid: true,
                reasons: [],
                status: 'good',
                signatureVerified: true,
                responderAuthorized: true,
                responder: expect.stringContaining('CN=Test OCSP Responder'),
                responderSource: 'embedded',
                hashAlgorithm: 'SHA-256',
                certIdHex: expect.stringMatching(/^3057300d0609608648016503040201/),
                evaluatedAt: '2027-01-01T00:00:00.000Z',
                evaluatedAtSource: 'input',
            });
            expect(r.diagnostics).toEqual([]);
        });

        it('the revoked leaf is PKI_REASON_REVOKED with status revoked, never isError', async () => {
            const r = await checkOcspStatusTool({ response: REVOKED, certificate: fixtureInput('revoked.crt.pem'), issuer: INTER, at: AT });
            expect(r.valid).toBe(false);
            expect(r.status).toBe('revoked');
            expect(r.reasons.map((x) => x['code'])).toContain('PKI_REASON_REVOKED');
            const result = await callToolDirect('check_ocsp_status', { response: REVOKED, certificate: fixtureInput('revoked.crt.pem'), issuer: INTER, at: AT });
            expect(result.isError).toBeUndefined();
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringMatching(/^check_ocsp_status: NOT OK — .*PKI_REASON_REVOKED.*\(status revoked, signature verified, responder authorised/) });
        });

        it('refuses an unauthorised responder unless trusted out of band', async () => {
            const r = await checkOcspStatusTool({ response: GOOD, certificate: LEAF, issuer: ROOT, at: AT, hashAlgorithm: 'SHA-256' });
            expect(r).toMatchObject({ valid: false, signatureVerified: true, responderAuthorized: false, responderSource: 'embedded' });
            const trusted = await checkOcspStatusTool({ response: GOOD, certificate: LEAF, issuer: ROOT, at: AT, hashAlgorithm: 'SHA-256', responderTrusted: true });
            expect(trusted.responderAuthorized).toBe(true);
        });

        it('treats the CA itself as an authorised responder, and a given responder is the only candidate', async () => {
            const ca = await checkOcspStatusTool({ response: GOOD, certificate: LEAF, issuer: RESPONDER, responder: RESPONDER, at: AT });
            expect(ca).toMatchObject({ responderAuthorized: true, signatureVerified: true, responderSource: 'input' });
            const wrong = await checkOcspStatusTool({ ...BASE, responder: ROOT, allowSha1: true });
            expect(wrong).toMatchObject({ valid: false, signatureVerified: false, responderAuthorized: false, responder: null, responderSource: null });
        });

        it('matches the nonce, demands one, judges freshness and the CertID hash', async () => {
            expect((await checkOcspStatusTool({ ...BASE, nonce: NONCE })).valid).toBe(true);
            expect((await checkOcspStatusTool({ ...BASE, nonce: NONCE, requireNonce: true })).valid).toBe(true);
            const mismatch = await checkOcspStatusTool({ ...BASE, nonce: '00' });
            expect(mismatch.valid).toBe(false);
            expect(mismatch.reasons.map((x) => x['code'])).toContain('PKI_REASON_REVOCATION_MISMATCH');
            const missing = await checkOcspStatusTool({ response: REVOKED, certificate: fixtureInput('revoked.crt.pem'), issuer: INTER, at: AT, requireNonce: true });
            expect(missing.valid).toBe(false);
            expect(missing.reasons.map((x) => x['code']).join()).toMatch(/PKI_REASON_/);
            expect((await checkOcspStatusTool({ ...BASE, at: '2047-01-01', staleTolerance: 1 })).valid).toBe(false);
            expect((await checkOcspStatusTool({ ...BASE, at: '2026-01-01', futureTolerance: 1 })).valid).toBe(false);
            const sha1 = await checkOcspStatusTool({ ...BASE, hashAlgorithm: 'SHA-1' });
            expect(sha1).toMatchObject({ valid: false, hashAlgorithm: 'SHA-1', certIdHex: expect.stringMatching(/^303b300906052b0e03021a0500/) });
        });

        it('a response that does not answer the certificate, or holds no answer at all', async () => {
            const other = await checkOcspStatusTool({ response: GOOD, certificate: fixtureInput('rsa.crt.pem'), issuer: INTER, at: AT });
            expect(other).toMatchObject({ valid: false, status: null, signatureVerified: true });
            const later = await checkOcspStatusTool({ response: TRY_LATER, certificate: LEAF, issuer: INTER, at: AT });
            expect(later).toMatchObject({ valid: false, status: null, signatureVerified: false, responderAuthorized: false, responder: null, responderSource: null, hashAlgorithm: 'SHA-1' });
            expect(later.reasons.map((x) => x['code']).join()).toMatch(/PKI_REASON_/);
            expect(CHECK_OCSP_STATUS_TOOL.text(later as unknown as Record<string, unknown>)).toMatch(/\(status no answer, signature NOT verified, responder NOT authorised/);
        });
    });

    describe('projection', () => {
        it('summary keeps the scalars only', async () => {
            const r = await checkOcspStatusTool(BASE);
            expect(checkOcspStatusSummary(r)).toEqual({
                valid: true,
                reasonCodes: [],
                status: 'good',
                signatureVerified: true,
                responderAuthorized: true,
                responder: expect.stringContaining('CN=Test OCSP Responder'),
                evaluatedAt: '2027-01-01T00:00:00.000Z',
                diagnosticCount: 0,
            });
        });

        it('verbosity and fields project over the wire', async () => {
            const result = await callToolDirect('check_ocsp_status', { ...BASE, verbosity: 'summary', fields: ['valid', 'status', 'responderAuthorized'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ valid: true, status: 'good', responderAuthorized: true });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringMatching(/^check_ocsp_status: OK — status good at 2027-01-01T00:00:00.000Z, signed by CN=Test OCSP Responder.*\(embedded, authorised\)/) });
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads the inputs from the sandbox and refuses escapes', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.ocsp.der'), path.join(sandbox, 'leaf.ocsp'));
            await fs.copyFile(fixture('leaf.crt.pem'), path.join(sandbox, 'leaf.crt.pem'));
            await fs.copyFile(fixture('inter.crt.der'), path.join(sandbox, 'inter.crt.der'));
            const r = await checkOcspStatusTool({ response: { path: 'leaf.ocsp' }, certificate: { path: 'leaf.crt.pem' }, issuer: { path: 'inter.crt.der' }, at: AT });
            expect(r.valid).toBe(true);
            expect(await codeOf(checkOcspStatusTool({ ...BASE, response: { path: '../leaf.ocsp' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(checkOcspStatusTool({ ...BASE, responder: { path: 'missing.crt.pem' } }))).toBe('INPUT_NOT_FOUND');
            expect(await codeOf(checkOcspStatusTool({ ...BASE, certificate: { path: 'leaf.exe' } }))).toBe('INVALID_EXTENSION');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(checkOcspStatusTool({ ...BASE, response: { path: 'leaf.ocsp' } }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it.each([
            ['nothing', {}],
            ['no issuer', { response: GOOD, certificate: LEAF }],
            ['no certificate', { response: GOOD, issuer: INTER }],
            ['unknown key', { ...BASE, trustAnchors: [ROOT] }],
            ['two input forms', { ...BASE, certificate: { pem: fixtureText('leaf.crt.pem'), derBase64: fixtureBase64('leaf.crt.der') } }],
            ['unknown hash', { ...BASE, hashAlgorithm: 'SHA-512' }],
            ['nonce not hex', { ...BASE, nonce: 'zz' }],
            ['nonce of 33 bytes', { ...BASE, nonce: 'ab'.repeat(33) }],
            ['negative staleTolerance', { ...BASE, staleTolerance: -1 }],
            ['fractional futureTolerance', { ...BASE, futureTolerance: 0.5 }],
            ['bad instant', { ...BASE, at: '2027-02-30' }],
        ])('VALIDATION_ERROR: %s', async (_what, input) => {
            expect(await codeOf(checkOcspStatusTool(input))).toBe('VALIDATION_ERROR');
        });

        it('PKI_* for bytes that are not an OCSP response, PKI_PEM_UNEXPECTED_LABEL for a non-certificate issuer', async () => {
            expect(await codeOf(checkOcspStatusTool({ ...BASE, response: { derBase64: fixtureBase64('leaf.crt.der') } }))).toMatch(/^PKI_/);
            expect(await codeOf(checkOcspStatusTool({ ...BASE, issuer: fixtureInput('inter.crl.pem') }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(checkOcspStatusTool({ ...BASE, certificate: { derBase64: fixtureBase64('leaf.csr.der') } }))).toMatch(/^PKI_/);
        });

        it('a private key is refused as the responder and never echoed', async () => {
            const result = await callToolDirect('check_ocsp_status', { ...BASE, responder: fixtureInput('leaf.key.pem') });
            expect(errorCodeOf(result)).toBe('PKI_PEM_UNEXPECTED_LABEL');
            assertResultClean(result);
        });
    });

    describe('definition', () => {
        it('is a read-only cacheable verdict pinned on at, with two validating examples', () => {
            expect(CHECK_OCSP_STATUS_TOOL.kind).toBe('verdict');
            expect(CHECK_OCSP_STATUS_TOOL.annotations.readOnlyHint).toBe(true);
            expect(CHECK_OCSP_STATUS_TOOL.cacheable).toBe(true);
            expect(CHECK_OCSP_STATUS_TOOL.instantInputs).toEqual(['at']);
            expect(CHECK_OCSP_STATUS_TOOL.examples?.length).toBe(2);
        });
    });
});
