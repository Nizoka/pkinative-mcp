/**
 * Tests for `verify_cms` — positive and negative verdicts on the fixtures
 * (attached, detached with content / digest, tampered content, wrong anchor,
 * profile and revocation flags, BER, strict), projection, path inputs, every
 * error code, and that a negative verdict is never isError.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { verifyCmsSummary, verifyCmsTool, VERIFY_CMS_TOOL } from '../src/tools/verify-cms.js';
import { codeOf, errorCodeOf } from './_pki-assert.js';
import { AT, fixture, fixtureBase64, fixtureBytes, fixtureInput } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const ROOT = [fixtureInput('root.crt.pem')];
const CONTENT = { base64: fixtureBase64('content.txt') };
const CONTENT_SHA256 = 'b1a1c762480b580288e0737422f01130e824c8014422371ae571880dfc642533';

describe('verify_cms', () => {
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

    describe('positive verdicts', () => {
        it('verifies the attached message against the root (chain through the embedded intermediate)', async () => {
            const r = await verifyCmsTool({ signedData: fixtureInput('attached.p7s'), trustAnchors: ROOT, at: AT });
            expect(r.valid).toBe(true);
            expect(r.reasons).toEqual([]);
            expect(r.signerCount).toBe(1);
            expect(r.signatureVerifications).toBe(3);
            expect(r.evaluatedAt).toBe('2027-01-01T00:00:00.000Z');
            expect(r.evaluatedAtSource).toBe('input');
            expect(r.atTimeStamp).toBe(false);
            const s = r.signers[0];
            expect(s).toMatchObject({ index: 0, valid: true, intact: true, signingTime: '2026-10-04T19:05:35.000Z', timeStamps: [], reasons: [] });
            expect(s?.certificate?.subject).toContain('CN=example.test');
            expect(s?.chain?.valid).toBe(true);
            expect(s?.chain?.path.map((c) => c.serialNumber)).toEqual(['1001', '02', '01']);
            expect(r.diagnostics).toEqual([]);
        });

        it('verifies the detached signature with its content, its digest, candidates and a purpose', async () => {
            const withContent = await verifyCmsTool({ signedData: fixtureInput('detached.p7s'), content: CONTENT, trustAnchors: ROOT, candidates: [fixtureInput('inter.crt.pem')], purposes: ['emailProtection'], at: AT });
            expect(withContent.valid).toBe(true);
            const withDigest = await verifyCmsTool({ signedData: fixtureInput('detached.p7s'), contentDigest: CONTENT_SHA256, trustAnchors: ROOT, at: AT });
            expect(withDigest.valid).toBe(true);
        });

        it('accepts offline revocation evidence under requireRevocation', async () => {
            const r = await verifyCmsTool({ signedData: fixtureInput('attached.p7s'), trustAnchors: ROOT, crls: [fixtureInput('inter.crl.der')], ocspResponses: [fixtureInput('leaf.ocsp.der')], requireRevocation: true, at: AT });
            expect(r.valid).toBe(true);
        });

        it('reads BER under encodingRules ber, and reports the engine diagnostic', async () => {
            const der = fixtureBytes('attached.p7s');
            const ber = { derBase64: Buffer.concat([Buffer.from([0x30, 0x83, 0x00]), der.subarray(2)]).toString('base64') };
            const strict = await verifyCmsTool({ signedData: ber, trustAnchors: ROOT, at: AT });
            expect(strict.valid).toBe(false);
            expect(strict.reasons.map((x) => x['code'])).toEqual(['PKI_REASON_INPUT_MALFORMED']);
            const lenient = await verifyCmsTool({ signedData: ber, trustAnchors: ROOT, at: AT, encodingRules: 'ber' });
            expect(lenient.valid).toBe(true);
            expect(lenient.diagnosticCounts).toEqual({ PKI_DIAG_BER_CONSTRUCT_ACCEPTED: 1 });
        });
    });

    describe('negative verdicts (never isError)', () => {
        it('tampered content: not intact, digest mismatch', async () => {
            const tampered = Buffer.from(fixtureBytes('content.txt'));
            tampered[0] = (tampered[0] as number) ^ 1;
            const result = await callToolDirect('verify_cms', { signedData: fixtureInput('detached.p7s'), content: { base64: tampered.toString('base64') }, trustAnchors: ROOT, at: AT, verbosity: 'summary' });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toMatchObject({ valid: false, reasonCodes: ['PKI_REASON_CMS_DIGEST_MISMATCH'], signers: [{ index: 0, valid: false, intact: false, reasonCodes: ['PKI_REASON_CMS_DIGEST_MISMATCH'] }] });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('verify_cms: NOT OK — PKI_REASON_CMS_DIGEST_MISMATCH') });
        });

        it.each([
            ['detached without content', { signedData: fixtureInput('detached.p7s') }, 'PKI_REASON_CMS_CONTENT_MISSING'],
            ['wrong trust anchor', { signedData: fixtureInput('attached.p7s'), trustAnchors: [fixtureInput('ed25519.crt.pem')] }, 'PKI_REASON_NO_TRUST_ANCHOR'],
            ['missing ESS attribute under requireSigningCertificate', { signedData: fixtureInput('attached.p7s'), requireSigningCertificate: true }, 'PKI_REASON_CMS_ATTRIBUTE_INVALID'],
            ['missing CMSAlgorithmProtection under requireAlgorithmProtection', { signedData: fixtureInput('attached.p7s'), requireAlgorithmProtection: true }, 'PKI_REASON_CMS_ATTRIBUTE_INVALID'],
            ['a purpose the chain does not permit', { signedData: fixtureInput('attached.p7s'), purposes: ['timeStamping'] }, 'PKI_REASON_PURPOSE_NOT_PERMITTED'],
            ['no revocation evidence under requireRevocation', { signedData: fixtureInput('attached.p7s'), requireRevocation: true }, 'PKI_REASON_REVOCATION_UNKNOWN'],
        ])('%s → %s', async (_label, input, code) => {
            const r = await verifyCmsTool({ trustAnchors: ROOT, at: AT, ...input });
            expect(r.valid).toBe(false);
            expect(r.reasons.map((x) => x['code'])).toContain(code);
        });

        it('a time-stamp token is a SignedData: strict escalates its SET diagnostic, lenient judges it', async () => {
            expect(await codeOf(verifyCmsTool({ signedData: fixtureInput('content.tst'), trustAnchors: ROOT, at: AT, strict: true }))).toBe('PKI_STRICT_DIAGNOSTIC');
            const r = await verifyCmsTool({ signedData: fixtureInput('content.tst'), trustAnchors: ROOT, candidates: [fixtureInput('tsa.crt.pem')], at: AT });
            expect(r.valid).toBe(true);
            expect(r.diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_CMS_SET_NOT_SORTED']);
        });
    });

    describe('projection', () => {
        it('summary keeps the verdict scalars and per-signer codes', async () => {
            const r = await verifyCmsTool({ signedData: fixtureInput('attached.p7s'), trustAnchors: ROOT, at: AT });
            expect(verifyCmsSummary(r)).toEqual({ valid: true, reasonCodes: [], signers: [{ index: 0, valid: true, intact: true, reasonCodes: [] }], evaluatedAt: '2027-01-01T00:00:00.000Z', diagnosticCount: 0 });
            const result = await callToolDirect('verify_cms', { signedData: fixtureInput('attached.p7s'), trustAnchors: ROOT, at: AT, fields: ['valid', 'signers.certificate.subject'] });
            expect(result.structuredContent).toEqual({ valid: true, signers: [{ certificate: { subject: expect.stringContaining('CN=example.test') } }] });
        });
    });

    describe('instant', () => {
        it('falls back to the operator pin, then the clock', async () => {
            process.env['PKINATIVE_MCP_AT'] = AT;
            try {
                const pinned = await verifyCmsTool({ signedData: fixtureInput('attached.p7s'), trustAnchors: ROOT });
                expect(pinned.evaluatedAtSource).toBe('pinned');
                expect(pinned.evaluatedAt).toBe('2027-01-01T00:00:00.000Z');
            } finally {
                delete process.env['PKINATIVE_MCP_AT'];
            }
            expect((await verifyCmsTool({ signedData: fixtureInput('attached.p7s'), trustAnchors: ROOT })).evaluatedAtSource).toBe('clock');
            expect(await codeOf(verifyCmsTool({ signedData: fixtureInput('attached.p7s'), trustAnchors: ROOT, at: '2027-02-31' }))).toBe('VALIDATION_ERROR');
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads the message, the content and the anchors from the sandbox', async () => {
            sandbox = await makeSandbox();
            for (const name of ['detached.p7s', 'content.txt', 'root.crt.pem']) await fs.copyFile(fixture(name), path.join(sandbox, name));
            const r = await verifyCmsTool({ signedData: { path: 'detached.p7s' }, content: { path: 'content.txt' }, trustAnchors: [{ path: 'root.crt.pem' }], at: AT });
            expect(r.valid).toBe(true);
            expect(await codeOf(verifyCmsTool({ signedData: { path: '../detached.p7s' }, trustAnchors: ROOT, at: AT }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it.each([
            ['no trust anchors', { signedData: fixtureInput('attached.p7s') }],
            ['empty trust anchors', { signedData: fixtureInput('attached.p7s'), trustAnchors: [] }],
            ['content and contentDigest', { signedData: fixtureInput('detached.p7s'), content: CONTENT, contentDigest: CONTENT_SHA256, trustAnchors: ROOT }],
            ['bad digest hex', { signedData: fixtureInput('detached.p7s'), contentDigest: 'zz', trustAnchors: ROOT }],
            ['unknown purpose', { signedData: fixtureInput('attached.p7s'), trustAnchors: ROOT, purposes: ['bogus'] }],
            ['policy is not an input here', { signedData: fixtureInput('attached.p7s'), trustAnchors: ROOT, policy: { requireExplicitPolicy: true } }],
            ['unknown key', { signedData: fixtureInput('attached.p7s'), trustAnchors: ROOT, bogus: 1 }],
        ])('VALIDATION_ERROR: %s', async (_label, input) => {
            expect(await codeOf(verifyCmsTool({ at: AT, ...input }))).toBe('VALIDATION_ERROR');
        });

        it('PKI_API_MISUSE when content is given for an attached message (isError, not a verdict)', async () => {
            const result = await callToolDirect('verify_cms', { signedData: fixtureInput('attached.p7s'), content: { text: 'x' }, trustAnchors: ROOT, at: AT });
            expect(errorCodeOf(result)).toBe('PKI_API_MISUSE');
        });

        it('PKI_PEM_UNEXPECTED_LABEL for a PEM without a CMS block; a certificate as an anchor must be one', async () => {
            expect(await codeOf(verifyCmsTool({ signedData: fixtureInput('leaf.crt.pem'), trustAnchors: ROOT, at: AT }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(verifyCmsTool({ signedData: fixtureInput('attached.p7s'), trustAnchors: [fixtureInput('leaf.csr.pem')], at: AT }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
        });
    });

    describe('definition', () => {
        it('is a read-only verdict, cacheable on a pinned instant, with two examples', () => {
            expect(VERIFY_CMS_TOOL.kind).toBe('verdict');
            expect(VERIFY_CMS_TOOL.annotations.readOnlyHint).toBe(true);
            expect(VERIFY_CMS_TOOL.cacheable).toBe(true);
            expect(VERIFY_CMS_TOOL.instantInputs).toEqual(['at']);
            expect(VERIFY_CMS_TOOL.examples?.length).toBe(2);
        });
    });
});
