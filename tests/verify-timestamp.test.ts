/**
 * Tests for `verify_timestamp` — positive verdicts (response + request,
 * token + digest, data, offline CRL), negative verdicts (other data, wrong
 * anchor, declined response, foreign OCSP, missing revocation), projection,
 * path inputs, every error code, and that a negative verdict is never
 * isError.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { verifyTimestampSummary, verifyTimestampTool, VERIFY_TIMESTAMP_TOOL } from '../src/tools/verify-timestamp.js';
import { codeOf, errorCodeOf } from './_pki-assert.js';
import { AT, fixture, fixtureBase64, fixtureInput } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const ROOT = [fixtureInput('root.crt.pem')];
const CONTENT = { base64: fixtureBase64('content.txt') };
const CONTENT_SHA256 = 'b1a1c762480b580288e0737422f01130e824c8014422371ae571880dfc642533';
const RESPONSE = fixtureInput('content.tsr');
const TOKEN = fixtureInput('content.tst');
const REQUEST = fixtureInput('content.tsq');
/** TimeStampResp { status { rejection (2) } } */
const REJECTION = { derBase64: Buffer.from('30053003020102', 'hex').toString('base64') };

describe('verify_timestamp', () => {
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
        it('verifies the response against its request and the data (TSA chain through the token certificates)', async () => {
            const r = await verifyTimestampTool({ response: RESPONSE, request: REQUEST, data: CONTENT, trustAnchors: ROOT, candidates: [fixtureInput('inter.crt.pem')], at: AT });
            expect(r.valid).toBe(true);
            expect(r.reasons).toEqual([]);
            expect(r.genTime).toBe('2026-10-04T19:05:35.000Z');
            expect(r.earliest).toBe('2026-10-04T19:05:34.000Z');
            expect(r.latest).toBe('2026-10-04T19:05:36.000Z');
            expect(r.tsa).toMatchObject({ subject: expect.stringContaining('CN=Test TSA'), serialNumber: '1005' });
            expect(r.chain?.valid).toBe(true);
            expect(r.chain?.path.map((c) => c.serialNumber)).toEqual(['1005', '02', '01']);
            expect(r.signatureVerifications).toBe(3);
            expect(r.evaluatedAt).toBe('2027-01-01T00:00:00.000Z');
            expect(r.evaluatedAtSource).toBe('input');
            expect(r.diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_CMS_SET_NOT_SORTED']);
        });

        it.each([
            ['token + digestHex', { token: TOKEN, digestHex: CONTENT_SHA256 }],
            ['token + request', { token: TOKEN, request: REQUEST }],
            ['response + data', { response: RESPONSE, data: CONTENT }],
            ['response + data + CRL under requireRevocation', { response: RESPONSE, request: REQUEST, crls: [fixtureInput('inter.crl.der')], requireRevocation: true }],
            ['allowNonCriticalTimeStampingEku and allowSha1 are accepted', { response: RESPONSE, data: CONTENT, allowNonCriticalTimeStampingEku: true, allowSha1: true }],
        ])('%s', async (_label, input) => {
            const r = await verifyTimestampTool({ trustAnchors: ROOT, at: AT, ...input });
            expect(r.valid).toBe(true);
        });
    });

    describe('negative verdicts (never isError)', () => {
        it('other data: imprint mismatch, genTime not established', async () => {
            const result = await callToolDirect('verify_timestamp', { response: RESPONSE, data: { text: 'not the content' }, trustAnchors: ROOT, at: AT, verbosity: 'summary' });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ valid: false, reasonCodes: ['PKI_REASON_TSP_IMPRINT_MISMATCH'], genTime: null, evaluatedAt: '2027-01-01T00:00:00.000Z', diagnosticCount: 1 });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('verify_timestamp: NOT OK — PKI_REASON_TSP_IMPRINT_MISMATCH') });
        });

        it.each([
            ['a one-byte digest', { token: TOKEN, digestHex: '00' }, 'PKI_REASON_TSP_IMPRINT_MISMATCH'],
            ['a declined response', { response: REJECTION, digestHex: CONTENT_SHA256 }, 'PKI_REASON_TSP_NOT_GRANTED'],
            ['the wrong trust anchor', { token: TOKEN, request: REQUEST, trustAnchors: [fixtureInput('ed25519.crt.pem')] }, 'PKI_REASON_NO_TRUST_ANCHOR'],
            ['no revocation evidence under requireRevocation', { response: RESPONSE, request: REQUEST, requireRevocation: true }, 'PKI_REASON_REVOCATION_UNKNOWN'],
            ['an OCSP response about another certificate', { response: RESPONSE, data: CONTENT, ocspResponses: [fixtureInput('leaf.ocsp.der')] }, 'PKI_REASON_REVOCATION_MISMATCH'],
        ])('%s → %s', async (_label, input, code) => {
            const r = await verifyTimestampTool({ trustAnchors: ROOT, at: AT, ...input });
            expect(r.valid).toBe(false);
            expect(r.genTime).toBeNull();
            expect(r.reasons.map((x) => x['code'])).toContain(code);
        });
    });

    describe('projection and instant', () => {
        it('summary keeps the verdict scalars; the pin and the clock back the omitted at', async () => {
            const r = await verifyTimestampTool({ token: TOKEN, digestHex: CONTENT_SHA256, trustAnchors: ROOT, at: AT });
            expect(verifyTimestampSummary(r)).toEqual({ valid: true, reasonCodes: [], genTime: '2026-10-04T19:05:35.000Z', evaluatedAt: '2027-01-01T00:00:00.000Z', diagnosticCount: 1 });
            const result = await callToolDirect('verify_timestamp', { token: TOKEN, digestHex: CONTENT_SHA256, trustAnchors: ROOT, at: AT, fields: ['valid', 'tsa.subject', 'latest'] });
            expect(result.structuredContent).toEqual({ valid: true, tsa: { subject: expect.stringContaining('CN=Test TSA') }, latest: '2026-10-04T19:05:36.000Z' });
            process.env['PKINATIVE_MCP_AT'] = AT;
            try {
                expect((await verifyTimestampTool({ token: TOKEN, digestHex: CONTENT_SHA256, trustAnchors: ROOT })).evaluatedAtSource).toBe('pinned');
            } finally {
                delete process.env['PKINATIVE_MCP_AT'];
            }
            expect((await verifyTimestampTool({ token: TOKEN, digestHex: CONTENT_SHA256, trustAnchors: ROOT })).evaluatedAtSource).toBe('clock');
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads the response, the request, the data and the anchors from the sandbox', async () => {
            sandbox = await makeSandbox();
            for (const name of ['content.tsr', 'content.tsq', 'content.txt', 'root.crt.pem']) await fs.copyFile(fixture(name), path.join(sandbox, name));
            const r = await verifyTimestampTool({ response: { path: 'content.tsr' }, request: { path: 'content.tsq' }, data: { path: 'content.txt' }, trustAnchors: [{ path: 'root.crt.pem' }], at: AT });
            expect(r.valid).toBe(true);
            expect(await codeOf(verifyTimestampTool({ response: { path: '../content.tsr' }, request: { path: 'content.tsq' }, trustAnchors: ROOT, at: AT }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(verifyTimestampTool({ response: { path: 'content.tsr' }, request: { path: 'missing.tsq' }, trustAnchors: ROOT, at: AT }))).toBe('INPUT_NOT_FOUND');
        });
    });

    describe('refusals', () => {
        it.each([
            ['neither token nor response', { request: REQUEST, trustAnchors: ROOT }],
            ['both token and response', { token: TOKEN, response: RESPONSE, request: REQUEST, trustAnchors: ROOT }],
            ['nothing stamped named (a token alone proves nothing)', { response: RESPONSE, trustAnchors: ROOT }],
            ['data and digestHex', { token: TOKEN, data: CONTENT, digestHex: CONTENT_SHA256, trustAnchors: ROOT }],
            ['no trust anchors', { response: RESPONSE, request: REQUEST }],
            ['empty trust anchors', { response: RESPONSE, request: REQUEST, trustAnchors: [] }],
            ['bad digest hex', { token: TOKEN, digestHex: 'zz', trustAnchors: ROOT }],
            ['a bad instant', { token: TOKEN, request: REQUEST, trustAnchors: ROOT, at: 'yesterday' }],
            ['purposes is not an input here', { token: TOKEN, request: REQUEST, trustAnchors: ROOT, purposes: ['timeStamping'] }],
            ['unknown key', { token: TOKEN, request: REQUEST, trustAnchors: ROOT, bogus: 1 }],
        ])('VALIDATION_ERROR: %s', async (_label, input) => {
            expect(await codeOf(verifyTimestampTool({ at: AT, ...input }))).toBe('VALIDATION_ERROR');
        });

        it('PKI_* for a request that is not a TimeStampReq, an anchor that is not a certificate, a key as a token', async () => {
            expect(await codeOf(verifyTimestampTool({ token: TOKEN, request: fixtureInput('leaf.crt.der'), trustAnchors: ROOT, at: AT }))).toBe('PKI_CMS_STRUCTURE_INVALID');
            expect(await codeOf(verifyTimestampTool({ token: TOKEN, request: REQUEST, trustAnchors: [fixtureInput('leaf.csr.pem')], at: AT }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            const result = await callToolDirect('verify_timestamp', { token: fixtureInput('leaf.key.pem'), request: REQUEST, trustAnchors: ROOT, at: AT });
            // A PEM private key is bytes the verifier cannot read: the verdict says so, and never echoes them.
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toMatchObject({ valid: false });
            expect(errorCodeOf(result)).toBeNull();
            expect(JSON.stringify(result)).not.toContain('-----BEGIN PRIVATE KEY-----\\n');
        });
    });

    describe('definition', () => {
        it('is a read-only verdict, cacheable on a pinned instant, with two examples', () => {
            expect(VERIFY_TIMESTAMP_TOOL.kind).toBe('verdict');
            expect(VERIFY_TIMESTAMP_TOOL.annotations.readOnlyHint).toBe(true);
            expect(VERIFY_TIMESTAMP_TOOL.cacheable).toBe(true);
            expect(VERIFY_TIMESTAMP_TOOL.instantInputs).toEqual(['at']);
            expect(VERIFY_TIMESTAMP_TOOL.examples?.length).toBe(2);
        });
    });
});
