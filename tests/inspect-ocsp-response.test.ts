/**
 * Tests for `inspect_ocsp_response` — the good and the revoked answer, a
 * non-successful status, the nonce flag, the signature check (responder or
 * embedded), projection, sandbox paths, every error code.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { INSPECT_OCSP_RESPONSE_TOOL, inspectOcspResponse, inspectOcspResponseSummary } from '../src/tools/inspect-ocsp-response.js';
import { assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureBase64, fixtureInput } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const GOOD = fixtureInput('leaf.ocsp.der');
const REVOKED = fixtureInput('revoked.ocsp.der');
/** OCSPResponse { responseStatus tryLater (3) } with no responseBytes. */
const TRY_LATER = { derBase64: Buffer.from('30030a0103', 'hex').toString('base64') };

describe('inspect_ocsp_response', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('facts', () => {
        it('reports the good answer of the delegated responder, signed by the embedded certificate', async () => {
            const r = await inspectOcspResponse({ response: GOOD });
            expect(r.status).toBe('successful');
            expect(r.basicResponse).not.toBeNull();
            const basic = r.basicResponse as NonNullable<typeof r.basicResponse>;
            expect(basic.responderId).toEqual({ kind: 'byName', nameDer: expect.stringMatching(/^30/) });
            expect(basic.producedAt.iso).toMatch(/^2026-10-04T/);
            expect(basic.responses).toHaveLength(1);
            expect(basic.responses[0]).toEqual({
                certId: { hashAlgorithm: expect.objectContaining({ oid: '2.16.840.1.101.3.4.2.1' }), issuerNameHash: expect.stringMatching(/^[0-9a-f]{64}$/), issuerKeyHash: expect.stringMatching(/^[0-9a-f]{64}$/), serialNumber: '1001' },
                status: { kind: 'good' },
                thisUpdate: expect.objectContaining({ iso: expect.stringMatching(/^2026-10-04T/) }),
                nextUpdate: expect.objectContaining({ iso: '2046-09-29T19:05:34.000Z' }),
                extensions: [],
            });
            expect(basic.extensions.map((e) => e['oid'])).toEqual(['1.3.6.1.5.5.7.48.1.2']);
            expect(basic.certificates).toEqual([expect.objectContaining({ subject: expect.stringContaining('CN=Test OCSP Responder'), serialNumber: '1004' })]);
            expect(basic.signatureAlgorithm.oid).toBe('1.2.840.10045.4.3.2');
            expect(r.noncePresent).toBe(true);
            expect(r.sizeBytes).toBeGreaterThan(100);
            expect(r.signature).toEqual({ valid: true, signer: expect.stringContaining('CN=Test OCSP Responder'), source: 'embedded' });
            expect(r.diagnostics).toEqual([]);
        });

        it('reports the revoked answer with its time and reason, no nonce', async () => {
            const r = await inspectOcspResponse({ response: REVOKED });
            expect(r.basicResponse?.responses[0]?.certId.serialNumber).toBe('1002');
            expect(r.basicResponse?.responses[0]?.status).toEqual({ kind: 'revoked', revocationTime: expect.objectContaining({ iso: '2026-06-01T00:00:00.000Z' }), reason: 'keyCompromise' });
            expect(r.noncePresent).toBe(false);
        });

        it('handles a non-successful response: no answer, no signature', async () => {
            const r = await inspectOcspResponse({ response: TRY_LATER });
            expect(r).toMatchObject({ status: 'tryLater', basicResponse: null, noncePresent: false, sizeBytes: 5 });
            expect(r.signature).toBeUndefined();
            expect(inspectOcspResponseSummary(r)).toEqual({ status: 'tryLater', responses: [], noncePresent: false, diagnosticCount: 0 });
            expect(INSPECT_OCSP_RESPONSE_TOOL.text(r as unknown as Record<string, unknown>)).toBe('inspect_ocsp_response: tryLater (no signed answer), 0 diagnostic(s).');
        });
    });

    describe('signature check (one key, not authorisation)', () => {
        it('verifies against a given responder and reports the wrong one as invalid', async () => {
            const ok = await inspectOcspResponse({ response: GOOD, responder: fixtureInput('ocsp.crt.pem') });
            expect(ok.signature).toEqual({ valid: true, signer: expect.stringContaining('CN=Test OCSP Responder'), source: 'responder' });
            const bad = await inspectOcspResponse({ response: GOOD, responder: fixtureInput('root.crt.pem') });
            expect(bad.signature).toEqual({ valid: false, signer: null, source: 'responder' });
        });
    });

    describe('projection', () => {
        it('summary keeps the scalars only', async () => {
            const r = await inspectOcspResponse({ response: GOOD });
            expect(inspectOcspResponseSummary(r)).toEqual({ status: 'successful', responses: [{ serialNumber: '1001', status: 'good' }], noncePresent: true, signatureValid: true, diagnosticCount: 0 });
        });

        it('fields project over the wire and the text line names the answers', async () => {
            const result = await callToolDirect('inspect_ocsp_response', { response: REVOKED, fields: ['status', 'basicResponse.responses.status.kind', 'noncePresent'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ status: 'successful', basicResponse: { responses: [{ status: { kind: 'revoked' } }] }, noncePresent: false });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringMatching(/^inspect_ocsp_response: successful, produced .*serial 1002 revoked, nonce absent, 1 embedded certificate\(s\), signature valid \(CN=Test OCSP Responder.*embedded\)/) });
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads a response from the sandbox and refuses escapes', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.ocsp.der'), path.join(sandbox, 'leaf.ors'));
            const r = await inspectOcspResponse({ response: { path: 'leaf.ors' } });
            expect(r.status).toBe('successful');
            expect(await codeOf(inspectOcspResponse({ response: { path: '../leaf.ors' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(inspectOcspResponse({ response: { path: 'missing.ors' } }))).toBe('INPUT_NOT_FOUND');
            expect(await codeOf(inspectOcspResponse({ response: { path: 'leaf.exe' } }))).toBe('INVALID_EXTENSION');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(inspectOcspResponse({ response: { path: 'leaf.ors' } }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it.each([
            ['nothing', {}],
            ['unknown key', { response: GOOD, allowSha1: true }],
            ['two input forms', { response: { derBase64: fixtureBase64('leaf.ocsp.der'), path: 'x.der' } }],
            ['responder in two forms', { response: GOOD, responder: { pem: 'x', derBase64: 'AAAA' } }],
        ])('VALIDATION_ERROR: %s', async (_what, input) => {
            expect(await codeOf(inspectOcspResponse(input))).toBe('VALIDATION_ERROR');
        });

        it('PKI_* for bytes that are not an OCSP response, PKI_PEM_UNEXPECTED_LABEL for a non-certificate responder', async () => {
            expect(await codeOf(inspectOcspResponse({ response: { derBase64: fixtureBase64('leaf.crt.der') } }))).toMatch(/^PKI_/);
            expect(await codeOf(inspectOcspResponse({ response: GOOD, responder: fixtureInput('inter.crl.pem') }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
        });

        it('a private key is refused as the responder and never echoed', async () => {
            const result = await callToolDirect('inspect_ocsp_response', { response: GOOD, responder: fixtureInput('leaf.key.pem') });
            expect(errorCodeOf(result)).toBe('PKI_PEM_UNEXPECTED_LABEL');
            assertResultClean(result);
        });
    });

    describe('definition', () => {
        it('is read-only, cacheable, with two validating examples', () => {
            expect(INSPECT_OCSP_RESPONSE_TOOL.kind).toBe('read');
            expect(INSPECT_OCSP_RESPONSE_TOOL.annotations.readOnlyHint).toBe(true);
            expect(INSPECT_OCSP_RESPONSE_TOOL.cacheable).toBe(true);
            expect(INSPECT_OCSP_RESPONSE_TOOL.instantInputs).toBeUndefined();
            expect(INSPECT_OCSP_RESPONSE_TOOL.examples?.length).toBe(2);
        });
    });
});
