/**
 * Tests for `inspect_cms` — the SignedData report, the signer views, the
 * one-key signature check, trailing data / BER, projection, path inputs,
 * every error code.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { inspectCms, inspectCmsSummary, INSPECT_CMS_TOOL } from '../src/tools/inspect-cms.js';
import { assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureBase64, fixtureBytes, fixtureInput } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const CONTENT = { base64: fixtureBase64('content.txt') };

describe('inspect_cms', () => {
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
        it('reports the attached SignedData', async () => {
            const r = await inspectCms({ signedData: fixtureInput('attached.p7s') });
            expect(r.version).toBe(1);
            expect(r.contentType).toEqual({ oid: '1.2.840.113549.1.7.1', name: 'data' });
            expect(r.contentLength).toBe(27);
            expect(r.digestAlgorithms.map((a) => a.name)).toEqual(['sha256']);
            expect(r.certificates.map((c) => c.subject)).toEqual([expect.stringContaining('CN=Test Intermediate CA'), expect.stringContaining('CN=example.test')]);
            expect(r.crlCount).toBe(0);
            expect(r.ocspResponseCount).toBe(0);
            expect(r.sizeBytes).toBe(fixtureBytes('attached.p7s').length);
            const s = r.signerInfos[0];
            expect(r.signerInfos).toHaveLength(1);
            expect(s?.version).toBe(1);
            expect(s?.sid).toEqual({ kind: 'issuerAndSerialNumber', issuer: expect.stringContaining('CN=Test Intermediate CA'), serialNumber: '1001' });
            expect(s?.digestAlgorithm.name).toBe('sha256');
            expect(s?.signatureAlgorithm.name).toBe('ecdsa-with-SHA256');
            expect(s?.signingTime).toBe('2026-10-04T19:05:35.000Z');
            expect(s?.signingCertificate).toBeNull();
            expect(s?.algorithmProtection).toBeNull();
            expect(s?.signedAttributes?.map((a) => a.name)).toEqual(['contentType', 'signingTime', 'messageDigest', 'smimeCapabilities']);
            expect(s?.unsignedAttributes).toBeNull();
            expect(s?.timeStampTokens).toBe(0);
            expect(s?.signature).toMatch(/^30[0-9a-f]+$/);
            expect(r.signerSignature).toBeUndefined();
            expect(r.diagnostics).toEqual([]);
        });

        it('reports a detached SignedData (contentLength null)', async () => {
            const r = await inspectCms({ signedData: fixtureInput('detached.p7s') });
            expect(r.contentLength).toBeNull();
            expect(r.certificates).toHaveLength(2);
        });

        it('reads a time-stamp token as the SignedData it is (id-ct-TSTInfo, with the OpenSSL SET diagnostic)', async () => {
            const r = await inspectCms({ signedData: fixtureInput('content.tst') });
            expect(r.contentType.oid).toBe('1.2.840.113549.1.9.16.1.4');
            expect(r.signerInfos[0]?.signingCertificate).toMatchObject({ version: 2, certIds: [{ hashAlgorithm: 'SHA-256', certHash: expect.stringMatching(/^[0-9a-f]{64}$/) }] });
            expect(r.diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_CMS_SET_NOT_SORTED']);
            expect(await codeOf(inspectCms({ signedData: fixtureInput('content.tst'), strict: true }))).toBe('PKI_STRICT_DIAGNOSTIC');
        });
    });

    describe('signature check (one key, not trust)', () => {
        it('verifies the signer against its certificate, attached and detached', async () => {
            const attached = await inspectCms({ signedData: fixtureInput('attached.p7s'), signerCertificate: fixtureInput('leaf.crt.pem') });
            expect(attached.signerSignature).toEqual({ index: 0, valid: true, signerSubject: expect.stringContaining('CN=example.test') });
            const detached = await inspectCms({ signedData: fixtureInput('detached.p7s'), signerCertificate: fixtureInput('leaf.crt.pem'), content: CONTENT, signerIndex: 0 });
            expect(detached.signerSignature?.valid).toBe(true);
        });

        it('reports an invalid signature under the wrong certificate (no isError)', async () => {
            const r = await inspectCms({ signedData: fixtureInput('attached.p7s'), signerCertificate: fixtureInput('rsa.crt.pem') });
            expect(r.signerSignature?.valid).toBe(false);
        });
    });

    describe('trailing data and BER', () => {
        it('refuses trailing bytes unless allowed, and BER lengths unless encodingRules ber', async () => {
            const der = fixtureBytes('attached.p7s');
            const trailing = { derBase64: Buffer.concat([der, Buffer.from([0])]).toString('base64') };
            expect(await codeOf(inspectCms({ signedData: trailing }))).toBe('PKI_ASN1_TRAILING_DATA');
            expect((await inspectCms({ signedData: trailing, allowTrailingData: true })).contentLength).toBe(27);
            const ber = { derBase64: Buffer.concat([Buffer.from([0x30, 0x83, 0x00]), der.subarray(2)]).toString('base64') };
            expect(await codeOf(inspectCms({ signedData: ber }))).toBe('PKI_ASN1_LENGTH_NON_MINIMAL');
            expect((await inspectCms({ signedData: ber, encodingRules: 'ber' })).signerInfos).toHaveLength(1);
        });
    });

    describe('projection', () => {
        it('summary keeps the scalars only', async () => {
            const r = await inspectCms({ signedData: fixtureInput('attached.p7s'), signerCertificate: fixtureInput('leaf.crt.pem') });
            expect(inspectCmsSummary(r)).toEqual({
                version: 1,
                contentTypeOid: '1.2.840.113549.1.7.1',
                contentLength: 27,
                signerCount: 1,
                signers: [{ index: 0, signingTime: '2026-10-04T19:05:35.000Z', timeStampTokens: 0 }],
                signerSignatureValid: true,
                diagnosticCount: 0,
            });
        });

        it('fields:[signerInfos.signature] returns the value a counter time-stamp stamps', async () => {
            const result = await callToolDirect('inspect_cms', { signedData: fixtureInput('attached.p7s'), fields: ['signerInfos.signature'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ signerInfos: [{ signature: expect.stringMatching(/^30[0-9a-f]+$/) }] });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('inspect_cms: SignedData v1') });
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads a .p7s from the sandbox and refuses escapes', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('detached.p7s'), path.join(sandbox, 'detached.p7s'));
            expect((await inspectCms({ signedData: { path: 'detached.p7s' } })).contentLength).toBeNull();
            expect(await codeOf(inspectCms({ signedData: { path: '../detached.p7s' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(inspectCms({ signedData: { path: 'missing.p7s' } }))).toBe('INPUT_NOT_FOUND');
        });
    });

    describe('refusals', () => {
        it.each([
            ['unknown key', { signedData: fixtureInput('attached.p7s'), bogus: 1 }],
            ['content without signerCertificate', { signedData: fixtureInput('attached.p7s'), content: CONTENT }],
            ['two input forms', { signedData: { derBase64: fixtureBase64('attached.p7s'), path: 'x.p7s' } }],
            ['no input', {}],
        ])('VALIDATION_ERROR: %s', async (_label, input) => {
            expect(await codeOf(inspectCms(input))).toBe('VALIDATION_ERROR');
        });

        it('NOT_FOUND for a signerIndex past the last signer', async () => {
            expect(await codeOf(inspectCms({ signedData: fixtureInput('attached.p7s'), signerCertificate: fixtureInput('leaf.crt.pem'), signerIndex: 4 }))).toBe('NOT_FOUND');
        });

        it('PKI_PEM_UNEXPECTED_LABEL for a PEM without a CMS block, PKI_CMS_STRUCTURE_INVALID for other DER', async () => {
            const result = await callToolDirect('inspect_cms', { signedData: fixtureInput('leaf.key.pem') });
            expect(errorCodeOf(result)).toBe('PKI_PEM_UNEXPECTED_LABEL');
            assertResultClean(result);
            expect(await codeOf(inspectCms({ signedData: fixtureInput('leaf.crt.der') }))).toBe('PKI_CMS_STRUCTURE_INVALID');
        });
    });

    describe('definition', () => {
        it('is read-only, cacheable, with two examples', () => {
            expect(INSPECT_CMS_TOOL.kind).toBe('read');
            expect(INSPECT_CMS_TOOL.annotations.readOnlyHint).toBe(true);
            expect(INSPECT_CMS_TOOL.cacheable).toBe(true);
            expect(INSPECT_CMS_TOOL.examples?.length).toBe(2);
        });
    });
});
