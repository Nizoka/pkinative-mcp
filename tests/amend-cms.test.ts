/**
 * Tests for `amend_cms` — add-unsigned-attribute positively (round trip
 * through inspect_cms and verify_cms, determinism), add-timestamp with a
 * token over the signature value (made here with sign_cms) and the imprint
 * refusal for the fixture token (which stamps the content), the sandbox
 * file mode, every error code.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { encodeAttribute, encodeObjectIdentifier, parseSignedData } from 'pkinative';

import { callToolDirect } from '../src/server.js';
import { amendCmsTool, AMEND_CMS_TOOL } from '../src/tools/amend-cms.js';
import { createTimestampRequestTool } from '../src/tools/create-timestamp-request.js';
import { inspectCms } from '../src/tools/inspect-cms.js';
import { signCmsTool } from '../src/tools/sign-cms.js';
import { verifyCmsTool } from '../src/tools/verify-cms.js';
import { artefactBytes, assertResultClean, assertValidDer, codeOf, errorCodeOf } from './_pki-assert.js';
import { AT, fixture, fixtureBase64, fixtureInput, PASSWORD } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const ATTACHED = fixtureInput('attached.p7s');
const ATTRIBUTE = Buffer.from(encodeAttribute('1.2.3.4', [encodeObjectIdentifier('1.2.3.4.5')])).toString('hex');
const ROOT = [fixtureInput('root.crt.pem')];
/** TimeStampResp { status { rejection (2) } } */
const REJECTION = { derBase64: Buffer.from('30053003020102', 'hex').toString('base64') };

function derOf(base64: string | undefined): Uint8Array {
    return new Uint8Array(Buffer.from(base64 ?? '', 'base64'));
}

/**
 * A token over signer 0's signature value of attached.p7s: a TSTInfo built
 * by hand (version 1, policy, imprint, serial, genTime) and signed as
 * id-ct-TSTInfo by the test leaf through sign_cms. Its TSA is not a real
 * one (no timeStamping EKU), which is why only amend_cms (imprint only) and
 * not verify_cms accepts it.
 */
async function tokenOverSignature(): Promise<string> {
    const signature = parseSignedData(derOf(fixtureBase64('attached.p7s'))).signerInfos[0]?.signature ?? new Uint8Array();
    const imprint = createHash('sha256').update(signature).digest();
    const seq = (children: Buffer[]): Buffer => {
        const body = Buffer.concat(children);
        return Buffer.concat([Buffer.from([0x30, body.length]), body]);
    };
    const tstInfo = seq([
        Buffer.from('020101', 'hex'),
        Buffer.from(encodeObjectIdentifier('1.3.6.1.4.1.99999.1')),
        seq([Buffer.from('300d06096086480165030402010500', 'hex'), Buffer.concat([Buffer.from([0x04, 0x20]), imprint])]),
        Buffer.from('020107', 'hex'),
        Buffer.concat([Buffer.from([0x18, 15]), Buffer.from('20270101000000Z', 'ascii')]),
    ]);
    const r = await signCmsTool({ content: { base64: tstInfo.toString('base64') }, contentType: '1.2.840.113549.1.9.16.1.4', signingTime: AT, certificate: fixtureInput('leaf.crt.pem'), signer: { key: fixtureInput('leaf.key.pem') } });
    return r.base64 as string;
}

describe('amend_cms', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_PASSWORD'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('add-unsigned-attribute', () => {
        it('appends the attribute, leaves the signature valid, and is deterministic', async () => {
            const r = await amendCmsTool({ signedData: ATTACHED, operation: 'add-unsigned-attribute', attribute: ATTRIBUTE });
            expect(r.summary).toEqual({ operation: 'add-unsigned-attribute', signerIndex: 0, unsignedAttributes: 1, timeStampTokens: 0, tokenGenTime: null, sizeBytesBefore: 1694 });
            expect(r.sizeBytes).toBe(1694 + ATTRIBUTE.length / 2 + 2);
            const der = derOf(r.base64);
            assertValidDer(der);
            const report = await inspectCms({ signedData: { derBase64: r.base64 as string } });
            expect(report.signerInfos[0]?.unsignedAttributes).toEqual([{ oid: '1.2.3.4', name: null, valueCount: 1 }]);
            expect((await verifyCmsTool({ signedData: { derBase64: r.base64 as string }, trustAnchors: ROOT, at: AT })).valid).toBe(true);
            const again = await amendCmsTool({ signedData: ATTACHED, operation: 'add-unsigned-attribute', attribute: ATTRIBUTE });
            expect(again.sha256).toBe(r.sha256);
        });

        it('delivers the DER once through the server (hex and PEM forms too)', async () => {
            const result = await callToolDirect('amend_cms', { signedData: ATTACHED, operation: 'add-unsigned-attribute', attribute: ATTRIBUTE });
            expect(result.isError).toBeUndefined();
            assertValidDer(artefactBytes(result));
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('amend_cms: add-unsigned-attribute on signer 0: 1 unsigned attribute(s)') });
            const hex = await amendCmsTool({ signedData: ATTACHED, operation: 'add-unsigned-attribute', attribute: ATTRIBUTE, encoding: 'hex' });
            expect(hex.hex).toMatch(/^3082[0-9a-f]+$/);
            const pem = await amendCmsTool({ signedData: ATTACHED, operation: 'add-unsigned-attribute', attribute: ATTRIBUTE, encoding: 'pem' });
            expect(Buffer.from(pem.base64 ?? '', 'base64').toString('utf8')).toMatch(/^-----BEGIN CMS-----/);
        });
    });

    describe('add-timestamp', () => {
        it('refuses the fixture response and token: they stamp the content, not the signature value (nothing written)', async () => {
            for (const name of ['content.tsr', 'content.tst']) {
                const result = await callToolDirect('amend_cms', { signedData: ATTACHED, operation: 'add-timestamp', token: fixtureInput(name) });
                expect(errorCodeOf(result), name).toBe('VALIDATION_ERROR');
                expect(result._meta?.['error']).toMatchObject({
                    message: expect.stringMatching(/signature value/),
                    data: { detail: 'PKI_REASON_TSP_IMPRINT_MISMATCH', reasons: [{ code: 'PKI_REASON_TSP_IMPRINT_MISMATCH' }], remedy: expect.stringMatching(/inspect_cms fields:\['signerInfos\.signature'\]/) },
                });
                expect(result.content.some((c) => c['type'] === 'resource')).toBe(false);
            }
        });

        it('attaches a token whose imprint is the signature value, and the request for it comes from create_timestamp_request', async () => {
            const signature = (await inspectCms({ signedData: ATTACHED, fields: ['signerInfos.signature'] })).signerInfos[0]?.signature ?? '';
            const request = await createTimestampRequestTool({ data: { base64: Buffer.from(signature, 'hex').toString('base64') } });
            expect(request.summary.imprintHex).toBe(createHash('sha256').update(Buffer.from(signature, 'hex')).digest('hex'));
            const token = await tokenOverSignature();
            const r = await amendCmsTool({ signedData: ATTACHED, operation: 'add-timestamp', token: { derBase64: token }, signerIndex: 0 });
            assertResultClean(r);
            expect(r.summary).toMatchObject({ operation: 'add-timestamp', signerIndex: 0, unsignedAttributes: 1, timeStampTokens: 1, tokenGenTime: '2027-01-01T00:00:00.000Z' });
            const sd = parseSignedData(derOf(r.base64));
            expect(sd.signerInfos[0]?.timeStampTokens).toHaveLength(1);
            expect((await inspectCms({ signedData: { derBase64: r.base64 as string } })).signerInfos[0]?.unsignedAttributes?.map((a) => a.oid)).toEqual(['1.2.840.113549.1.9.16.2.14']);
        });

        it('refuses a response that carries no token, and a token that is not a SignedData', async () => {
            const rejected = await callToolDirect('amend_cms', { signedData: ATTACHED, operation: 'add-timestamp', token: REJECTION });
            expect(errorCodeOf(rejected)).toBe('VALIDATION_ERROR');
            expect(rejected._meta?.['error']).toMatchObject({ message: expect.stringMatching(/"rejection": it carries no token/), data: { status: 'rejection' } });
            expect(await codeOf(amendCmsTool({ signedData: ATTACHED, operation: 'add-timestamp', token: fixtureInput('leaf.crt.der') }))).toBe('PKI_CMS_STRUCTURE_INVALID');
        });
    });

    describe('file mode (sandbox)', () => {
        it('writes inside the sandbox, never overwrites, reads inputs from it', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('attached.p7s'), path.join(sandbox, 'attached.p7s'));
            const input = { signedData: { path: 'attached.p7s' }, operation: 'add-unsigned-attribute', attribute: ATTRIBUTE, outputMode: 'file', outputPath: 'amended.p7s' };
            const result = await callToolDirect('amend_cms', input);
            expect(result.isError).toBeUndefined();
            expect((result.structuredContent as Record<string, unknown>)['mode']).toBe('file');
            expect(result.content.some((c) => c['type'] === 'resource_link')).toBe(true);
            await fs.stat(path.join(sandbox, 'amended.p7s'));
            expect(await codeOf(amendCmsTool(input))).toBe('OUTPUT_EXISTS');
            expect(await codeOf(amendCmsTool({ ...input, outputPath: 'amended.p12' }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(amendCmsTool({ ...input, outputPath: 'amended.crt' }))).toBe('INVALID_EXTENSION');
        });
    });

    describe('refusals', () => {
        it.each([
            ['no operation', { signedData: ATTACHED, attribute: ATTRIBUTE }],
            ['unknown operation', { signedData: ATTACHED, operation: 'remove', attribute: ATTRIBUTE }],
            ['add-unsigned-attribute without attribute', { signedData: ATTACHED, operation: 'add-unsigned-attribute' }],
            ['add-unsigned-attribute with token', { signedData: ATTACHED, operation: 'add-unsigned-attribute', attribute: ATTRIBUTE, token: fixtureInput('content.tst') }],
            ['add-timestamp without token', { signedData: ATTACHED, operation: 'add-timestamp' }],
            ['add-timestamp with attribute', { signedData: ATTACHED, operation: 'add-timestamp', token: fixtureInput('content.tst'), attribute: ATTRIBUTE }],
            ['bad attribute hex', { signedData: ATTACHED, operation: 'add-unsigned-attribute', attribute: 'zz' }],
            ['negative signerIndex', { signedData: ATTACHED, operation: 'add-unsigned-attribute', attribute: ATTRIBUTE, signerIndex: -1 }],
            ['unknown key', { signedData: ATTACHED, operation: 'add-unsigned-attribute', attribute: ATTRIBUTE, bogus: 1 }],
        ])('VALIDATION_ERROR: %s', async (_label, input) => {
            expect(await codeOf(amendCmsTool(input))).toBe('VALIDATION_ERROR');
        });

        it('NOT_FOUND past the last signer, PKI_API_MISUSE for a signed-only attribute type, PKI_* for bad bytes', async () => {
            expect(await codeOf(amendCmsTool({ signedData: ATTACHED, operation: 'add-unsigned-attribute', attribute: ATTRIBUTE, signerIndex: 3 }))).toBe('NOT_FOUND');
            // signingTime (1.2.840.113549.1.9.5) is a signed-only attribute.
            expect(await codeOf(amendCmsTool({ signedData: ATTACHED, operation: 'add-unsigned-attribute', attribute: '301c06092a864886f70d010905310f170d3237303130313030303030305a' }))).toBe('PKI_API_MISUSE');
            expect(await codeOf(amendCmsTool({ signedData: fixtureInput('leaf.crt.der'), operation: 'add-unsigned-attribute', attribute: ATTRIBUTE }))).toBe('PKI_CMS_STRUCTURE_INVALID');
            expect(await codeOf(amendCmsTool({ signedData: fixtureInput('leaf.key.pem'), operation: 'add-unsigned-attribute', attribute: ATTRIBUTE }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(amendCmsTool({ signedData: { path: 'x.p7s' }, operation: 'add-unsigned-attribute', attribute: ATTRIBUTE }))).toBe('SECURITY_VIOLATION');
        });

        it('a PKCS#12 is never a SignedData, and its password is never echoed', async () => {
            const result = await callToolDirect('amend_cms', { signedData: fixtureInput('leaf.p12'), operation: 'add-unsigned-attribute', attribute: ATTRIBUTE, password: PASSWORD });
            expect(errorCodeOf(result)).toBe('VALIDATION_ERROR');
            assertResultClean(result);
        });
    });

    describe('definition', () => {
        it('writes a deterministic artefact, cacheable, with two examples', () => {
            expect(AMEND_CMS_TOOL.kind).toBe('artefact');
            expect(AMEND_CMS_TOOL.annotations).toMatchObject({ readOnlyHint: false, idempotentHint: true });
            expect(AMEND_CMS_TOOL.cacheable).toBe(true);
            expect(AMEND_CMS_TOOL.examples?.length).toBe(2);
        });
    });
});
