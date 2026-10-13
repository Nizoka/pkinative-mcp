/**
 * Tests for `create_timestamp_request` — the TimeStampReq over data or a
 * digest, every option (hash, nonce random / pinned, policy, certReq), the
 * exact bytes against the OpenSSL fixture request, the round trip through
 * verify_timestamp, the sandbox file mode, every error code.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { decodeAsn1 } from 'pkinative';

import { callToolDirect } from '../src/server.js';
import { createTimestampRequestTool, CREATE_TIMESTAMP_REQUEST_TOOL } from '../src/tools/create-timestamp-request.js';
import { verifyTimestampTool } from '../src/tools/verify-timestamp.js';
import { artefactBytes, assertValidDer, codeOf } from './_pki-assert.js';
import { AT, fixture, fixtureBase64, fixtureBytes, fixtureInput } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const CONTENT = { base64: fixtureBase64('content.txt') };
const CONTENT_SHA256 = 'b1a1c762480b580288e0737422f01130e824c8014422371ae571880dfc642533';
/** The nonce OpenSSL wrote into content.tsq (INTEGER 09542fc792be1438). */
const FIXTURE_NONCE = BigInt('0x09542fc792be1438').toString(10);

function derOf(base64: string | undefined): Uint8Array {
    return new Uint8Array(Buffer.from(base64 ?? '', 'base64'));
}

/** The members after the messageImprint of a TimeStampReq: reqPolicy, nonce, certReq. */
function trailing(der: Uint8Array): string[] {
    return decodeAsn1(der).children.slice(2).map((n) => Buffer.from(n.bytes).toString('hex'));
}

describe('create_timestamp_request', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('building', () => {
        it('reproduces the OpenSSL fixture request byte for byte (same hash, nonce, certReq)', async () => {
            const r = await createTimestampRequestTool({ data: CONTENT, nonce: FIXTURE_NONCE });
            expect(r.summary).toEqual({ hashAlgorithm: 'SHA-256', imprintHex: CONTENT_SHA256, nonce: FIXTURE_NONCE, randomNonce: false, policy: null, certReq: true, dataBytes: 27 });
            expect(Buffer.from(derOf(r.base64)).equals(fixtureBytes('content.tsq'))).toBe(true);
            expect(r.mimeType).toBe('application/timestamp-query');
            expect(r.diagnostics).toEqual([]);
        });

        it('writes the digest, policy, 0x nonce and certReq false it is given', async () => {
            const r = await createTimestampRequestTool({ digestHex: '00'.repeat(48), hashAlgorithm: 'SHA-384', nonce: '0x2a', policy: '1.2.3', certReq: false, encoding: 'hex' });
            expect(r.summary).toEqual({ hashAlgorithm: 'SHA-384', imprintHex: '00'.repeat(48), nonce: '42', randomNonce: false, policy: '1.2.3', certReq: false, dataBytes: null });
            expect(r.hex).toMatch(/^30[0-9a-f]+$/);
            expect(trailing(derOf(Buffer.from(r.hex ?? '', 'hex').toString('base64')))).toEqual(['06022a03', '02012a']);
            const bare = await createTimestampRequestTool({ digestHex: CONTENT_SHA256 });
            expect(trailing(derOf(bare.base64))).toEqual(['0101ff']);
            expect(bare.summary.nonce).toBeNull();
        });

        it("draws a random 63-bit nonce on 'random' and says so", async () => {
            const a = await createTimestampRequestTool({ data: { text: 'x' }, nonce: 'random' });
            const b = await createTimestampRequestTool({ data: { text: 'x' }, nonce: 'random' });
            expect(a.summary.randomNonce).toBe(true);
            expect(a.summary.nonce).toMatch(/^\d+$/);
            expect(BigInt(a.summary.nonce ?? '0') < 2n ** 63n).toBe(true);
            expect(a.summary.nonce).not.toBe(b.summary.nonce);
            expect(a.sha256).not.toBe(b.sha256);
        });

        it('accepts SHA-512 and text / base64 data', async () => {
            const r = await createTimestampRequestTool({ data: { text: 'hello' }, hashAlgorithm: 'SHA-512' });
            expect(r.summary.imprintHex).toHaveLength(128);
            expect(r.summary.dataBytes).toBe(5);
        });

        it('its request verifies the fixture response (the request is what ties the two)', async () => {
            const r = await createTimestampRequestTool({ data: CONTENT, nonce: FIXTURE_NONCE });
            const verdict = await verifyTimestampTool({ response: fixtureInput('content.tsr'), request: { derBase64: r.base64 as string }, trustAnchors: [fixtureInput('root.crt.pem')], at: AT });
            expect(verdict.valid).toBe(true);
            const other = await createTimestampRequestTool({ data: CONTENT, nonce: '7' });
            const mismatch = await verifyTimestampTool({ response: fixtureInput('content.tsr'), request: { derBase64: other.base64 as string }, trustAnchors: [fixtureInput('root.crt.pem')], at: AT });
            expect(mismatch.valid).toBe(false);
            expect(mismatch.reasons.map((x) => x['code'])).toContain('PKI_REASON_TSP_REQUEST_MISMATCH');
        });
    });

    describe('through the server', () => {
        it('delivers the DER once as an embedded resource', async () => {
            const result = await callToolDirect('create_timestamp_request', { digestHex: CONTENT_SHA256, nonce: '1' });
            expect(result.isError).toBeUndefined();
            assertValidDer(artefactBytes(result));
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('create_timestamp_request: TimeStampReq SHA-256 b1a1c762480b5802…, nonce 1') });
            expect((result.structuredContent as Record<string, unknown>)['base64']).toBeUndefined();
        });
    });

    describe('file mode (sandbox)', () => {
        it('writes a .tsq inside the sandbox, never overwrites, hashes a sandbox file', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('content.txt'), path.join(sandbox, 'content.txt'));
            const input = { data: { path: 'content.txt' }, outputMode: 'file', outputPath: 'req/content.tsq' };
            const result = await callToolDirect('create_timestamp_request', input);
            expect(result.isError).toBeUndefined();
            expect((result.structuredContent as Record<string, unknown>)['summary']).toMatchObject({ imprintHex: CONTENT_SHA256, dataBytes: 27 });
            expect(result.content.some((c) => c['type'] === 'resource_link')).toBe(true);
            await fs.stat(path.join(sandbox, 'req', 'content.tsq'));
            expect(await codeOf(createTimestampRequestTool(input))).toBe('OUTPUT_EXISTS');
            expect(await codeOf(createTimestampRequestTool({ ...input, outputPath: 'req/content.p7s' }))).toBe('INVALID_EXTENSION');
            expect(await codeOf(createTimestampRequestTool({ ...input, outputPath: 'req/content.pem', encoding: 'pem' }))).toBe('OK');
            expect(await codeOf(createTimestampRequestTool({ data: { path: '../content.txt' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(createTimestampRequestTool({ data: { path: 'missing.txt' } }))).toBe('INPUT_NOT_FOUND');
        });
    });

    describe('refusals', () => {
        it.each([
            ['neither data nor digestHex', {}],
            ['both data and digestHex', { data: CONTENT, digestHex: CONTENT_SHA256 }],
            ['a digest of the wrong length', { digestHex: '00', hashAlgorithm: 'SHA-384' }],
            ['a SHA-256 digest with SHA-512', { digestHex: CONTENT_SHA256, hashAlgorithm: 'SHA-512' }],
            ['bad hex', { digestHex: 'zz' }],
            ['an unsupported hash', { data: CONTENT, hashAlgorithm: 'SHA-1' }],
            ['a bad nonce', { data: CONTENT, nonce: 'x' }],
            ['a bad policy', { data: CONTENT, policy: 'tsa' }],
            ['two content forms', { data: { text: 'a', base64: 'YQ==' } }],
            ['hex to a file', { data: CONTENT, outputMode: 'file', outputPath: 'x.tsq', encoding: 'hex' }],
            ['unknown key', { data: CONTENT, bogus: 1 }],
        ])('VALIDATION_ERROR: %s', async (_label, input) => {
            expect(await codeOf(createTimestampRequestTool(input))).toBe('VALIDATION_ERROR');
        });

        it('MISSING_OUTPUT_PATH in file mode without a path, SECURITY_VIOLATION without a sandbox', async () => {
            expect(await codeOf(createTimestampRequestTool({ data: CONTENT, outputMode: 'file' }))).toBe('MISSING_OUTPUT_PATH');
            expect(await codeOf(createTimestampRequestTool({ data: CONTENT, outputMode: 'file', outputPath: 'x.tsq' }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('definition', () => {
        it("produces, is cacheable except on 'random' (the server's gate), with two examples", () => {
            expect(CREATE_TIMESTAMP_REQUEST_TOOL.kind).toBe('artefact');
            expect(CREATE_TIMESTAMP_REQUEST_TOOL.annotations.idempotentHint).toBe(false);
            expect(CREATE_TIMESTAMP_REQUEST_TOOL.cacheable).toBe(true);
            expect(CREATE_TIMESTAMP_REQUEST_TOOL.examples?.length).toBe(2);
        });
    });
});
