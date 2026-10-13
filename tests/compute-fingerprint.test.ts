/**
 * Tests for `compute_fingerprint` — the OpenSSL oracles on the fixtures,
 * every mode and formatting option, key identifiers from the three sources,
 * SHAKE256 bounds, projection, path inputs, every refusal, no secret.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { MAX_SHAKE_OUTPUT_BYTES } from '../src/caps.js';
import { computeFingerprintSummary, computeFingerprintTool, COMPUTE_FINGERPRINT_TOOL } from '../src/tools/compute-fingerprint.js';
import { assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureBase64, fixtureInput, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

// Oracles computed by OpenSSL 3.5.5 on the same fixtures (pkinative-cli tests/commands/encodings.test.ts).
const LEAF_SHA256 = '00:37:7D:D9:30:5C:C2:7F:EB:BD:1D:D3:C1:F8:5D:61:CD:49:ED:E6:04:30:74:BA:2B:7C:BA:09:9A:83:49:98';
const LEAF_SKI = '8C:82:55:89:3D:6F:73:6E:8E:C2:9A:EC:75:FE:C0:72:FA:38:31:74';

describe('compute_fingerprint', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    });

    afterEach(async () => {
        vi.restoreAllMocks();
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('fingerprint', () => {
        it('matches OpenSSL on PEM and DER', async () => {
            const pem = await computeFingerprintTool({ input: fixtureInput('leaf.crt.pem') });
            expect(pem).toMatchObject({ mode: 'fingerprint', algorithm: 'SHA-256', formatted: LEAF_SHA256, hex: LEAF_SHA256.replace(/:/g, '').toLowerCase(), sizeBytes: 701, label: 'CERTIFICATE' });
            expect(pem.from).toBeUndefined();
            expect(pem.diagnostics).toEqual([]);
            const der = await computeFingerprintTool({ input: { derBase64: fixtureBase64('leaf.crt.der') } });
            expect(der).toMatchObject({ formatted: LEAF_SHA256, label: null });
        });

        it.each([
            ['SHA-1', 40], ['SHA-256', 64], ['SHA-384', 96], ['SHA-512', 128],
        ] as const)('%s, formatted with separator and case', async (algorithm, hexLength) => {
            const r = await computeFingerprintTool({ input: fixtureInput('leaf.crt.pem'), algorithm, separator: '', letterCase: 'lower' });
            expect(r.algorithm).toBe(algorithm);
            expect(r.hex).toHaveLength(hexLength);
            expect(r.formatted).toBe(r.hex);
            const dashed = await computeFingerprintTool({ input: fixtureInput('leaf.crt.pem'), algorithm, separator: '-' });
            expect(dashed.formatted).toBe(r.hex.toUpperCase().match(/.{2}/g)?.join('-'));
        });

        it('goes through Web Crypto only when asked, with the same result', async () => {
            const digest = vi.spyOn(globalThis.crypto.subtle, 'digest');
            const plain = await computeFingerprintTool({ input: fixtureInput('leaf.crt.der') });
            expect(digest).not.toHaveBeenCalled();
            const web = await computeFingerprintTool({ input: fixtureInput('leaf.crt.der'), webcrypto: true });
            expect(digest).toHaveBeenCalledTimes(1);
            expect(web.hex).toBe(plain.hex);
        });

        it('digests any object — a CRL, a CMS, a private key — without echoing a byte of it', async () => {
            expect((await computeFingerprintTool({ input: fixtureInput('inter.crl.pem') })).label).toBe('X509 CRL');
            expect((await computeFingerprintTool({ input: fixtureInput('attached.p7s') })).sizeBytes).toBeGreaterThan(0);
            for (const name of ['leaf.key.pem', 'leaf.key.der', 'leaf.key.enc.pem', 'leaf.p12']) {
                const result = await callToolDirect('compute_fingerprint', { input: fixtureInput(name) });
                expect(result.isError, name).toBeUndefined();
                expect(result.structuredContent).toMatchObject({ mode: 'fingerprint', hex: expect.stringMatching(/^[0-9a-f]{64}$/) });
                assertResultClean(result, name);
            }
        });
    });

    describe('key-id', () => {
        it.each([
            ['leaf.crt.der', 'certificate'], ['leaf.crt.pem', 'certificate'], ['leaf.csr.pem', 'csr'], ['leaf.csr.der', 'csr'], ['leaf.pub.pem', 'spki'],
        ] as const)('computes the RFC 5280 key identifier from %s (%s)', async (name, from) => {
            const r = await computeFingerprintTool({ input: fixtureInput(name), mode: 'key-id' });
            expect(r).toMatchObject({ mode: 'key-id', algorithm: 'SHA-1', formatted: LEAF_SKI, from, sizeBytes: 65 });
        });

        it('SHA-256 on request', async () => {
            const r = await computeFingerprintTool({ input: fixtureInput('leaf.crt.der'), mode: 'key-id', algorithm: 'SHA-256' });
            expect(r.hex).toHaveLength(64);
        });

        it('refuses an object that holds no public key (PKI_*), never echoing a key', async () => {
            expect(await codeOf(computeFingerprintTool({ input: fixtureInput('inter.crl.der'), mode: 'key-id' }))).toMatch(/^PKI_/);
            expect(await codeOf(computeFingerprintTool({ input: { derBase64: Buffer.from('3006020101020102', 'hex').toString('base64') }, mode: 'key-id' }))).toBe('PKI_X509_SPKI_INVALID');
            const result = await callToolDirect('compute_fingerprint', { input: fixtureInput('leaf.key.pem'), mode: 'key-id' });
            expect(errorCodeOf(result)).toMatch(/^PKI_/);
            assertResultClean(result);
        });
    });

    describe('shake256', () => {
        it('squeezes the default and any requested length, up to the cap', async () => {
            const r = await computeFingerprintTool({ input: fixtureInput('leaf.crt.pem'), mode: 'shake256' });
            expect(r).toMatchObject({ mode: 'shake256', algorithm: 'SHAKE256', outputLength: 32 });
            expect(r.hex).toHaveLength(64);
            expect(r.formatted.split(':')).toHaveLength(32);
            const sixteen = await computeFingerprintTool({ input: fixtureInput('leaf.crt.pem'), mode: 'shake256', outputLength: 16 });
            expect(sixteen.hex).toBe(r.hex.slice(0, 32));
            const max = await computeFingerprintTool({ input: fixtureInput('leaf.crt.der'), mode: 'shake256', outputLength: MAX_SHAKE_OUTPUT_BYTES, separator: '' });
            expect(max.hex).toHaveLength(2 * MAX_SHAKE_OUTPUT_BYTES);
        });
    });

    describe('projection', () => {
        it('summary keeps mode, algorithm and hex', async () => {
            const r = await computeFingerprintTool({ input: fixtureInput('leaf.crt.pem') });
            expect(computeFingerprintSummary(r)).toEqual({ mode: 'fingerprint', algorithm: 'SHA-256', hex: r.hex, diagnosticCount: 0 });
        });

        it('fields project over the wire', async () => {
            const result = await callToolDirect('compute_fingerprint', { input: fixtureInput('leaf.csr.pem'), mode: 'key-id', fields: ['formatted', 'from', 'nope'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ formatted: LEAF_SKI, from: 'csr' });
            expect(result._meta).toEqual({ unmatchedFields: ['nope'], availableFields: expect.arrayContaining(['hex', 'label']) });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('SHA-1 key identifier (csr)') });
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads any PKI file, a key file included', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.crt.der'), path.join(sandbox, 'leaf.crt.der'));
            await fs.copyFile(fixture('leaf.key.pem'), path.join(sandbox, 'leaf.key.pem'));
            expect((await computeFingerprintTool({ input: { path: 'leaf.crt.der' } })).formatted).toBe(LEAF_SHA256);
            const key = await callToolDirect('compute_fingerprint', { input: { path: 'leaf.key.pem' }, algorithm: 'SHA-1' });
            expect(key.isError).toBeUndefined();
            assertResultClean(key);
            expect(await codeOf(computeFingerprintTool({ input: { path: '../leaf.crt.der' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(computeFingerprintTool({ input: { path: 'missing.der' } }))).toBe('INPUT_NOT_FOUND');
            expect(await codeOf(computeFingerprintTool({ input: { path: 'leaf.exe' } }))).toBe('INVALID_EXTENSION');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(computeFingerprintTool({ input: { path: 'leaf.crt.der' } }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it.each([
            ['no input', {}],
            ['unknown key', { input: fixtureInput('leaf.crt.pem'), bogus: 1 }],
            ['two input forms', { input: { pem: fixtureText('leaf.crt.pem'), derBase64: fixtureBase64('leaf.crt.der') } }],
            ['unknown mode', { input: fixtureInput('leaf.crt.pem'), mode: 'md5' }],
            ['unknown algorithm', { input: fixtureInput('leaf.crt.pem'), algorithm: 'MD5' }],
            ['SHA-512 key identifier', { input: fixtureInput('leaf.crt.pem'), mode: 'key-id', algorithm: 'SHA-512' }],
            ['algorithm with shake256', { input: fixtureInput('leaf.crt.pem'), mode: 'shake256', algorithm: 'SHA-256' }],
            ['outputLength outside shake256', { input: fixtureInput('leaf.crt.pem'), outputLength: 16 }],
            ['outputLength zero', { input: fixtureInput('leaf.crt.pem'), mode: 'shake256', outputLength: 0 }],
            ['outputLength above the cap', { input: fixtureInput('leaf.crt.pem'), mode: 'shake256', outputLength: MAX_SHAKE_OUTPUT_BYTES + 1 }],
            ['webcrypto outside fingerprint', { input: fixtureInput('leaf.crt.pem'), mode: 'key-id', webcrypto: true }],
            ['bad letterCase', { input: fixtureInput('leaf.crt.pem'), letterCase: 'mixed' }],
            ['a bundle where one object is expected', { input: { pem: fixtureText('leaf.crt.pem') + fixtureText('inter.crt.pem') } }],
        ])('VALIDATION_ERROR: %s', async (_name, input) => {
            expect(await codeOf(computeFingerprintTool(input))).toBe('VALIDATION_ERROR');
        });

        it('PKI_PEM_* for a malformed PEM text', async () => {
            expect(await codeOf(computeFingerprintTool({ input: { pem: fixtureText('leaf.crt.pem').replace(/=+\n-----END/, '\n-----END') } }))).toBe('PKI_PEM_BASE64_INVALID');
        });
    });

    describe('definition', () => {
        it('is read-only, cacheable, with two validating examples', () => {
            expect(COMPUTE_FINGERPRINT_TOOL.kind).toBe('read');
            expect(COMPUTE_FINGERPRINT_TOOL.annotations.readOnlyHint).toBe(true);
            expect(COMPUTE_FINGERPRINT_TOOL.cacheable).toBe(true);
            expect(COMPUTE_FINGERPRINT_TOOL.examples?.length).toBe(2);
        });
    });
});
