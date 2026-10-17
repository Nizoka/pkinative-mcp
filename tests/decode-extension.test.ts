/**
 * Tests for `decode_extension` — known kinds, unknown OIDs, the malformed
 * refusal with its remedy, both value forms, projection, path inputs.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { ToolError } from '../src/errors.js';
import { callToolDirect } from '../src/server.js';
import { decodeExtension, decodeExtensionSummary, DECODE_EXTENSION_TOOL } from '../src/tools/decode-extension.js';
import { inspectCertificate } from '../src/tools/inspect-certificate.js';
import { codeOf, errorCodeOf } from './_pki-assert.js';
import { fixtureInput } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

describe('decode_extension', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('known kinds', () => {
        it('decodes a critical basicConstraints', async () => {
            const r = await decodeExtension({ oid: '2.5.29.19', valueHex: '30030101ff', critical: true });
            expect(r).toMatchObject({ kind: 'basicConstraints', oid: '2.5.29.19', name: 'basicConstraints', critical: true, sizeBytes: 5, decoded: { cA: true } });
            expect(r.decoded).not.toHaveProperty('valueDer');
            expect(r.decoded).not.toHaveProperty('kind');
            expect(r.diagnostics).toEqual([]);
            expect(r.diagnosticCounts).toEqual({});
        });

        it.each([
            ['2.5.29.37', '300a06082b06010505070301', 'extendedKeyUsage', { purposes: ['1.3.6.1.5.5.7.3.1'] }],
            ['2.5.29.15', '03020780', 'keyUsage', { usages: ['digitalSignature'] }],
            ['2.5.29.17', '30088206612e74657374', 'subjectAltName', { names: [{ kind: 'dNSName', value: 'a.test' }] }],
            ['2.5.29.14', '0402a1b2', 'subjectKeyIdentifier', { keyIdentifier: 'a1b2' }],
            ['2.5.29.35', '30048002a1b2', 'authorityKeyIdentifier', { keyIdentifier: 'a1b2' }],
        ])('%s → %s', async (oid, valueHex, kind, decoded) => {
            const r = await decodeExtension({ oid, valueHex });
            expect(r.kind).toBe(kind);
            expect(r.critical).toBe(false);
            expect(r.decoded).toMatchObject(decoded);
        });

        it('decodes the raw extensions of a real certificate back to what inspect_certificate shows', async () => {
            const raw = await inspectCertificate({ certificate: fixtureInput('leaf.crt.pem'), rawExtensions: true });
            const full = await inspectCertificate({ certificate: fixtureInput('leaf.crt.pem') });
            for (const [i, ext] of raw.extensions.entries()) {
                const r = await decodeExtension({ oid: ext['oid'] as string, valueHex: ext['valueDer'] as string, critical: ext['critical'] as boolean });
                const expected = full.extensions[i] as Record<string, unknown>;
                expect(r.kind, String(ext['oid'])).toBe(expected['kind']);
                for (const [k, v] of Object.entries(expected)) {
                    if (['kind', 'oid', 'name', 'critical'].includes(k)) continue;
                    expect(r.decoded[k], `${String(ext['oid'])}.${k}`).toEqual(v);
                }
            }
        });

        it('accepts the value as DER (derBase64) with 0x / colon hex tolerated', async () => {
            const a = await decodeExtension({ oid: '2.5.29.19', value: { derBase64: Buffer.from('30030101ff', 'hex').toString('base64') } });
            const b = await decodeExtension({ oid: '2.5.29.19', valueHex: '0x30:03:01:01:ff' });
            expect(a.decoded).toEqual(b.decoded);
            expect(a.kind).toBe('basicConstraints');
        });
    });

    describe('unknown and malformed', () => {
        it('an unregistered OID is kind unknown with its size (no members)', async () => {
            const r = await decodeExtension({ oid: '1.2.3.4', valueHex: '0500' });
            expect(r).toMatchObject({ kind: 'unknown', oid: '1.2.3.4', name: null, critical: false, sizeBytes: 2, decoded: {} });
        });

        it('PKI_X509_EXTENSION_MALFORMED with the decode_asn1 remedy', async () => {
            try {
                await decodeExtension({ oid: '2.5.29.19', valueHex: '0500' });
                expect.unreachable();
            } catch (e) {
                expect(e).toBeInstanceOf(ToolError);
                expect((e as ToolError).code).toBe('PKI_X509_EXTENSION_MALFORMED');
                expect((e as ToolError).data).toMatchObject({ errorClass: 'parse', remedy: expect.stringContaining('decode_asn1') });
            }
            const result = await callToolDirect('decode_extension', { oid: '2.5.29.9', valueHex: '300f300d0603550406310613024652' });
            expect(errorCodeOf(result)).toMatch(/^PKI_/);
        });
    });

    describe('projection', () => {
        it('summary keeps the scalars; fields project over the wire', async () => {
            const r = await decodeExtension({ oid: '2.5.29.37', valueHex: '300a06082b06010505070301' });
            expect(decodeExtensionSummary(r)).toEqual({ kind: 'extendedKeyUsage', oid: '2.5.29.37', name: 'extKeyUsage', critical: false, sizeBytes: 12, diagnosticCount: 0 });
            const result = await callToolDirect('decode_extension', { oid: '2.5.29.37', valueHex: '300a06082b06010505070301', fields: ['kind', 'decoded.purposes', 'nope'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ kind: 'extendedKeyUsage', decoded: { purposes: ['1.3.6.1.5.5.7.3.1'] } });
            expect(result._meta).toEqual({ unmatchedFields: ['nope'], availableFields: expect.arrayContaining(['kind', 'decoded']) });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('decode_extension: 2.5.29.37 (extKeyUsage) decoded as extendedKeyUsage') });
            const summary = await callToolDirect('decode_extension', { oid: '2.5.29.37', valueHex: '300a06082b06010505070301', verbosity: 'summary' });
            expect(summary.structuredContent).toEqual({ kind: 'extendedKeyUsage', oid: '2.5.29.37', name: 'extKeyUsage', critical: false, sizeBytes: 12, diagnosticCount: 0 });
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads the value from a sandbox file and refuses escapes', async () => {
            sandbox = await makeSandbox();
            await fs.writeFile(path.join(sandbox, 'bc.bin'), Buffer.from('30030101ff', 'hex'));
            const r = await decodeExtension({ oid: '2.5.29.19', value: { path: 'bc.bin' } });
            expect(r.decoded).toEqual({ cA: true });
            expect(await codeOf(decodeExtension({ oid: '2.5.29.19', value: { path: '../bc.bin' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(decodeExtension({ oid: '2.5.29.19', value: { path: 'missing.bin' } }))).toBe('INPUT_NOT_FOUND');
            expect(await codeOf(decodeExtension({ oid: '2.5.29.19', value: { path: 'bc.txt' } }))).toBe('INVALID_EXTENSION');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(decodeExtension({ oid: '2.5.29.19', value: { path: 'bc.bin' } }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it('VALIDATION_ERROR: both or neither value form, a bad OID, a bad hex, an unknown key', async () => {
            expect(await codeOf(decodeExtension({ oid: '2.5.29.19' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(decodeExtension({ oid: '2.5.29.19', valueHex: '0500', value: { derBase64: 'BQA=' } }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(decodeExtension({ oid: 'basicConstraints', valueHex: '0500' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(decodeExtension({ oid: '2.5.29.19', valueHex: 'zz' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(decodeExtension({ oid: '2.5.29.19', valueHex: '0500', bogus: 1 }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(decodeExtension({}))).toBe('VALIDATION_ERROR');
        });
    });

    describe('definition', () => {
        it('is read-only, cacheable, with two validating examples', () => {
            expect(DECODE_EXTENSION_TOOL.kind).toBe('read');
            expect(DECODE_EXTENSION_TOOL.annotations.readOnlyHint).toBe(true);
            expect(DECODE_EXTENSION_TOOL.cacheable).toBe(true);
            expect(DECODE_EXTENSION_TOOL.examples?.length).toBe(2);
        });
    });
});
