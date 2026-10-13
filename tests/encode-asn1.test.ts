/**
 * Tests for `encode_asn1` — every node type round-tripped through
 * decode_asn1, the three encodings and the file mode, determinism, the
 * JSON-path spec errors, the depth bound, every refusal.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { ToolError } from '../src/errors.js';
import { callToolDirect } from '../src/server.js';
import { decodeAsn1Tool } from '../src/tools/decode-asn1.js';
import { encodeAsn1Tool, ENCODE_ASN1_TOOL } from '../src/tools/encode-asn1.js';
import { artefactBytes, assertResultClean, assertValidDer, codeOf, errorCodeOf } from './_pki-assert.js';
import { AT } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const EVERY_TYPE = {
    type: 'sequence',
    children: [
        { type: 'boolean', value: true },
        { type: 'integer', value: '0x7f' },
        { type: 'integer', value: -129 },
        { type: 'integer', value: '-5' },
        { type: 'enumerated', value: 3 },
        { type: 'null' },
        { type: 'bit-string', hex: '0a', unusedBits: 1 },
        { type: 'bit-string', hex: '' },
        { type: 'named-bits', bits: [0, 5] },
        { type: 'octet-string', hex: '00ff' },
        { type: 'oid', value: '2.5.4.3' },
        { type: 'relative-oid', value: '8571.3.2' },
        { type: 'string', stringType: 'printable', value: 'FR' },
        { type: 'time', value: AT },
        { type: 'time', value: Date.UTC(2051, 0, 1), timeType: 'GeneralizedTime' },
        { type: 'set', children: [{ type: 'null' }] },
        { type: 'set-of', children: [{ type: 'integer', value: 2 }, { type: 'integer', value: 1 }] },
        { type: 'explicit', tag: 0, inner: { type: 'integer', value: 2 } },
        { type: 'implicit', tag: 1, class: 'context', inner: { type: 'octet-string', hex: 'aa' } },
        { type: 'tlv', class: 'private', tag: 5, constructed: false, hex: '01' },
        { type: 'der', hex: '0500' },
    ],
};

function nest(type: 'sequence' | 'explicit' | 'implicit', levels: number): unknown {
    let node: unknown = { type: 'null' };
    for (let i = 0; i < levels; i++) node = type === 'sequence' ? { type, children: [node] } : { type, tag: i, inner: node };
    return node;
}

describe('encode_asn1', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('encoding', () => {
        it('encodes every node type, and the bytes decode back to the expected tree', async () => {
            const result = await callToolDirect('encode_asn1', { spec: EVERY_TYPE });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toMatchObject({ mode: 'base64', encoding: 'der', summary: { rootTag: 'SEQUENCE', nodeCount: 26 }, diagnostics: [] });
            expect(JSON.stringify(result.structuredContent)).not.toContain('"base64":"');
            const bytes = artefactBytes(result);
            assertValidDer(bytes);
            const tree = await decodeAsn1Tool({ input: { derBase64: Buffer.from(bytes).toString('base64') } });
            const top = tree.nodes.filter((n) => n.depth === 1);
            expect(top.map((n) => n.tagName)).toEqual([
                'BOOLEAN', 'INTEGER', 'INTEGER', 'INTEGER', 'ENUMERATED', 'NULL', 'BIT STRING', 'BIT STRING', 'BIT STRING', 'OCTET STRING',
                'OBJECT IDENTIFIER', 'RELATIVE-OID', 'PrintableString', 'UTCTime', 'GeneralizedTime', 'SET', 'SET', '[0]', '[1]', '[PRIVATE 5]', 'NULL',
            ]);
            expect(top[1]?.preview).toBe('7f');
            expect(top[2]?.preview).toBe('ff7f');
            expect(top[10]).toMatchObject({ oid: '2.5.4.3', oidName: 'commonName' });
            expect(top[13]?.preview).toBe(Buffer.from('270101000000Z').toString('hex'));
            expect(top[14]?.preview).toBe(Buffer.from('20510101000000Z').toString('hex'));
            const setOf = tree.nodes.filter((n) => n.path.startsWith('16.'));
            expect(setOf.map((n) => n.preview)).toEqual(['01', '02']);
        });

        it('returns hex inline, PEM under a label, and is deterministic', async () => {
            const spec = { type: 'sequence', children: [{ type: 'oid', value: '1.2.840.10045.4.3.2' }] };
            const hex = await encodeAsn1Tool({ spec, encoding: 'hex' });
            expect(hex).toMatchObject({ mode: 'base64', encoding: 'hex', hex: '300a06082a8648ce3d040302', sizeBytes: 12, summary: { rootTag: 'SEQUENCE', nodeCount: 2, sizeBytes: 12 } });
            const again = await encodeAsn1Tool({ spec, encoding: 'hex' });
            expect(again.sha256).toBe(hex.sha256);
            const pem = await encodeAsn1Tool({ spec: { type: 'null' }, encoding: 'pem', label: 'TEST' });
            expect(Buffer.from(pem.base64 ?? '', 'base64').toString('utf8')).toBe('-----BEGIN TEST-----\nBQA=\n-----END TEST-----\n');
            expect(pem.mimeType).toBe('application/x-pem-file');
        });

        it('encodes negative integer strings by their magnitude and an explicit tag class', async () => {
            expect((await encodeAsn1Tool({ spec: { type: 'integer', value: '-300' }, encoding: 'hex' })).hex).toBe('0202fed4');
            expect((await encodeAsn1Tool({ spec: { type: 'enumerated', value: '-0x7f' }, encoding: 'hex' })).hex).toBe('0a0181');
            expect((await encodeAsn1Tool({ spec: { type: 'explicit', tag: 3, class: 'application', inner: { type: 'null' } }, encoding: 'hex' })).hex).toBe('63020500');
            expect((await encodeAsn1Tool({ spec: { type: 'string', stringType: 'utf8', value: 'é' }, encoding: 'hex' })).hex).toBe('0c02c3a9');
        });
    });

    describe('file mode (sandbox)', () => {
        it('writes the DER, then refuses to overwrite', async () => {
            sandbox = await makeSandbox();
            const result = await callToolDirect('encode_asn1', { spec: { type: 'null' }, outputMode: 'file', outputPath: 'out/null.asn1' });
            expect(result.isError).toBeUndefined();
            expect(result.content.some((c) => c.type === 'resource_link')).toBe(true);
            expect(result.structuredContent).toMatchObject({ mode: 'file', filePath: expect.stringContaining('null.asn1') });
            expect(new Uint8Array(await fs.readFile(path.join(sandbox, 'out', 'null.asn1')))).toEqual(new Uint8Array([5, 0]));
            expect(await codeOf(encodeAsn1Tool({ spec: { type: 'null' }, outputMode: 'file', outputPath: 'out/null.asn1' }))).toBe('OUTPUT_EXISTS');
            expect(await codeOf(encodeAsn1Tool({ spec: { type: 'null' }, outputMode: 'file', outputPath: 'out/null.crt' }))).toBe('INVALID_EXTENSION');
            expect(await codeOf(encodeAsn1Tool({ spec: { type: 'null' }, outputMode: 'file', outputPath: 'out/null.key' }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(encodeAsn1Tool({ spec: { type: 'null' }, outputMode: 'file', outputPath: '../null.der' }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(encodeAsn1Tool({ spec: { type: 'null' }, outputMode: 'file' }))).toBe('MISSING_OUTPUT_PATH');
            expect(await codeOf(encodeAsn1Tool({ spec: { type: 'null' }, encoding: 'hex', outputMode: 'file', outputPath: 'x.der' }))).toBe('VALIDATION_ERROR');
            const pem = await encodeAsn1Tool({ spec: { type: 'null' }, encoding: 'pem', label: 'TEST', outputMode: 'file', outputPath: 'out/null.pem' });
            expect(pem.mode).toBe('file');
            expect(await fs.readFile(path.join(sandbox, 'out', 'null.pem'), 'utf8')).toBe('-----BEGIN TEST-----\nBQA=\n-----END TEST-----\n');
        });

        it('refuses a file output when the sandbox is unset', async () => {
            expect(await codeOf(encodeAsn1Tool({ spec: { type: 'null' }, outputMode: 'file', outputPath: 'x.der' }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('spec errors name the JSON path', () => {
        it.each([
            [[1], 'VALIDATION_ERROR', /spec: Invalid input: expected object/],
            [{ type: 'sequence', children: [[1]] }, 'VALIDATION_ERROR', /\$\.children\[0\]: expected an object/],
            [{ type: 'frob' }, 'VALIDATION_ERROR', /\$\.type: unknown type "frob"/],
            [{ type: 'sequence', children: [{ type: 'integer', value: 1.5 }] }, 'VALIDATION_ERROR', /\$\.children\[0\]\.value: expected a safe integer/],
            [{ type: 'boolean', value: 'yes' }, 'VALIDATION_ERROR', /\$\.value: expected a boolean/],
            [{ type: 'bit-string', hex: 'zz' }, 'VALIDATION_ERROR', /\$\.hex: expected a hexadecimal string/],
            [{ type: 'bit-string', hex: '00', unusedBits: -1 }, 'VALIDATION_ERROR', /unusedBits/],
            [{ type: 'named-bits', bits: ['a'] }, 'VALIDATION_ERROR', /\$\.bits/],
            [{ type: 'string', stringType: 'klingon', value: 'x' }, 'VALIDATION_ERROR', /stringType: expected one of/],
            [{ type: 'explicit', tag: 0, class: 'weird', inner: { type: 'null' } }, 'VALIDATION_ERROR', /class: expected one of/],
            [{ type: 'explicit', tag: -1, inner: { type: 'null' } }, 'VALIDATION_ERROR', /\$\.tag: expected a tag number/],
            [{ type: 'sequence' }, 'VALIDATION_ERROR', /children: expected an array/],
            [{ type: 'time', value: 'yesterday' }, 'VALIDATION_ERROR', /\$\.value/],
            [{ type: 'der', hex: '0500ff' }, 'PKI_ASN1_TRAILING_DATA', /\$/],
            [{ type: 'oid', value: 'x.y' }, 'PKI_OID_INVALID', /\$/],
            [{ type: 'string', stringType: 'printable', value: 'é' }, /^PKI_ASN1_(STRING_INVALID|VALUE_OUT_OF_RANGE)$/, /\$/],
        ])('%j → %s', async (spec, code, message) => {
            try {
                await encodeAsn1Tool({ spec });
                expect.unreachable();
            } catch (e) {
                expect(e).toBeInstanceOf(ToolError);
                if (typeof code === 'string') expect((e as ToolError).code).toBe(code);
                else expect((e as ToolError).code).toMatch(code);
                expect((e as ToolError).message).toMatch(message);
            }
        });

        for (const type of ['sequence', 'explicit', 'implicit'] as const) {
            it(`counts one level per ${type} against limits.maxDepth`, async () => {
                expect((await encodeAsn1Tool({ spec: nest(type, 3), limits: { maxDepth: 3 } })).sizeBytes).toBeGreaterThan(0);
                const result = await callToolDirect('encode_asn1', { spec: nest(type, 4), limits: { maxDepth: 3 } });
                expect(errorCodeOf(result)).toBe('PKI_LIMIT_EXCEEDED');
                expect((result._meta?.['error'] as { data: Record<string, unknown> }).data).toMatchObject({ limit: 'maxDepth', configured: 3, observed: 4, remedy: expect.stringContaining('limits.maxDepth') });
            });
        }
    });

    describe('refusals', () => {
        it.each([
            ['no spec', {}],
            ['spec without type', { spec: { value: 1 } }],
            ['spec not an object', { spec: 'null' }],
            ['unknown key', { spec: { type: 'null' }, bogus: 1 }],
            ['pem without label', { spec: { type: 'null' }, encoding: 'pem' }],
            ['label without pem', { spec: { type: 'null' }, label: 'TEST' }],
            ['lower-case label', { spec: { type: 'null' }, encoding: 'pem', label: 'test' }],
            ['bad encoding', { spec: { type: 'null' }, encoding: 'base64' }],
        ])('VALIDATION_ERROR: %s', async (_name, input) => {
            expect(await codeOf(encodeAsn1Tool(input))).toBe('VALIDATION_ERROR');
        });

        it('SECURITY_VIOLATION for a private-key label, LIMIT_CEILING_EXCEEDED above a ceiling', async () => {
            const result = await callToolDirect('encode_asn1', { spec: { type: 'null' }, encoding: 'pem', label: 'EC PRIVATE KEY' });
            expect(errorCodeOf(result)).toBe('SECURITY_VIOLATION');
            assertResultClean(result);
            expect(await codeOf(encodeAsn1Tool({ spec: { type: 'null' }, limits: { maxInputBytes: 1024 * 1024 * 1024 } }))).toBe('LIMIT_CEILING_EXCEEDED');
        });
    });

    describe('definition', () => {
        it('is an artefact tool, WRITES, cacheable, with two validating examples', () => {
            expect(ENCODE_ASN1_TOOL.kind).toBe('artefact');
            expect(ENCODE_ASN1_TOOL.annotations).toEqual({ readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false });
            expect(ENCODE_ASN1_TOOL.cacheable).toBe(true);
            expect(ENCODE_ASN1_TOOL.instantInputs).toBeUndefined();
            expect(ENCODE_ASN1_TOOL.examples?.length).toBe(2);
        });
    });
});
