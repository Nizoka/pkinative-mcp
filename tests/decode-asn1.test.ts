/**
 * Tests for `decode_asn1` — the tree of the fixtures, every typed reader,
 * node selection, re-encoding (inline and file), sequences, BER, the
 * secret guard on keys and PKCS#12, projection, every refusal, no secret.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { MAX_PREVIEW_BYTES } from '../src/caps.js';
import { decodeAsn1Summary, decodeAsn1Tool, DECODE_ASN1_TOOL, selectNode, tagName } from '../src/tools/decode-asn1.js';
import { artefactBytes, assertResultClean, assertValidDer, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureBase64, fixtureBytes, fixtureInput, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const der = (hex: string): { derBase64: string } => ({ derBase64: Buffer.from(hex.replace(/ /g, ''), 'hex').toString('base64') });

describe('decode_asn1', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('tree', () => {
        it('lists the certificate tree depth-first with offsets, tags, previews and OID names', async () => {
            const r = await decodeAsn1Tool({ input: fixtureInput('root.crt.der') });
            expect(r).toMatchObject({ label: null, sizeBytes: 471, nodeCount: 60, truncated: false });
            expect(r.nodes[0]).toEqual({ root: 0, path: '', depth: 0, offset: 0, headerLength: 4, contentLength: 467, indefinite: false, tagClass: 'universal', tagNumber: 16, tagName: 'SEQUENCE', constructed: true, childCount: 3 });
            expect(r.nodes[1]).toMatchObject({ path: '0', depth: 1, tagName: 'SEQUENCE', childCount: 8 });
            expect(r.nodes[2]).toMatchObject({ path: '0.0', tagClass: 'context', tagNumber: 0, tagName: '[0]', constructed: true });
            expect(r.nodes[3]).toMatchObject({ path: '0.0.0', tagName: 'INTEGER', preview: '02', childCount: 0 });
            expect(r.nodes.find((n) => n.path === '0.2.0')).toMatchObject({ tagName: 'OBJECT IDENTIFIER', oid: '1.2.840.10045.4.3.2', oidName: 'ecdsa-with-SHA256', preview: '2a8648ce3d040302' });
            expect(r.nodes.find((n) => n.path === '0.3.0.0.1')).toMatchObject({ tagName: 'PrintableString', preview: '4652' });
            expect(r.nodes.find((n) => n.path === '0.4.0')).toMatchObject({ tagName: 'UTCTime' });
            expect(r.nodes.filter((n) => n.preview !== undefined).every((n) => n.constructed === false)).toBe(true);
            const bits = r.nodes.find((n) => n.path === '2');
            expect(bits).toMatchObject({ tagName: 'BIT STRING', previewTruncated: true });
            expect(bits?.preview).toHaveLength(2 * MAX_PREVIEW_BYTES);
            expect(r.diagnostics).toEqual([]);
        });

        it('honours maxPreviewBytes (0 hides previews) and keeps the PEM label', async () => {
            const r = await decodeAsn1Tool({ input: fixtureInput('leaf.crt.pem'), maxPreviewBytes: 0 });
            expect(r.label).toBe('CERTIFICATE');
            expect(r.nodes.every((n) => n.preview === undefined)).toBe(true);
            const four = await decodeAsn1Tool({ input: fixtureInput('leaf.crt.pem'), maxPreviewBytes: 4 });
            expect(four.nodes.find((n) => n.path === '2')?.preview).toHaveLength(8);
        });

        it('names every tag class and unknown universal tags', async () => {
            const r = await decodeAsn1Tool({ input: der('30170500 0a0102 0d04c27b0302 1f2201ff 6003020101 c00100') });
            expect(r.nodes.map((n) => n.tagName)).toEqual(['SEQUENCE', 'NULL', 'ENUMERATED', 'RELATIVE-OID', 'DURATION', '[APPLICATION 0]', 'INTEGER', '[PRIVATE 0]']);
            expect(tagName({ tagClass: 'universal', tagNumber: 99 })).toBe('UNIVERSAL 99');
            expect(tagName({ tagClass: 'context', tagNumber: 3 })).toBe('[3]');
        });

        it('selects a subtree with nodePath, paths staying absolute', async () => {
            const r = await decodeAsn1Tool({ input: fixtureInput('root.crt.der'), nodePath: '0.3' });
            expect(r.nodes[0]).toMatchObject({ path: '0.3', depth: 0, tagName: 'SEQUENCE', childCount: 3 });
            expect(r.nodes[1]).toMatchObject({ path: '0.3.0', depth: 1, tagName: 'SET' });
            expect(r.nodeCount).toBeLessThan(60);
        });

        it('decodes a sequence of top-level values, and tolerates trailing bytes on request', async () => {
            const two = await decodeAsn1Tool({ input: der('05000500'), sequence: true });
            expect(two.nodes.map((n) => [n.root, n.path, n.offset])).toEqual([[0, '', 0], [1, '', 2]]);
            expect(await codeOf(decodeAsn1Tool({ input: der('05000500') }))).toBe('PKI_ASN1_TRAILING_DATA');
            const tolerant = await decodeAsn1Tool({ input: der('05000500'), allowTrailingData: true });
            expect(tolerant.nodeCount).toBe(1);
        });

        it('accepts BER only with encodingRules ber', async () => {
            const result = await callToolDirect('decode_asn1', { input: der('30800500 0000') });
            expect(errorCodeOf(result)).toBe('PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN');
            expect((result._meta?.['error'] as { data: { remedy: string } }).data.remedy).toContain("encodingRules:'ber'");
            const ber = await decodeAsn1Tool({ input: der('30800500 0000'), encodingRules: 'ber' });
            expect(ber.nodes[0]).toMatchObject({ indefinite: true, tagName: 'SEQUENCE', childCount: 1 });
        });
    });

    describe('typed readers', () => {
        it.each([
            ['0.1', 'integer', { type: 'integer', value: '1' }],
            ['0.1', 'small-integer', { type: 'small-integer', value: 1 }],
            ['0.2.0', 'oid', { type: 'oid', value: '1.2.840.10045.4.3.2', name: 'ecdsa-with-SHA256' }],
            ['0.3.0.0.1', 'string', { type: 'string', value: { stringType: 'printable', value: 'FR' } }],
            ['0.4.0', 'time', { type: 'time', value: { type: 'UTCTime', epochMilliseconds: Date.UTC(2026, 0, 1), iso: '2026-01-01T00:00:00.000Z', text: '260101000000Z' } }],
            ['0.7.0.1.1', 'boolean', { type: 'boolean', value: true }],
            ['2', 'bit-string', { type: 'bit-string', value: { hex: expect.stringMatching(/^30/), unusedBits: 0 } }],
            ['0.7.0.0.1', 'octet-string', { type: 'octet-string', value: expect.stringMatching(/^[0-9a-f]+$/) }],
        ] as const)('reads %s as %s', async (nodePath, read, value) => {
            const r = await decodeAsn1Tool({ input: fixtureInput('root.crt.der'), nodePath, read });
            expect(r.value).toEqual(value);
            expect(r.nodes).toHaveLength(nodePath === '2' ? 1 : r.nodes.length);
        });

        it('reads null, enumerated and relative-oid at the root', async () => {
            expect((await decodeAsn1Tool({ input: der('0500'), read: 'null' })).value).toEqual({ type: 'null', value: null });
            expect((await decodeAsn1Tool({ input: der('0a0102'), read: 'enumerated' })).value).toEqual({ type: 'enumerated', value: '2' });
            expect((await decodeAsn1Tool({ input: der('0d04c27b0302'), read: 'relative-oid' })).value).toEqual({ type: 'relative-oid', value: '8571.3.2' });
            expect((await decodeAsn1Tool({ input: der('0202fed4'), read: 'integer' })).value).toEqual({ type: 'integer', value: '-300' });
        });

        it('reads IMPLICIT-tagged strings and times with stringType / timeType, PKI_API_MISUSE without', async () => {
            const str = await decodeAsn1Tool({ input: der('80024652'), read: 'string', stringType: 'printable' });
            expect(str.value).toEqual({ type: 'string', value: { stringType: 'printable', value: 'FR' } });
            const time = await decodeAsn1Tool({ input: der(`810d${Buffer.from('270101000000Z').toString('hex')}`), read: 'time', timeType: 'UTCTime' });
            expect(time.value?.value).toMatchObject({ epochMilliseconds: Date.UTC(2027, 0, 1) });
            expect(await codeOf(decodeAsn1Tool({ input: der('80024652'), read: 'string' }))).toBe('PKI_API_MISUSE');
        });

        it('PKI_ASN1_UNEXPECTED_TAG for a wrong reader', async () => {
            expect(await codeOf(decodeAsn1Tool({ input: der('0500'), read: 'integer' }))).toBe('PKI_ASN1_UNEXPECTED_TAG');
            expect(await codeOf(decodeAsn1Tool({ input: fixtureInput('root.crt.der'), read: 'boolean' }))).toBe('PKI_ASN1_UNEXPECTED_TAG');
        });
    });

    describe('reencode', () => {
        it('re-encodes the whole input byte for byte, delivered once as the embedded resource', async () => {
            const result = await callToolDirect('decode_asn1', { input: fixtureInput('leaf.crt.pem'), reencode: true });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toMatchObject({ reencode: { identical: true }, artefact: { mode: 'base64', encoding: 'der', sizeBytes: 701 } });
            expect(JSON.stringify(result.structuredContent)).not.toContain('base64":"');
            const bytes = artefactBytes(result);
            assertValidDer(bytes);
            expect(bytes).toEqual(fixtureBytes('leaf.crt.der'));
        });

        it('re-encodes a sub-node as hex, and the whole labelled input as PEM', async () => {
            const tbs = await decodeAsn1Tool({ input: fixtureInput('leaf.crt.pem'), nodePath: '0', reencode: true, encoding: 'hex' });
            expect(tbs.artefact?.hex).toMatch(/^3082/);
            expect(tbs.reencode).toEqual({ identical: true });
            const pem = await decodeAsn1Tool({ input: fixtureInput('leaf.crt.pem'), reencode: true, encoding: 'pem' });
            expect(Buffer.from(pem.artefact?.base64 ?? '', 'base64').toString('utf8')).toBe(fixtureText('leaf.crt.pem'));
            expect(pem.artefact?.mimeType).toBe('application/x-pem-file');
            expect(await codeOf(decodeAsn1Tool({ input: fixtureInput('leaf.crt.der'), reencode: true, encoding: 'pem' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(decodeAsn1Tool({ input: fixtureInput('leaf.crt.pem'), nodePath: '0', reencode: true, encoding: 'pem' }))).toBe('VALIDATION_ERROR');
        });

        it('writes the re-encoded node to the sandbox and never overwrites', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.crt.der'), path.join(sandbox, 'leaf.crt.der'));
            const result = await callToolDirect('decode_asn1', { input: { path: 'leaf.crt.der' }, nodePath: '0', reencode: true, outputMode: 'file', outputPath: 'tbs.der' });
            expect(result.isError).toBeUndefined();
            expect(result.content.some((c) => c.type === 'resource_link')).toBe(true);
            assertValidDer(new Uint8Array(await fs.readFile(path.join(sandbox, 'tbs.der'))));
            expect(await codeOf(decodeAsn1Tool({ input: { path: 'leaf.crt.der' }, reencode: true, outputMode: 'file', outputPath: 'tbs.der' }))).toBe('OUTPUT_EXISTS');
            expect(await codeOf(decodeAsn1Tool({ input: { path: 'leaf.crt.der' }, reencode: true, outputMode: 'file', outputPath: 'tbs.crt' }))).toBe('INVALID_EXTENSION');
            expect(await codeOf(decodeAsn1Tool({ input: { path: 'leaf.crt.der' }, reencode: true, outputMode: 'file' }))).toBe('MISSING_OUTPUT_PATH');
            expect(await codeOf(decodeAsn1Tool({ input: { path: '../leaf.crt.der' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(decodeAsn1Tool({ input: { path: 'missing.der' } }))).toBe('INPUT_NOT_FOUND');
        });
    });

    describe('secret guard', () => {
        it.each([
            ['leaf.key.pem', 'inspect_private_key'], ['leaf.key.enc.pem', 'inspect_private_key'], ['rsa.key.pem', 'inspect_private_key'],
            ['ed25519.key.pem', 'inspect_private_key'], ['leaf.key.der', 'inspect_private_key'],
            ['leaf.p12', 'inspect_pkcs12'], ['legacy.p12', 'inspect_pkcs12'], ['nomac.p12', 'inspect_pkcs12'], ['certs-only.p12', 'inspect_pkcs12'],
        ])('refuses %s with SECURITY_VIOLATION and remedy %s', async (name, remedy) => {
            const result = await callToolDirect('decode_asn1', { input: fixtureInput(name) });
            expect(errorCodeOf(result)).toBe('SECURITY_VIOLATION');
            expect((result._meta?.['error'] as { data: { remedy: string } }).data.remedy).toBe(remedy);
            assertResultClean(result);
        });

        it('refuses a key file by path too, and keeps the caller diagnostics clean', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.key.der'), path.join(sandbox, 'leaf.key.der'));
            const result = await callToolDirect('decode_asn1', { input: { path: 'leaf.key.der' } });
            expect(errorCodeOf(result)).toBe('SECURITY_VIOLATION');
            assertResultClean(result);
            const ok = await decodeAsn1Tool({ input: fixtureInput('leaf.crt.der') });
            expect(ok.diagnosticCounts).toEqual({});
        });
    });

    describe('projection', () => {
        it('summary keeps the counts, the root tag and the value', async () => {
            const r = await decodeAsn1Tool({ input: fixtureInput('root.crt.der'), nodePath: '0.1', read: 'integer' });
            expect(decodeAsn1Summary(r)).toEqual({ label: null, sizeBytes: 471, nodeCount: 1, rootTag: 'INTEGER', truncated: false, value: { type: 'integer', value: '1' }, diagnosticCount: 0 });
            const re = await decodeAsn1Tool({ input: fixtureInput('root.crt.der'), reencode: true, encoding: 'hex' });
            expect(decodeAsn1Summary(re)).toMatchObject({ rootTag: 'SEQUENCE', identical: true });
        });

        it('fields project over the wire', async () => {
            const result = await callToolDirect('decode_asn1', { input: fixtureInput('root.crt.der'), nodePath: '0.2', fields: ['nodes.path', 'nodes.oidName'] });
            expect(result.structuredContent).toEqual({ nodes: [{ path: '0.2' }, { path: '0.2.0', oidName: 'ecdsa-with-SHA256' }] });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('decode_asn1: DER (471 bytes), 2 node(s), root SEQUENCE') });
        });
    });

    describe('refusals', () => {
        it.each([
            ['no input', {}],
            ['unknown key', { input: fixtureInput('root.crt.der'), bogus: 1 }],
            ['two input forms', { input: { pem: fixtureText('root.crt.pem'), derBase64: fixtureBase64('root.crt.der') } }],
            ['bad nodePath', { input: fixtureInput('root.crt.der'), nodePath: 'a.b' }],
            ['sequence with nodePath', { input: der('05000500'), sequence: true, nodePath: '0' }],
            ['sequence with read', { input: der('05000500'), sequence: true, read: 'null' }],
            ['sequence with reencode', { input: der('05000500'), sequence: true, reencode: true }],
            ['read with reencode', { input: der('0500'), read: 'null', reencode: true }],
            ['stringType without read string', { input: der('0500'), read: 'null', stringType: 'utf8' }],
            ['timeType without read time', { input: der('0500'), timeType: 'UTCTime' }],
            ['file output without reencode', { input: der('0500'), outputMode: 'file', outputPath: 'x.der' }],
            ['preview above 256', { input: der('0500'), maxPreviewBytes: 257 }],
            ['hex to a file', { input: der('0500'), reencode: true, encoding: 'hex', outputMode: 'file', outputPath: 'x.der' }],
        ])('VALIDATION_ERROR: %s', async (_name, input) => {
            expect(await codeOf(decodeAsn1Tool(input))).toBe('VALIDATION_ERROR');
        });

        it('NOT_FOUND for a missing nodePath step, naming the range', async () => {
            const result = await callToolDirect('decode_asn1', { input: fixtureInput('root.crt.der'), nodePath: '0.99' });
            expect(errorCodeOf(result)).toBe('NOT_FOUND');
            expect(result._meta?.['error']).toMatchObject({ message: expect.stringContaining('has 8 child(ren) (0..7)'), data: { nodePath: '0.99', step: 99, at: '0', childCount: 8 } });
            const root = await decodeAsn1Tool({ input: der('0500') });
            expect(root.nodeCount).toBe(1);
            expect(() => selectNode({ tagClass: 'universal', tagNumber: 5, constructed: false, offset: 0, headerLength: 2, contentLength: 0, indefinite: false, bytes: new Uint8Array([5, 0]), content: new Uint8Array(0), children: [] }, '0')).toThrow(/has 0 child\(ren\)/);
        });

        it('PKI_ASN1_* for malformed bytes and PKI_LIMIT_EXCEEDED past a limit', async () => {
            expect(await codeOf(decodeAsn1Tool({ input: der('3004020101') }))).toBe('PKI_ASN1_TRUNCATED');
            expect(await codeOf(decodeAsn1Tool({ input: fixtureInput('root.crt.der'), limits: { maxNodes: 10 } }))).toBe('PKI_LIMIT_EXCEEDED');
            expect(await codeOf(decodeAsn1Tool({ input: fixtureInput('root.crt.der'), limits: { maxDepth: 2 } }))).toBe('PKI_LIMIT_EXCEEDED');
        });
    });

    describe('definition', () => {
        it('is read-only, cacheable, with two validating examples', () => {
            expect(DECODE_ASN1_TOOL.kind).toBe('read');
            expect(DECODE_ASN1_TOOL.annotations.readOnlyHint).toBe(true);
            expect(DECODE_ASN1_TOOL.cacheable).toBe(true);
            expect(DECODE_ASN1_TOOL.examples?.length).toBe(2);
        });
    });
});
