/**
 * Tests for `convert_pem` — block listing, extraction (der / hex / pem,
 * inline and file), DER wrapping, projection, every refusal, no secret.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { convertPem, convertPemSummary, CONVERT_PEM_TOOL } from '../src/tools/convert-pem.js';
import { artefactBytes, assertResultClean, assertValidDer, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureBase64, fixtureBytes, fixtureInput, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const LEAF_SHA256 = '00377dd9305cc27febbd1dd3c1f85d61cd49ede6043074ba2b7cba099a834998';

describe('convert_pem', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('decode', () => {
        it('lists the blocks of a bundle with their facts', async () => {
            const r = await convertPem({ mode: 'decode', input: { pem: fixtureText('leaf.crt.pem') + fixtureText('inter.crt.pem') } });
            expect(r.mode).toBe('decode');
            expect(r.count).toBe(2);
            expect(r.blocks).toEqual([
                { index: 0, label: 'CERTIFICATE', sizeBytes: 701, offset: 0, headers: [], sha256: LEAF_SHA256 },
                { index: 1, label: 'CERTIFICATE', sizeBytes: 482, offset: fixtureText('leaf.crt.pem').length, headers: [], sha256: expect.stringMatching(/^[0-9a-f]{64}$/) },
            ]);
            expect(r.artefact).toBeUndefined();
            expect(r.diagnostics).toEqual([]);
        });

        it('filters by label and lists a private-key block by label and size only', async () => {
            const bundle = { pem: fixtureText('leaf.crt.pem') + fixtureText('leaf.key.pem') };
            const all = await convertPem({ mode: 'decode', input: bundle });
            expect(all.blocks?.map((b) => [b.index, b.label, b.sizeBytes])).toEqual([[0, 'CERTIFICATE', 701], [1, 'PRIVATE KEY', 138]]);
            const only = await convertPem({ mode: 'decode', input: bundle, label: 'PRIVATE KEY' });
            expect(only.blocks?.map((b) => b.index)).toEqual([1]);
            const result = await callToolDirect('convert_pem', { mode: 'decode', input: bundle });
            expect(result.isError).toBeUndefined();
            assertResultClean(result);
        });

        it('lists RFC 1421 headers under pemMode lax and refuses them in strict mode', async () => {
            const pem = '-----BEGIN THING-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nBQA=\n-----END THING-----\n';
            expect(await codeOf(convertPem({ mode: 'decode', input: { pem } }))).toBe('PKI_PEM_HEADERS_FORBIDDEN');
            const lax = await convertPem({ mode: 'decode', input: { pem }, pemMode: 'lax' });
            expect(lax.blocks?.[0]).toMatchObject({ label: 'THING', sizeBytes: 2, headers: [['Proc-Type', '4,ENCRYPTED'], ['DEK-Info', 'AES-128-CBC,00']] });
            expect(lax.diagnostics.length).toBeGreaterThan(0);
        });

        it.each([
            ['der', (bytes: Uint8Array) => expect(bytes).toEqual(fixtureBytes('leaf.crt.der'))],
            ['pem', (bytes: Uint8Array) => expect(bytes).toEqual(fixtureBytes('leaf.crt.der'))],
        ] as const)('extracts a block as %s through the server (embedded resource once)', async (encoding, check) => {
            const result = await callToolDirect('convert_pem', { mode: 'decode', input: fixtureInput('leaf.crt.pem'), extractIndex: 0, encoding });
            expect(result.isError).toBeUndefined();
            const structured = result.structuredContent as Record<string, unknown>;
            expect(structured['extracted']).toEqual({ index: 0, label: 'CERTIFICATE' });
            expect(structured['artefact']).toEqual({ mode: 'base64', encoding, sizeBytes: 701, sha256: LEAF_SHA256 });
            expect(JSON.stringify(structured)).not.toContain('"base64":"');
            const bytes = artefactBytes(result);
            assertValidDer(bytes);
            check(bytes);
            if (encoding === 'pem') {
                const block = result.content.find((c) => c.type === 'resource') as { resource: { text?: string; mimeType: string } };
                expect(block.resource.text).toBe(fixtureText('leaf.crt.pem'));
                expect(block.resource.mimeType).toBe('application/x-pem-file');
            }
        });

        it('extracts as hex inline, with the MIME type by label', async () => {
            const r = await convertPem({ mode: 'decode', input: fixtureInput('inter.crl.pem'), extractIndex: 0, encoding: 'hex' });
            expect(r.artefact).toMatchObject({ mode: 'base64', encoding: 'hex', hex: expect.stringMatching(/^3082/) });
            const crl = await convertPem({ mode: 'decode', input: fixtureInput('inter.crl.pem'), extractIndex: 0 });
            expect(crl.artefact?.mimeType).toBe('application/pkix-crl');
            const csr = await convertPem({ mode: 'decode', input: fixtureInput('leaf.csr.pem'), extractIndex: 0 });
            expect(csr.artefact?.mimeType).toBe('application/pkcs10');
        });

        it('never extracts a private-key block (SECURITY_VIOLATION, remedy inspect_private_key)', async () => {
            for (const name of ['leaf.key.pem', 'leaf.key.enc.pem', 'rsa.key.pem', 'ed25519.key.pem']) {
                const result = await callToolDirect('convert_pem', { mode: 'decode', input: fixtureInput(name), extractIndex: 0 });
                expect(errorCodeOf(result), name).toBe('SECURITY_VIOLATION');
                expect((result._meta?.['error'] as { data: { remedy: string } }).data.remedy).toBe('inspect_private_key');
                assertResultClean(result);
            }
        });
    });

    describe('encode', () => {
        it('wraps DER identically to OpenSSL and delivers the PEM text once', async () => {
            const result = await callToolDirect('convert_pem', { mode: 'encode', input: { derBase64: fixtureBase64('leaf.crt.der') }, label: 'CERTIFICATE' });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toMatchObject({ mode: 'encode', label: 'CERTIFICATE', sizeBytes: 701, sha256: LEAF_SHA256, artefact: { mode: 'base64', encoding: 'pem', sizeBytes: 701 } });
            const block = result.content.find((c) => c.type === 'resource') as { resource: { text?: string } };
            expect(block.resource.text).toBe(fixtureText('leaf.crt.pem'));
            expect(artefactBytes(result)).toEqual(fixtureBytes('leaf.crt.der'));
        });

        it("accepts encoding:'pem' explicitly and any RFC 7468 label", async () => {
            const r = await convertPem({ mode: 'encode', input: { derBase64: Buffer.from('0500', 'hex').toString('base64') }, label: 'ASN1 VALUE 2', encoding: 'pem' });
            expect(Buffer.from(r.artefact?.base64 ?? '', 'base64').toString('utf8')).toBe('-----BEGIN ASN1 VALUE 2-----\nBQA=\n-----END ASN1 VALUE 2-----\n');
        });
    });

    describe('projection', () => {
        it('summary keeps count and labels (decode) or the artefact facts (encode)', async () => {
            const d = await convertPem({ mode: 'decode', input: fixtureInput('inter.crt.pem') });
            expect(convertPemSummary(d)).toEqual({ mode: 'decode', count: 1, labels: ['CERTIFICATE'], diagnosticCount: 0 });
            const e = await convertPem({ mode: 'encode', input: fixtureInput('leaf.crt.der'), label: 'CERTIFICATE' });
            expect(convertPemSummary(e)).toEqual({ mode: 'encode', label: 'CERTIFICATE', sizeBytes: 701, sha256: LEAF_SHA256, diagnosticCount: 0 });
        });

        it('fields project over the wire', async () => {
            const result = await callToolDirect('convert_pem', { mode: 'decode', input: fixtureInput('inter.crt.pem'), verbosity: 'summary', fields: ['labels'] });
            expect(result.structuredContent).toEqual({ labels: ['CERTIFICATE'] });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('convert_pem: 1 block(s)') });
        });
    });

    describe('sandbox (path inputs and file outputs)', () => {
        it('reads a PEM file, writes the extracted block, never overwrites', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.crt.pem'), path.join(sandbox, 'leaf.crt.pem'));
            const result = await callToolDirect('convert_pem', { mode: 'decode', input: { path: 'leaf.crt.pem' }, extractIndex: 0, outputMode: 'file', outputPath: 'out/leaf.der' });
            expect(result.isError).toBeUndefined();
            expect(result.content.some((c) => c.type === 'resource_link')).toBe(true);
            expect(new Uint8Array(await fs.readFile(path.join(sandbox, 'out', 'leaf.der')))).toEqual(fixtureBytes('leaf.crt.der'));
            expect(await codeOf(convertPem({ mode: 'decode', input: { path: 'leaf.crt.pem' }, extractIndex: 0, outputMode: 'file', outputPath: 'out/leaf.der' }))).toBe('OUTPUT_EXISTS');
            expect(await codeOf(convertPem({ mode: 'decode', input: { path: 'leaf.crt.pem' }, extractIndex: 0, outputMode: 'file', outputPath: 'out/leaf.key' }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(convertPem({ mode: 'decode', input: { path: 'leaf.crt.pem' }, extractIndex: 0, outputMode: 'file', outputPath: 'out/leaf.txt' }))).toBe('INVALID_EXTENSION');
            expect(await codeOf(convertPem({ mode: 'decode', input: { path: 'leaf.crt.pem' }, extractIndex: 0, outputMode: 'file' }))).toBe('MISSING_OUTPUT_PATH');
            expect(await codeOf(convertPem({ mode: 'decode', input: { path: 'leaf.crt.pem' }, extractIndex: 0, encoding: 'hex', outputMode: 'file', outputPath: 'x.der' }))).toBe('VALIDATION_ERROR');
        });

        it('encodes a DER file into a PEM file, and refuses a PEM file as DER', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.crt.der'), path.join(sandbox, 'leaf.crt.der'));
            await fs.copyFile(fixture('leaf.crt.pem'), path.join(sandbox, 'leaf.crt.pem'));
            const r = await convertPem({ mode: 'encode', input: { path: 'leaf.crt.der' }, label: 'CERTIFICATE', outputMode: 'file', outputPath: 'wrapped.pem' });
            expect(r.artefact?.mode).toBe('file');
            expect(await fs.readFile(path.join(sandbox, 'wrapped.pem'), 'utf8')).toBe(fixtureText('leaf.crt.pem'));
            expect(await codeOf(convertPem({ mode: 'encode', input: { path: 'leaf.crt.pem' }, label: 'X' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(convertPem({ mode: 'decode', input: { path: 'leaf.crt.der' } }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(convertPem({ mode: 'decode', input: { path: '../leaf.crt.pem' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(convertPem({ mode: 'decode', input: { path: 'missing.pem' } }))).toBe('INPUT_NOT_FOUND');
            expect(await codeOf(convertPem({ mode: 'decode', input: { path: 'leaf.exe' } }))).toBe('INVALID_EXTENSION');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(convertPem({ mode: 'decode', input: { path: 'leaf.crt.pem' } }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('A2-042: encode wraps one DER value and never key material', () => {
        it('A2-042: a key behind a text or binary prefix, or any bytes that are not one DER value, are refused and never wrapped', async () => {
            const keyPem = fixtureText('leaf.key.pem');
            const keyDer = fixtureBytes('leaf.key.der');
            const cases: Array<[string, Uint8Array]> = [
                ['text prefix then a PEM key', new TextEncoder().encode(`${'x'.repeat(300)}\n${keyPem}`)],
                ['binary prefix then a DER key', new Uint8Array(Buffer.concat([Buffer.alloc(64, 0x41), Buffer.from(keyDer)]))],
                ['a certificate followed by a DER key', new Uint8Array(Buffer.concat([Buffer.from(fixtureBytes('leaf.crt.der')), Buffer.from(keyDer)]))],
            ];
            for (const [label, bytes] of cases) {
                const result = await callToolDirect('convert_pem', { mode: 'encode', input: { derBase64: Buffer.from(bytes).toString('base64') }, label: 'CERTIFICATE' });
                expect(result.isError, label).toBe(true);
                expect(errorCodeOf(result), label).toMatch(/^(SECURITY_VIOLATION|PKI_ASN1_[A-Z_]+)$/);
                expect(result.content.some((c) => c.type === 'resource'), label).toBe(false);
                assertResultClean(result, label);
            }
        });
    });

    describe('refusals', () => {
        it.each([
            ['no mode', { input: fixtureInput('leaf.crt.pem') }],
            ['unknown key', { mode: 'decode', input: fixtureInput('leaf.crt.pem'), bogus: 1 }],
            ['decode with derBase64', { mode: 'decode', input: { derBase64: fixtureBase64('leaf.crt.der') } }],
            ['decode with encoding but no extractIndex', { mode: 'decode', input: fixtureInput('leaf.crt.pem'), encoding: 'hex' }],
            ['decode with a file output but no extractIndex', { mode: 'decode', input: fixtureInput('leaf.crt.pem'), outputMode: 'file', outputPath: 'x.der' }],
            ['encode without label', { mode: 'encode', input: fixtureInput('leaf.crt.der') }],
            ['encode with a lower-case label', { mode: 'encode', input: fixtureInput('leaf.crt.der'), label: 'bad-' }],
            ['encode with a pem input', { mode: 'encode', input: fixtureInput('leaf.crt.pem'), label: 'CERTIFICATE' }],
            ['encode with encoding der', { mode: 'encode', input: fixtureInput('leaf.crt.der'), label: 'CERTIFICATE', encoding: 'der' }],
            ['encode with extractIndex', { mode: 'encode', input: fixtureInput('leaf.crt.der'), label: 'CERTIFICATE', extractIndex: 0 }],
            ['two input forms', { mode: 'decode', input: { pem: fixtureText('leaf.crt.pem'), path: 'x.pem' } }],
        ])('VALIDATION_ERROR: %s', async (_name, input) => {
            expect(await codeOf(convertPem(input))).toBe('VALIDATION_ERROR');
        });

        it('NOT_FOUND for an index past the last block or outside the label filter', async () => {
            expect(await codeOf(convertPem({ mode: 'decode', input: fixtureInput('leaf.crt.pem'), extractIndex: 3 }))).toBe('NOT_FOUND');
            const bundle = { pem: fixtureText('leaf.crt.pem') + fixtureText('leaf.csr.pem') };
            expect(await codeOf(convertPem({ mode: 'decode', input: bundle, label: 'CERTIFICATE', extractIndex: 1 }))).toBe('NOT_FOUND');
        });

        it('PKI_PEM_UNEXPECTED_LABEL for a label absent from the text', async () => {
            expect(await codeOf(convertPem({ mode: 'decode', input: fixtureInput('leaf.crt.pem'), label: 'X509 CRL' }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
        });

        it('PKI_PEM_* for a malformed text (missing padding is refused in both modes)', async () => {
            const stripped = fixtureText('leaf.crt.pem').replace(/=+\n-----END/, '\n-----END');
            expect(await codeOf(convertPem({ mode: 'decode', input: { pem: stripped } }))).toBe('PKI_PEM_BASE64_INVALID');
            expect(await codeOf(convertPem({ mode: 'decode', input: { pem: stripped }, pemMode: 'lax' }))).toBe('PKI_PEM_BASE64_INVALID');
            expect(await codeOf(convertPem({ mode: 'decode', input: { pem: '-----BEGIN CERTIFICATE-----\nBQA=\n' } }))).toBe('PKI_PEM_UNTERMINATED');
        });

        it('SECURITY_VIOLATION: encode refuses DER that parses as a PKCS#8 key (plain or encrypted) or a PKCS#12 file under any label, never echoing it', async () => {
            for (const [name, label] of [['leaf.key.der', 'CERTIFICATE'], ['leaf.p12', 'PKCS12'], ['plain-keybag.p12', 'DATA'], ['nomac.p12', 'X509 CRL']] as const) {
                const result = await callToolDirect('convert_pem', { mode: 'encode', input: fixtureInput(name), label });
                expect(errorCodeOf(result), name).toBe('SECURITY_VIOLATION');
                assertResultClean(result, name);
            }
            const enc = new Uint8Array(Buffer.from(fixtureText('leaf.key.enc.pem').replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64'));
            const encrypted = await callToolDirect('convert_pem', { mode: 'encode', input: { derBase64: Buffer.from(enc).toString('base64') }, label: 'CERTIFICATE' });
            expect(errorCodeOf(encrypted)).toBe('SECURITY_VIOLATION');
            assertResultClean(encrypted);
            // A certificate under an odd label is still produced: the sniff refuses key material, not labels.
            expect((await callToolDirect('convert_pem', { mode: 'encode', input: fixtureInput('leaf.crt.der'), label: 'TRUSTED CERTIFICATE' })).isError).not.toBe(true);
        });

        it('SECURITY_VIOLATION: never produces a private-key labelled block', async () => {
            const result = await callToolDirect('convert_pem', { mode: 'encode', input: fixtureInput('leaf.key.der'), label: 'PRIVATE KEY' });
            expect(errorCodeOf(result)).toBe('SECURITY_VIOLATION');
            assertResultClean(result);
        });
    });

    describe('definition', () => {
        it('is a read tool with an artefact attachment, WRITES annotations, cacheable, two examples', () => {
            expect(CONVERT_PEM_TOOL.kind).toBe('read');
            expect(CONVERT_PEM_TOOL.annotations).toEqual({ readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false });
            expect(CONVERT_PEM_TOOL.cacheable).toBe(true);
            expect(CONVERT_PEM_TOOL.examples?.length).toBe(2);
        });
    });
});
