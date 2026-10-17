/**
 * Tests for `src/output.ts` — artefact emission in base64 mode (pem / der /
 * hex) and file mode (exclusive sandboxed writes), the text writer, and the
 * shared input / output schema fragments.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { encodePem } from 'pkinative';

import { MAX_BASE64_OUTPUT_BYTES, MAX_HEX_INLINE_BYTES } from '../src/caps.js';
import { ToolError } from '../src/errors.js';
import { ARTEFACT_OUTPUT_PROPERTIES, emitArtefact, outputInputProperties, outputShape, writeSandboxedText, type EmitOptions } from '../src/output.js';
import { OUTPUT_EXTENSIONS, SECRET_EXTENSIONS, TEXT_OUTPUT_EXTENSIONS } from '../src/sandbox.js';
import { fixtureBytes } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const DER = fixtureBytes('leaf.crt.der');
const SHA256 = createHash('sha256').update(DER).digest('hex');
const PEM_TEXT = encodePem('CERTIFICATE', DER);
const CERT: Omit<EmitOptions, 'mode' | 'encoding'> = { pemLabel: 'CERTIFICATE', mimeType: 'application/pkix-cert' };

async function rejectionOf(p: Promise<unknown>): Promise<ToolError> {
    try {
        await p;
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to reject');
}

describe('emitArtefact — base64 mode', () => {
    it('pem: the PEM text as base64 under application/x-pem-file; sizeBytes and sha256 are of the DER', async () => {
        const r = await emitArtefact(DER, { ...CERT, mode: 'base64', encoding: 'pem' });
        expect(r).toEqual({ mode: 'base64', encoding: 'pem', sizeBytes: DER.byteLength, sha256: SHA256, base64: Buffer.from(PEM_TEXT).toString('base64'), mimeType: 'application/x-pem-file' });
        expect(Buffer.from(r.base64 as string, 'base64').toString('utf8')).toBe(PEM_TEXT);
        expect(PEM_TEXT.startsWith('-----BEGIN CERTIFICATE-----\n')).toBe(true);
    });

    it('der: the bytes as base64 under the engine MIME type', async () => {
        const r = await emitArtefact(DER, { ...CERT, mode: 'base64', encoding: 'der' });
        expect(r).toEqual({ mode: 'base64', encoding: 'der', sizeBytes: DER.byteLength, sha256: SHA256, base64: Buffer.from(DER).toString('base64'), mimeType: 'application/pkix-cert' });
        expect(new Uint8Array(Buffer.from(r.base64 as string, 'base64'))).toEqual(DER);
    });

    it('hex: the lowercase hex in `hex` (no base64), capped at MAX_HEX_INLINE_BYTES, inline only', async () => {
        const r = await emitArtefact(DER, { ...CERT, mode: 'base64', encoding: 'hex', summary: { kind: 'certificate' } });
        expect(r).toEqual({ mode: 'base64', encoding: 'hex', sizeBytes: DER.byteLength, sha256: SHA256, hex: Buffer.from(DER).toString('hex'), mimeType: 'application/octet-stream', summary: { kind: 'certificate' } });
        expect(r).not.toHaveProperty('base64');
        const big = await rejectionOf(emitArtefact(new Uint8Array(MAX_HEX_INLINE_BYTES + 1), { ...CERT, mode: 'base64', encoding: 'hex' }));
        expect(big.code).toBe('OUTPUT_TOO_LARGE');
        expect(big.data).toEqual({ sizeBytes: MAX_HEX_INLINE_BYTES + 1, cap: MAX_HEX_INLINE_BYTES, remedy: "encoding:'der'" });
        expect((await emitArtefact(new Uint8Array(MAX_HEX_INLINE_BYTES), { ...CERT, mode: 'base64', encoding: 'hex' })).hex).toHaveLength(MAX_HEX_INLINE_BYTES * 2);
        const file = await rejectionOf(emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'hex', outputPath: 'x.crt' }));
        expect(file.code).toBe('VALIDATION_ERROR');
        expect(file.data).toEqual({ remedy: "encoding:'der'" });
    });

    it('OUTPUT_TOO_LARGE above the inline cap with the file remedy', async () => {
        const err = await rejectionOf(emitArtefact(new Uint8Array(MAX_BASE64_OUTPUT_BYTES + 1), { ...CERT, mode: 'base64', encoding: 'der' }));
        expect(err.code).toBe('OUTPUT_TOO_LARGE');
        expect(err.message).toContain("outputMode:'file'");
        expect(err.data).toEqual({ sizeBytes: MAX_BASE64_OUTPUT_BYTES + 1, cap: MAX_BASE64_OUTPUT_BYTES, remedy: "outputMode:'file'" });
    });
});

describe('emitArtefact — file mode', () => {
    let sandbox: string | null = null;

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    it('needs outputPath (MISSING_OUTPUT_PATH) and the sandbox (SECURITY_VIOLATION)', async () => {
        const missing = await rejectionOf(emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'der' }));
        expect(missing.code).toBe('MISSING_OUTPUT_PATH');
        expect(missing.data).toEqual({ remedy: 'outputPath' });
        const unset = await rejectionOf(emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'der', outputPath: 'leaf.crt' }));
        expect(unset.code).toBe('SECURITY_VIOLATION');
        expect(unset.message).toContain('PKINATIVE_MCP_OUTPUT_DIR');
    });

    it('der: writes the bytes exactly once under an allowed extension, creating parents; sha256 is of the DER', async () => {
        sandbox = await makeSandbox();
        const r = await emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'der', outputPath: 'out/leaf.crt', summary: { serial: '1001' } });
        expect(r).toEqual({ mode: 'file', encoding: 'der', sizeBytes: DER.byteLength, sha256: SHA256, filePath: path.join(sandbox, 'out', 'leaf.crt'), mimeType: 'application/pkix-cert', summary: { serial: '1001' } });
        expect(new Uint8Array(await fs.readFile(r.filePath as string))).toEqual(DER);
        const again = await rejectionOf(emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'der', outputPath: 'out/leaf.crt' }));
        expect(again.code).toBe('OUTPUT_EXISTS');
        expect(again.message).toContain("'out/leaf.crt'");
        expect(again.message).not.toContain(sandbox);
        expect(again.data).toEqual({ path: 'out/leaf.crt' });
        expect((await rejectionOf(emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'der', outputPath: '../leaf.crt' }))).code).toBe('SECURITY_VIOLATION');
        expect((await rejectionOf(emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'der', outputPath: 'leaf.txt' }))).code).toBe('INVALID_EXTENSION');
    });

    it('pem: requires a .pem name (INVALID_EXTENSION otherwise) and writes the PEM text', async () => {
        sandbox = await makeSandbox();
        const bad = await rejectionOf(emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'pem', outputPath: 'leaf.crt' }));
        expect(bad.code).toBe('INVALID_EXTENSION');
        expect(bad.data).toEqual({ extensions: ['.pem'] });
        const r = await emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'pem', outputPath: 'leaf.pem' });
        expect(r).toEqual({ mode: 'file', encoding: 'pem', sizeBytes: DER.byteLength, sha256: SHA256, filePath: path.join(sandbox, 'leaf.pem'), mimeType: 'application/x-pem-file' });
        expect(await fs.readFile(r.filePath as string, 'utf8')).toBe(PEM_TEXT);
    });

    it('der: derExtensions narrows the allowed names; the default is every PKI output extension', async () => {
        sandbox = await makeSandbox();
        const narrow = await rejectionOf(emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'der', outputPath: 'req.crt', derExtensions: ['.csr', '.p10'] }));
        expect(narrow.code).toBe('INVALID_EXTENSION');
        expect(narrow.data).toEqual({ extensions: ['.csr', '.p10'] });
        expect((await emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'der', outputPath: 'req.csr', derExtensions: ['.csr', '.p10'] })).filePath).toBe(path.join(sandbox, 'req.csr'));
        const wide = await rejectionOf(emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'der', outputPath: 'x.exe' }));
        expect(wide.data).toEqual({ extensions: OUTPUT_EXTENSIONS });
        for (const ext of ['.der', '.cer', '.p7s', '.tsq', '.ocsp', '.bin']) {
            expect((await emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'der', outputPath: `many/x${ext}` })).filePath, ext).toBe(path.join(sandbox, 'many', `x${ext}`));
        }
    });

    it('a key-bearing extension is SECURITY_VIOLATION in every encoding, even when derExtensions names it', async () => {
        sandbox = await makeSandbox();
        for (const ext of SECRET_EXTENSIONS) {
            const err = await rejectionOf(emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'der', outputPath: `out${ext}`, derExtensions: [ext] }));
            expect(err.code, ext).toBe('SECURITY_VIOLATION');
            expect(err.message, ext).toContain('never writes private keys');
        }
        expect((await rejectionOf(emitArtefact(DER, { ...CERT, mode: 'file', encoding: 'pem', outputPath: 'out.key' }))).code).toBe('SECURITY_VIOLATION');
        expect(await fs.readdir(sandbox)).toEqual([]);
    });
});

describe('writeSandboxedText', () => {
    let sandbox: string | null = null;

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    it('writes UTF-8 text under a text extension, never overwrites, honours a custom allow-list', async () => {
        sandbox = await makeSandbox();
        const text = '# Draft\n\nbody — ünïcödé\n';
        const r = await writeSandboxedText(text, 'drafts/issue.md');
        expect(r).toEqual({ filePath: path.join(sandbox, 'drafts', 'issue.md'), sizeBytes: Buffer.byteLength(text, 'utf8') });
        expect(await fs.readFile(r.filePath, 'utf8')).toBe(text);
        expect((await rejectionOf(writeSandboxedText('second', 'drafts/issue.md'))).code).toBe('OUTPUT_EXISTS');
        expect(await fs.readFile(r.filePath, 'utf8')).toBe(text);
        for (const ext of TEXT_OUTPUT_EXTENSIONS) expect((await writeSandboxedText('x', `t/file${ext}`)).filePath, ext).toBe(path.join(sandbox, 't', `file${ext}`));
        const bad = await rejectionOf(writeSandboxedText('x', 'issue.crt'));
        expect(bad.code).toBe('INVALID_EXTENSION');
        expect(bad.data).toEqual({ extensions: TEXT_OUTPUT_EXTENSIONS });
        expect((await writeSandboxedText('x', 'bundle.p7b', ['.p7b'])).filePath).toBe(path.join(sandbox, 'bundle.p7b'));
        expect((await rejectionOf(writeSandboxedText('x', 'issue.md', ['.txt']))).code).toBe('INVALID_EXTENSION');
        expect((await rejectionOf(writeSandboxedText('x', '../escape.md'))).code).toBe('SECURITY_VIOLATION');
        expect((await rejectionOf(writeSandboxedText('x', 'k.key', ['.key']))).code).toBe('SECURITY_VIOLATION');
    });

    it('is SECURITY_VIOLATION without a sandbox and OUTPUT_TOO_LARGE above the inline cap (checked before the path resolves)', async () => {
        expect((await rejectionOf(writeSandboxedText('x', 'issue.md'))).code).toBe('SECURITY_VIOLATION');
        const huge = await rejectionOf(writeSandboxedText('x'.repeat(MAX_BASE64_OUTPUT_BYTES + 1), 'huge.md'));
        expect(huge.code).toBe('OUTPUT_TOO_LARGE');
        expect(huge.data).toEqual({ sizeBytes: MAX_BASE64_OUTPUT_BYTES + 1, cap: MAX_BASE64_OUTPUT_BYTES });
    });
});

describe('schema fragments', () => {
    it('outputInputProperties / outputShape are in lock-step (keys, enums, defaults)', () => {
        for (const encoding of ['pem', 'der', 'hex'] as const) {
            const properties = outputInputProperties(encoding, '.crt / .pem') as Record<string, Record<string, unknown>>;
            const shape = outputShape(encoding);
            expect(Object.keys(properties)).toEqual(Object.keys(shape));
            expect(Object.keys(properties)).toEqual(['outputMode', 'outputPath', 'encoding']);
            expect(properties['outputMode']).toMatchObject({ type: 'string', enum: ['base64', 'file'], default: 'base64' });
            expect(properties['encoding']).toMatchObject({ type: 'string', enum: ['pem', 'der', 'hex'], default: encoding });
            expect(properties['outputPath']).toMatchObject({ type: 'string', minLength: 1 });
            expect(properties['outputPath']?.['description']).toContain('.crt / .pem');
            expect(properties['outputPath']?.['description']).toContain('.key .p8 .p12 .pfx');
            expect(shape.outputMode.parse(undefined)).toBe('base64');
            expect(shape.encoding.parse(undefined)).toBe(encoding);
            expect(shape.encoding.safeParse('base64').success).toBe(false);
            expect(shape.outputMode.safeParse('stream').success).toBe(false);
            expect(shape.outputPath.safeParse('').success).toBe(false);
            expect(shape.outputPath.safeParse(undefined).success).toBe(true);
        }
    });

    it('ARTEFACT_OUTPUT_PROPERTIES names the members every artefact result shares', () => {
        expect(Object.keys(ARTEFACT_OUTPUT_PROPERTIES)).toEqual(['mode', 'encoding', 'sizeBytes', 'sha256', 'filePath', 'hex']);
        expect(ARTEFACT_OUTPUT_PROPERTIES.mode.enum).toEqual(['base64', 'file']);
        expect(ARTEFACT_OUTPUT_PROPERTIES.encoding.enum).toEqual(['pem', 'der', 'hex']);
        expect(ARTEFACT_OUTPUT_PROPERTIES.sizeBytes).toMatchObject({ type: 'integer', minimum: 0 });
        expect(ARTEFACT_OUTPUT_PROPERTIES.sha256.description).toContain('DER');
    });
});
