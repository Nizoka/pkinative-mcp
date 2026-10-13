/**
 * Tests for `src/pki-input.ts` — the PKI object input every tool shares:
 * PEM / derBase64 / path exclusivity, PEM sniffing and label discipline,
 * bundle flattening, the inline-byte accounting and the secret-label table.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { MAX_BUNDLE_ITEMS, MAX_INLINE_INPUT_BYTES_PER_CALL } from '../src/caps.js';
import { ToolError } from '../src/errors.js';
import { createParseContext, type ParseContext } from '../src/parse-context.js';
import {
    decodePemBlocks,
    isPathInput,
    isSecretLabel,
    LABELS,
    loadPkiBundle,
    loadPkiObject,
    loadPkiObjects,
    looksLikePem,
    pkiBundleSchema,
    PkiBundleSchema,
    pkiInputSchema,
    PkiInputSchema,
    SECRET_LABELS,
} from '../src/pki-input.js';
import { PKI_INPUT_EXTENSIONS } from '../src/sandbox.js';
import { assertNoSecret } from './_pki-assert.js';
import { fixture, fixtureBase64, fixtureBytes, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const bytesOf = (text: string): Uint8Array => new TextEncoder().encode(text);

async function rejectionOf(p: Promise<unknown>): Promise<ToolError> {
    try {
        await p;
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to reject');
}

function thrown(fn: () => unknown): ToolError {
    try {
        fn();
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to throw');
}

describe('looksLikePem', () => {
    it('recognises -----BEGIN after an optional BOM and whitespace, and nothing else', () => {
        expect(looksLikePem(bytesOf('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'))).toBe(true);
        expect(looksLikePem(new Uint8Array([0xef, 0xbb, 0xbf, ...bytesOf('-----BEGIN X')]))).toBe(true);
        expect(looksLikePem(bytesOf('\n\r\n\t  -----BEGIN X'))).toBe(true);
        expect(looksLikePem(bytesOf('# comment\n-----BEGIN X'))).toBe(false);
        expect(looksLikePem(bytesOf('-----BEGIN'))).toBe(false);
        expect(looksLikePem(bytesOf('----BEGIN X'))).toBe(false);
        expect(looksLikePem(bytesOf('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A'))).toBe(false);
        expect(looksLikePem(fixtureBytes('leaf.crt.der'))).toBe(false);
        expect(looksLikePem(fixtureBytes('leaf.crt.pem'))).toBe(true);
        expect(looksLikePem(new Uint8Array(0))).toBe(false);
    });
});

describe('schemas', () => {
    it('pkiInputSchema is a closed object with the three exclusive members and the sandbox extensions', () => {
        const schema = pkiInputSchema('The certificate', ' Extra.');
        expect(schema).toMatchObject({ type: 'object', additionalProperties: false, description: 'The certificate: exactly one of pem / derBase64 / path. Extra.' });
        const properties = schema['properties'] as Record<string, Record<string, unknown>>;
        expect(Object.keys(properties)).toEqual(['pem', 'derBase64', 'path']);
        expect(properties['pem']).toMatchObject({ type: 'string', minLength: 20 });
        expect(properties['derBase64']).toMatchObject({ type: 'string', minLength: 4 });
        expect(properties['path']).toMatchObject({ type: 'string', minLength: 1 });
        expect(properties['path']?.['description']).toContain(PKI_INPUT_EXTENSIONS.join(' '));
        expect(properties['pem']?.['description']).toContain('The certificate');
    });

    it('pkiBundleSchema wraps it in a bounded array', () => {
        const schema = pkiBundleSchema('Trust anchors', ' Extra.');
        expect(schema).toMatchObject({ type: 'array', minItems: 1, maxItems: MAX_BUNDLE_ITEMS, items: pkiInputSchema('Trust anchors') });
        expect(schema['description']).toBe('Trust anchors (every PEM block of every item is taken). Extra.');
        expect(MAX_BUNDLE_ITEMS).toBe(256);
    });

    it('PkiInputSchema: exactly one member, pem must start with -----BEGIN, no unknown key', () => {
        expect(PkiInputSchema.safeParse({ pem: fixtureText('leaf.crt.pem') }).success).toBe(true);
        expect(PkiInputSchema.safeParse({ pem: '\n  ' + fixtureText('leaf.crt.pem') }).success).toBe(true);
        expect(PkiInputSchema.safeParse({ derBase64: 'AAAA' }).success).toBe(true);
        expect(PkiInputSchema.safeParse({ path: 'leaf.crt.der' }).success).toBe(true);
        expect(PkiInputSchema.safeParse({}).success).toBe(false);
        expect(PkiInputSchema.safeParse({ pem: fixtureText('leaf.crt.pem'), derBase64: 'AAAA' }).success).toBe(false);
        expect(PkiInputSchema.safeParse({ derBase64: 'AAAA', path: 'x' }).success).toBe(false);
        expect(PkiInputSchema.safeParse({ pem: fixtureBase64('leaf.crt.der') }).success).toBe(false);
        expect(PkiInputSchema.safeParse({ pem: '-----BEGIN X-----' }).success).toBe(false);
        expect(PkiInputSchema.safeParse({ derBase64: 'AA' }).success).toBe(false);
        expect(PkiInputSchema.safeParse({ path: '' }).success).toBe(false);
        expect(PkiInputSchema.safeParse({ derBase64: 'AAAA', bogus: 1 }).success).toBe(false);
        const issue = PkiInputSchema.safeParse({ pem: fixtureBase64('leaf.crt.der') });
        expect(issue.success ? [] : issue.error.issues.map((i) => i.message)).toEqual([expect.stringContaining('-----BEGIN')]);
    });

    it('PkiBundleSchema bounds the item count', () => {
        expect(PkiBundleSchema.safeParse([]).success).toBe(false);
        expect(PkiBundleSchema.safeParse([{ derBase64: 'AAAA' }]).success).toBe(true);
        expect(PkiBundleSchema.safeParse(Array.from({ length: MAX_BUNDLE_ITEMS + 1 }, () => ({ derBase64: 'AAAA' }))).success).toBe(false);
    });
});

describe('loadPkiObjects / loadPkiObject / loadPkiBundle', () => {
    let ctx: ParseContext;
    let sandbox: string | null = null;

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    function fresh(): ParseContext {
        ctx = createParseContext({});
        return ctx;
    }

    it('pem: every matching block of a bundle, in order, with its label and the source', async () => {
        const bundle = fixtureText('leaf.crt.pem') + fixtureText('inter.crt.pem') + fixtureText('root.crt.pem');
        const objects = await loadPkiObjects({ pem: bundle }, 'chain', LABELS.certificate, fresh());
        expect(objects.map((o) => o.label)).toEqual(['CERTIFICATE', 'CERTIFICATE', 'CERTIFICATE']);
        expect(objects.map((o) => o.source)).toEqual(['pem', 'pem', 'pem']);
        expect(objects[0]?.der).toEqual(fixtureBytes('leaf.crt.der'));
        expect(objects[1]?.der).toEqual(fixtureBytes('inter.crt.der'));
        expect(objects[2]?.der).toEqual(fixtureBytes('root.crt.der'));
    });

    it('pem: the label filter keeps the wanted blocks only; an empty label list takes every block', async () => {
        const mixed = fixtureText('leaf.crt.pem') + fixtureText('leaf.csr.pem') + fixtureText('leaf.pub.pem');
        const csr = await loadPkiObjects({ pem: mixed }, 'request', LABELS.csr, fresh());
        expect(csr.map((o) => o.label)).toEqual(['CERTIFICATE REQUEST']);
        expect(csr[0]?.der).toEqual(fixtureBytes('leaf.csr.der'));
        const any = await loadPkiObjects({ pem: mixed }, 'object', LABELS.any, fresh());
        expect(any.map((o) => o.label)).toEqual(['CERTIFICATE', 'CERTIFICATE REQUEST', 'PUBLIC KEY']);
        const both = await loadPkiObjects({ pem: mixed }, 'object', [...LABELS.certificate, ...LABELS.publicKey], fresh());
        expect(both.map((o) => o.label)).toEqual(['CERTIFICATE', 'PUBLIC KEY']);
    });

    it('pem: no matching block is PKI_PEM_UNEXPECTED_LABEL naming the labels present, with the convert_pem remedy and no key byte', async () => {
        const err = await rejectionOf(loadPkiObjects({ pem: fixtureText('leaf.key.pem') }, 'certificate', LABELS.certificate, fresh()));
        expect(err.code).toBe('PKI_PEM_UNEXPECTED_LABEL');
        expect(err.message).toContain('certificate (pem) holds no CERTIFICATE or X509 CERTIFICATE or TRUSTED CERTIFICATE PEM block');
        expect(err.message).toContain('labels present: PRIVATE KEY');
        expect(err.data).toEqual({ errorClass: 'input', path: 'certificate', remedy: "convert_pem mode:'decode' (lists the labels present)" });
        assertNoSecret(JSON.stringify({ message: err.message, data: err.data }));
    });

    it('pem: a malformed PEM text is the engine PKI_PEM_* code through the guard', async () => {
        const unterminated = '-----BEGIN CERTIFICATE-----\nMIIB\n';
        const err = await rejectionOf(loadPkiObjects({ pem: unterminated }, 'certificate', LABELS.certificate, fresh()));
        expect(err.code).toMatch(/^PKI_PEM_/);
        expect(err.message).toContain('Cannot decode certificate as PEM');
        expect(err.data).toMatchObject({ errorClass: 'parse', engineError: 'PkiEncodingError' });
    });

    it('derBase64: one object, label undefined, source derBase64; the decode mistakes are VALIDATION_ERROR', async () => {
        const objects = await loadPkiObjects({ derBase64: fixtureBase64('leaf.crt.der') }, 'certificate', LABELS.certificate, fresh());
        expect(objects).toHaveLength(1);
        expect(objects[0]).toEqual({ der: fixtureBytes('leaf.crt.der'), label: undefined, source: 'derBase64' });
        // A data: URI prefix is tolerated; a PEM text in derBase64 is refused by name.
        expect((await loadPkiObjects({ derBase64: `data:application/pkix-cert;base64,${fixtureBase64('leaf.crt.der')}` }, 'certificate', LABELS.certificate, fresh()))[0]?.der).toEqual(fixtureBytes('leaf.crt.der'));
        const pemInDer = await rejectionOf(loadPkiObjects({ derBase64: fixtureText('leaf.crt.pem') }, 'certificate', LABELS.certificate, fresh()));
        expect(pemInDer.code).toBe('VALIDATION_ERROR');
        expect(pemInDer.data).toEqual({ field: 'certificate.derBase64', remedy: 'pem' });
        // Labels do not apply to DER: a CSR DER loads under the certificate labels (the parser decides later).
        expect((await loadPkiObjects({ derBase64: fixtureBase64('leaf.csr.der') }, 'certificate', LABELS.certificate, fresh()))[0]?.label).toBeUndefined();
    });

    it('none of the three members is VALIDATION_ERROR naming the input', async () => {
        const err = await rejectionOf(loadPkiObjects({}, 'trustAnchors[0]', LABELS.certificate, fresh()));
        expect(err.code).toBe('VALIDATION_ERROR');
        expect(err.message).toBe('trustAnchors[0]: pass exactly one of pem / derBase64 / path');
        expect(err.data).toEqual({ path: 'trustAnchors[0]' });
    });

    it('path: reads DER and PEM files from the sandbox (sniffed by their first bytes), source = the relative path', async () => {
        sandbox = await makeSandbox();
        await fs.copyFile(fixture('leaf.crt.der'), path.join(sandbox, 'leaf.crt.der'));
        await fs.mkdir(path.join(sandbox, 'pem'));
        await fs.copyFile(fixture('leaf.crt.pem'), path.join(sandbox, 'pem', 'leaf.crt.pem'));
        await fs.writeFile(path.join(sandbox, 'pem', 'bom.crt'), Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(fixtureText('leaf.crt.pem'))]));
        const der = await loadPkiObjects({ path: 'leaf.crt.der' }, 'certificate', LABELS.certificate, fresh());
        expect(der).toEqual([{ der: fixtureBytes('leaf.crt.der'), label: undefined, source: 'leaf.crt.der' }]);
        const pem = await loadPkiObjects({ path: 'pem/leaf.crt.pem' }, 'certificate', LABELS.certificate, fresh());
        expect(pem).toEqual([{ der: fixtureBytes('leaf.crt.der'), label: 'CERTIFICATE', source: 'pem/leaf.crt.pem' }]);
        const bom = await loadPkiObjects({ path: 'pem/bom.crt' }, 'certificate', LABELS.certificate, fresh());
        expect(bom[0]?.label).toBe('CERTIFICATE');
    });

    it('path: INPUT_NOT_FOUND, INVALID_EXTENSION (named after the input), SECURITY_VIOLATION on escape and when the sandbox is unset', async () => {
        sandbox = await makeSandbox();
        const missing = await rejectionOf(loadPkiObjects({ path: 'missing.crt' }, 'certificate', LABELS.certificate, fresh()));
        expect(missing.code).toBe('INPUT_NOT_FOUND');
        expect(missing.message).toContain('certificate.path');
        expect(missing.data).toEqual({ path: 'missing.crt', remedy: 'resources/list' });
        const ext = await rejectionOf(loadPkiObjects({ path: 'leaf.exe' }, 'certificate', LABELS.certificate, fresh()));
        expect(ext.code).toBe('INVALID_EXTENSION');
        expect(ext.message).toContain('certificate.path');
        expect(ext.data).toEqual({ extensions: PKI_INPUT_EXTENSIONS });
        expect((await rejectionOf(loadPkiObjects({ path: '../leaf.crt.der' }, 'certificate', LABELS.certificate, fresh()))).code).toBe('SECURITY_VIOLATION');
        expect((await rejectionOf(loadPkiObjects({ path: 'C:\\leaf.crt.der' }, 'certificate', LABELS.certificate, fresh()))).code).toBe('SECURITY_VIOLATION');
        await cleanupSandbox(sandbox);
        sandbox = null;
        const unset = await rejectionOf(loadPkiObjects({ path: 'leaf.crt.der' }, 'certificate', LABELS.certificate, fresh()));
        expect(unset.code).toBe('SECURITY_VIOLATION');
        expect(unset.message).toContain('PKINATIVE_MCP_OUTPUT_DIR');
    });

    it('loadPkiObject returns the one object and refuses several matching blocks (VALIDATION_ERROR, convert_pem extractIndex)', async () => {
        const one = await loadPkiObject({ pem: fixtureText('leaf.crt.pem') }, 'certificate', LABELS.certificate, fresh());
        expect(one).toEqual({ der: fixtureBytes('leaf.crt.der'), label: 'CERTIFICATE', source: 'pem' });
        // Non-matching blocks around the one wanted block do not count.
        const mixed = await loadPkiObject({ pem: fixtureText('leaf.csr.pem') + fixtureText('leaf.crt.pem') }, 'certificate', LABELS.certificate, fresh());
        expect(mixed.label).toBe('CERTIFICATE');
        const err = await rejectionOf(loadPkiObject({ pem: fixtureText('leaf.crt.pem') + fixtureText('inter.crt.pem') }, 'certificate', LABELS.certificate, fresh()));
        expect(err.code).toBe('VALIDATION_ERROR');
        expect(err.message).toBe('certificate (pem) holds 2 CERTIFICATE/X509 CERTIFICATE/TRUSTED CERTIFICATE blocks where one object is expected.');
        expect(err.data).toEqual({ path: 'certificate', remedy: 'convert_pem extractIndex' });
        const any = await rejectionOf(loadPkiObject({ pem: fixtureText('leaf.crt.pem') + fixtureText('leaf.csr.pem') }, 'object', LABELS.any, fresh()));
        expect(any.message).toBe('object (pem) holds 2 blocks where one object is expected.');
    });

    it('loadPkiBundle flattens every block of every item and names the item in errors; undefined is empty', async () => {
        const objects = await loadPkiBundle([
            { pem: fixtureText('leaf.crt.pem') + fixtureText('inter.crt.pem') },
            { derBase64: fixtureBase64('root.crt.der') },
        ], 'candidates', LABELS.certificate, fresh());
        expect(objects.map((o) => [o.label, o.source])).toEqual([['CERTIFICATE', 'pem'], ['CERTIFICATE', 'pem'], [undefined, 'derBase64']]);
        expect(objects[2]?.der).toEqual(fixtureBytes('root.crt.der'));
        expect(await loadPkiBundle(undefined, 'crls', LABELS.crl, fresh())).toEqual([]);
        expect(await loadPkiBundle([], 'crls', LABELS.crl, fresh())).toEqual([]);
        const err = await rejectionOf(loadPkiBundle([{ pem: fixtureText('leaf.crt.pem') }, { pem: fixtureText('leaf.pub.pem') }], 'trustAnchors', LABELS.certificate, fresh()));
        expect(err.code).toBe('PKI_PEM_UNEXPECTED_LABEL');
        expect(err.data?.['path']).toBe('trustAnchors[1]');
    });

    it('every read is held to the effective maxInputBytes (INPUT_TOO_LARGE; the path route already in use gets no remedy)', async () => {
        const small = createParseContext({ limits: { maxInputBytes: 1024 } });
        const pem = await rejectionOf(loadPkiObjects({ pem: fixtureText('rsa.crt.pem') }, 'certificate', LABELS.certificate, small));
        expect(pem.code).toBe('INPUT_TOO_LARGE');
        expect(pem.data).toEqual({ what: 'certificate (pem)', observed: 1054, cap: 1024, remedy: 'path' });
        // The decoded size is what counts for derBase64 (rsa.crt.der is 737 bytes; its base64 is longer).
        const tiny = createParseContext({ limits: { maxInputBytes: 700 } });
        const der = await rejectionOf(loadPkiObjects({ derBase64: fixtureBase64('rsa.crt.der') }, 'certificate', LABELS.certificate, tiny));
        expect(der.code).toBe('INPUT_TOO_LARGE');
        expect(der.data).toEqual({ what: 'certificate (derBase64, decoded)', observed: 737, cap: 700, remedy: 'path' });
        expect((await loadPkiObjects({ derBase64: fixtureBase64('rsa.crt.der') }, 'certificate', LABELS.certificate, small))[0]?.der).toHaveLength(737);
        // The leaf (701 bytes DER, 1005 bytes PEM) fits the same cap.
        expect((await loadPkiObjects({ pem: fixtureText('leaf.crt.pem') }, 'certificate', LABELS.certificate, small))[0]?.label).toBe('CERTIFICATE');
        sandbox = await makeSandbox();
        await fs.copyFile(fixture('rsa.crt.pem'), path.join(sandbox, 'rsa.crt.pem'));
        await fs.copyFile(fixture('rsa.crt.der'), path.join(sandbox, 'rsa.crt.der'));
        const file = await rejectionOf(loadPkiObjects({ path: 'rsa.crt.pem' }, 'certificate', LABELS.certificate, small));
        expect(file.code).toBe('INPUT_TOO_LARGE');
        expect(file.data).toEqual({ what: "certificate.path 'rsa.crt.pem'", observed: 1054, cap: 1024 });
        expect(file.message).toContain('PKINATIVE_MCP_MAX_INPUT_BYTES');
        // The 737-byte DER of the same certificate fits (the file size is what is measured, before any sniffing).
        expect((await loadPkiObjects({ path: 'rsa.crt.der' }, 'certificate', LABELS.certificate, small))[0]?.source).toBe('rsa.crt.der');
    });

    it('inline inputs are charged against the per-call envelope; a path input is not', async () => {
        const budget = createParseContext({});
        budget.charge(MAX_INLINE_INPUT_BYTES_PER_CALL - 1000, 'earlier inputs');
        const err = await rejectionOf(loadPkiObjects({ pem: fixtureText('leaf.crt.pem') }, 'certificate', LABELS.certificate, budget));
        expect(err.code).toBe('INPUT_TOO_LARGE');
        expect(err.data).toMatchObject({ what: 'certificate (inline inputs of this call)', observed: MAX_INLINE_INPUT_BYTES_PER_CALL - 1000 + 1005, cap: MAX_INLINE_INPUT_BYTES_PER_CALL, remedy: 'path' });
        const der = await rejectionOf(loadPkiObjects({ derBase64: fixtureBase64('rsa.crt.der') }, 'certificate', LABELS.certificate, budget));
        expect(der.code).toBe('INPUT_TOO_LARGE');
        sandbox = await makeSandbox();
        await fs.copyFile(fixture('leaf.crt.der'), path.join(sandbox, 'leaf.crt.der'));
        expect((await loadPkiObjects({ path: 'leaf.crt.der' }, 'certificate', LABELS.certificate, budget))[0]?.source).toBe('leaf.crt.der');
    });
});

describe('decodePemBlocks', () => {
    const withHeaders = fixtureText('leaf.crt.pem').replace('-----BEGIN CERTIFICATE-----\n', '-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00\n\n');

    it('strict (the default) refuses RFC 1421 headers with the engine code; lax accepts them and reports the tolerance to the sink', () => {
        const strict = createParseContext({});
        const err = thrown(() => decodePemBlocks(withHeaders, 'certificate', strict));
        expect(err.code).toBe('PKI_PEM_HEADERS_FORBIDDEN');
        expect(err.message).toContain('Cannot decode certificate as PEM');
        expect(err.data).toMatchObject({ errorClass: 'unsupported', engineError: 'PkiEncodingError' });
        const lax = createParseContext({ pemMode: 'lax' });
        const blocks = decodePemBlocks(withHeaders, 'certificate', lax);
        expect(blocks).toHaveLength(1);
        expect(blocks[0]?.label).toBe('CERTIFICATE');
        expect(blocks[0]?.bytes).toEqual(fixtureBytes('leaf.crt.der'));
        expect(blocks[0]?.headers).toEqual([['Proc-Type', '4,ENCRYPTED'], ['DEK-Info', 'AES-256-CBC,00']]);
        expect(lax.sink.has('PKI_DIAG_PEM_LAX_ACCEPTED')).toBe(true);
        expect(strict.sink.report().diagnostics).toEqual([]);
    });

    it('a clean PEM decodes identically in both modes and honours maxPemBlocks', () => {
        const text = fixtureText('leaf.crt.pem') + fixtureText('inter.crt.pem');
        expect(decodePemBlocks(text, 'x', createParseContext({})).map((b) => b.label)).toEqual(['CERTIFICATE', 'CERTIFICATE']);
        expect(decodePemBlocks(text, 'x', createParseContext({ pemMode: 'lax' })).map((b) => b.label)).toEqual(['CERTIFICATE', 'CERTIFICATE']);
        const err = thrown(() => decodePemBlocks(text, 'x', createParseContext({ limits: { maxPemBlocks: 1 } })));
        expect(err.code).toBe('PKI_LIMIT_EXCEEDED');
        expect(err.data).toMatchObject({ errorClass: 'limit', limit: 'maxPemBlocks', configured: 1 });
    });
});

describe('isPathInput', () => {
    it('finds a string path member anywhere in objects and arrays, up to the depth cap', () => {
        expect(isPathInput({ path: 'x' })).toBe(true);
        expect(isPathInput({ certificate: { path: 'leaf.crt' } })).toBe(true);
        expect(isPathInput({ trustAnchors: [{ pem: '-----BEGIN' }, { path: 'root.crt' }] })).toBe(true);
        expect(isPathInput({ signer: { key: { path: 'k.pem' } } })).toBe(true);
        expect(isPathInput({ pem: 'x' })).toBe(false);
        expect(isPathInput({ path: 1 })).toBe(false);
        expect(isPathInput({ certificate: { derBase64: 'AAAA' }, fields: ['path'] })).toBe(false);
        expect(isPathInput(null)).toBe(false);
        expect(isPathInput('path')).toBe(false);
        expect(isPathInput(undefined)).toBe(false);
        expect(isPathInput([])).toBe(false);
        const nest = (depth: number): unknown => {
            let value: unknown = { path: 'x' };
            for (let i = 0; i < depth; i++) value = { a: value };
            return value;
        };
        expect(isPathInput(nest(8))).toBe(true);
        expect(isPathInput(nest(9))).toBe(false);
        expect(isPathInput([[[[[[[[{ path: 'x' }]]]]]]]])).toBe(true);
    });
});

describe('labels', () => {
    it('LABELS covers the RFC 7468 kinds; SECRET_LABELS names every private-key label', () => {
        expect(Object.keys(LABELS)).toEqual(['certificate', 'csr', 'crl', 'cms', 'privateKey', 'encryptedPrivateKey', 'publicKey', 'any']);
        expect(LABELS.certificate).toEqual(['CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE']);
        expect(LABELS.csr).toEqual(['CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST']);
        expect(LABELS.crl).toEqual(['X509 CRL']);
        expect(LABELS.cms).toEqual(['CMS', 'PKCS7']);
        expect(LABELS.privateKey).toEqual(['PRIVATE KEY']);
        expect(LABELS.encryptedPrivateKey).toEqual(['ENCRYPTED PRIVATE KEY']);
        expect(LABELS.publicKey).toEqual(['PUBLIC KEY']);
        expect(LABELS.any).toEqual([]);
        expect(SECRET_LABELS).toEqual(['PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'DSA PRIVATE KEY', 'PGP PRIVATE KEY BLOCK']);
        for (const label of [...LABELS.privateKey, ...LABELS.encryptedPrivateKey]) expect(SECRET_LABELS).toContain(label);
    });

    it('isSecretLabel is true for every secret label only; DER (undefined) is never a secret by label', () => {
        for (const label of SECRET_LABELS) expect(isSecretLabel(label), label).toBe(true);
        expect(isSecretLabel('CERTIFICATE')).toBe(false);
        expect(isSecretLabel('PUBLIC KEY')).toBe(false);
        expect(isSecretLabel('private key')).toBe(false);
        expect(isSecretLabel(undefined)).toBe(false);
    });
});
