/**
 * Tests for `src/spki.ts` — a public key from whatever the caller has at
 * hand (a certificate, a request, a bare SubjectPublicKeyInfo), and the key
 * type read from the SPKI algorithm identifier.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { encodeNull, encodeSequence } from 'pkinative';

import { ToolError } from '../src/errors.js';
import { createParseContext } from '../src/parse-context.js';
import { keyTypeOfSpki, loadPublicKey, publicKeyOf, readSpki } from '../src/spki.js';
import { fixture, fixtureBase64, fixtureBytes, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const ctx = createParseContext({});

/** The SPKI DER of a key, derived by Node (the module never asks the engine to export anything). */
function spkiOf(keyPem: string): Uint8Array {
    return new Uint8Array(createPublicKey(keyPem).export({ type: 'spki', format: 'der' }));
}

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

describe('readSpki / keyTypeOfSpki', () => {
    it('EC P-256: the uncompressed point and the curve', () => {
        const { bits, type } = readSpki(spkiOf(fixtureText('leaf.key.pem')), ctx);
        expect(bits).toHaveLength(65);
        expect(bits[0]).toBe(0x04);
        expect(type).toEqual({ kind: 'ec', curve: 'P-256' });
        expect(keyTypeOfSpki(spkiOf(fixtureText('leaf.key.pem')), ctx)).toEqual({ kind: 'ec', curve: 'P-256' });
    });

    it('RSA: kind rsa, no curve', () => {
        const { bits, type } = readSpki(spkiOf(fixtureText('rsa.key.pem')), ctx);
        expect(bits.length).toBeGreaterThan(256);
        expect(type).toEqual({ kind: 'rsa' });
        expect(type).not.toHaveProperty('curve');
    });

    it('Ed25519: kind ed25519 and the 32 key bytes', () => {
        const { bits, type } = readSpki(spkiOf(fixtureText('ed25519.key.pem')), ctx);
        expect(bits).toHaveLength(32);
        expect(type).toEqual({ kind: 'ed25519' });
    });

    it('the PUBLIC KEY fixture equals the key derived from the private key', () => {
        const pub = fixtureBytes('leaf.pub.pem');
        expect(pub[0]).not.toBe(0x30);
        const { bits } = readSpki(spkiOf(fixtureText('leaf.key.pem')), ctx);
        const fromPem = readSpki(publicKeyOf({ der: spkiOf(fixtureText('leaf.key.pem')), label: 'PUBLIC KEY', source: 'pem' }, ctx).spki, ctx);
        expect(fromPem.bits).toEqual(bits);
    });

    it('a two-member SEQUENCE that is not an SPKI is PKI_X509_SPKI_INVALID; non-DER is the engine code', () => {
        const err = thrown(() => readSpki(encodeSequence([encodeNull(), encodeNull()]), ctx));
        expect(err.code).toBe('PKI_X509_SPKI_INVALID');
        expect(err.data).toEqual({ errorClass: 'parse' });
        expect(thrown(() => readSpki(encodeSequence([encodeNull()]), ctx)).code).toBe('PKI_X509_SPKI_INVALID');
        const garbage = thrown(() => readSpki(new Uint8Array([0x30, 0x05, 0x02]), ctx));
        expect(garbage.code).toMatch(/^PKI_ASN1_/);
        expect(garbage.message).toContain('Cannot read the public key');
        expect(garbage.data).toMatchObject({ errorClass: 'parse', engineError: 'PkiEncodingError' });
    });

    it('an unknown algorithm or curve yields type undefined (the bits are still read)', () => {
        // An EC key on a curve Web Crypto does not sign with: secp256k1.
        const k1 = generateKeyPairSync('ec', { namedCurve: 'secp256k1' }).publicKey.export({ type: 'spki', format: 'der' });
        const ec = readSpki(new Uint8Array(k1), ctx);
        expect(ec.bits).toHaveLength(65);
        expect(ec.type).toBeUndefined();
        const x25519 = generateKeyPairSync('x25519').publicKey.export({ type: 'spki', format: 'der' });
        const x = readSpki(new Uint8Array(x25519), ctx);
        expect(x.bits).toHaveLength(32);
        expect(x.type).toBeUndefined();
    });
});

describe('publicKeyOf', () => {
    const leafSpki = spkiOf(fixtureText('leaf.key.pem'));

    it('from a certificate (PEM label) — the subjectPublicKeyInfo DER', () => {
        const key = publicKeyOf({ der: fixtureBytes('leaf.crt.der'), label: 'CERTIFICATE', source: 'pem' }, ctx);
        expect(key.from).toBe('certificate');
        expect(key.spki).toEqual(leafSpki);
        expect(key.type).toEqual({ kind: 'ec', curve: 'P-256' });
        expect(key.bits).toEqual(readSpki(leafSpki, ctx).bits);
        expect(publicKeyOf({ der: fixtureBytes('rsa.crt.der'), label: 'X509 CERTIFICATE', source: 'pem' }, ctx)).toMatchObject({ from: 'certificate', type: { kind: 'rsa' } });
        expect(publicKeyOf({ der: fixtureBytes('ed25519.crt.der'), label: 'TRUSTED CERTIFICATE', source: 'pem' }, ctx)).toMatchObject({ from: 'certificate', type: { kind: 'ed25519' } });
    });

    it('from a CSR (PEM label) and a PUBLIC KEY block', () => {
        const csr = publicKeyOf({ der: fixtureBytes('leaf.csr.der'), label: 'CERTIFICATE REQUEST', source: 'pem' }, ctx);
        expect(csr.from).toBe('csr');
        expect(csr.spki).toEqual(leafSpki);
        expect(csr.type).toEqual({ kind: 'ec', curve: 'P-256' });
        const spki = publicKeyOf({ der: leafSpki, label: 'PUBLIC KEY', source: 'pem' }, ctx);
        expect(spki).toEqual({ spki: leafSpki, bits: csr.bits, from: 'spki', type: { kind: 'ec', curve: 'P-256' } });
    });

    it('DER of unknown kind is sniffed: two members → SPKI, three → certificate, else request', () => {
        expect(publicKeyOf({ der: leafSpki, label: undefined, source: 'derBase64' }, ctx)).toMatchObject({ from: 'spki', spki: leafSpki });
        expect(publicKeyOf({ der: fixtureBytes('leaf.crt.der'), label: undefined, source: 'derBase64' }, ctx)).toMatchObject({ from: 'certificate', spki: leafSpki });
        expect(publicKeyOf({ der: fixtureBytes('leaf.csr.der'), label: undefined, source: 'derBase64' }, ctx)).toMatchObject({ from: 'csr', spki: leafSpki });
    });

    it('a PEM label the readers refuse, and a DER that is neither, are the engine PKI_* code naming the source', () => {
        const labelled = thrown(() => publicKeyOf({ der: fixtureBytes('inter.crl.der'), label: 'CERTIFICATE', source: 'pem' }, ctx));
        expect(labelled.code).toMatch(/^PKI_X509_/);
        expect(labelled.message).toContain('Cannot read the certificate');
        const csrLabelled = thrown(() => publicKeyOf({ der: fixtureBytes('leaf.crt.der'), label: 'CERTIFICATE REQUEST', source: 'pem' }, ctx));
        expect(csrLabelled.code).toMatch(/^PKI_/);
        expect(csrLabelled.message).toContain('Cannot read the request');
        const crl = thrown(() => publicKeyOf({ der: fixtureBytes('inter.crl.der'), label: undefined, source: 'crl.der' }, ctx));
        expect(crl.code).toMatch(/^PKI_X509_/);
        expect(crl.message).toContain('crl.der is not a certificate, a request or a public key');
        expect(crl.data).toMatchObject({ errorClass: 'parse', engineError: 'PkiCertificateError' });
        const garbage = thrown(() => publicKeyOf({ der: new Uint8Array([1, 2, 3]), label: undefined, source: 'derBase64' }, ctx));
        expect(garbage.code).toMatch(/^PKI_ASN1_/);
        expect(garbage.message).toContain('Cannot read the public key');
    });
});

describe('loadPublicKey', () => {
    let sandbox: string | null = null;

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    it('loads a certificate, a request or a public key from any input form, including a sandbox path', async () => {
        const leafSpki = spkiOf(fixtureText('leaf.key.pem'));
        expect((await loadPublicKey({ pem: fixtureText('leaf.crt.pem') }, 'issuer', ctx))).toMatchObject({ from: 'certificate', spki: leafSpki });
        expect((await loadPublicKey({ pem: fixtureText('leaf.csr.pem') }, 'request', ctx))).toMatchObject({ from: 'csr', spki: leafSpki });
        expect((await loadPublicKey({ pem: fixtureText('leaf.pub.pem') }, 'subjectPublicKey', ctx))).toMatchObject({ from: 'spki', spki: leafSpki });
        expect((await loadPublicKey({ derBase64: fixtureBase64('leaf.csr.der') }, 'request', ctx))).toMatchObject({ from: 'csr' });
        sandbox = await makeSandbox();
        await fs.copyFile(fixture('leaf.pub.pem'), path.join(sandbox, 'leaf.pub.pem'));
        await fs.copyFile(fixture('rsa.crt.der'), path.join(sandbox, 'rsa.crt.der'));
        expect((await loadPublicKey({ path: 'leaf.pub.pem' }, 'subjectPublicKey', ctx))).toMatchObject({ from: 'spki', spki: leafSpki });
        expect((await loadPublicKey({ path: 'rsa.crt.der' }, 'issuer', ctx))).toMatchObject({ from: 'certificate', type: { kind: 'rsa' } });
        expect((await rejectionOf(loadPublicKey({ path: 'missing.pem' }, 'issuer', ctx))).code).toBe('INPUT_NOT_FOUND');
    });

    it('a private key, a CRL or several blocks are refused with the input discipline codes', async () => {
        const key = await rejectionOf(loadPublicKey({ pem: fixtureText('leaf.key.pem') }, 'issuer', ctx));
        expect(key.code).toBe('PKI_PEM_UNEXPECTED_LABEL');
        expect(key.message).toContain('labels present: PRIVATE KEY');
        expect((await rejectionOf(loadPublicKey({ pem: fixtureText('inter.crl.pem') }, 'issuer', ctx))).code).toBe('PKI_PEM_UNEXPECTED_LABEL');
        const two = await rejectionOf(loadPublicKey({ pem: fixtureText('leaf.crt.pem') + fixtureText('leaf.pub.pem') }, 'issuer', ctx));
        expect(two.code).toBe('VALIDATION_ERROR');
        expect(two.data).toEqual({ path: 'issuer', remedy: 'convert_pem extractIndex' });
        expect((await rejectionOf(loadPublicKey({ path: 'x.pem' }, 'issuer', ctx))).code).toBe('SECURITY_VIOLATION');
    });
});
