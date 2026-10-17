/**
 * Tests for `src/key-views.ts` — curated, secret-free views of key material:
 * built field by field from an allow-list over real fixtures, and proven to
 * carry no key byte, scalar or password.
 */
import { describe, expect, it } from 'vitest';
import { decodePem, importPrivateKey, parseCertificate, parseEncryptedPrivateKeyInfo, parsePkcs12, parsePrivateKeyInfo, type DistinguishedName } from 'pkinative';

import {
    bagView,
    dn,
    ENCRYPTION_VIEW_SCHEMA,
    encryptedKeyView,
    encryptionView,
    KEY_VIEW_SCHEMA,
    macView,
    privateKeyView,
    SIGNING_KEY_VIEW_SCHEMA,
    signingKeyView,
} from '../src/key-views.js';
import { assertNoSecret } from './_pki-assert.js';
import { fixtureBytes, fixtureText } from './_pki-fixtures.js';

const SILENT = { onDiagnostic: () => undefined };
const pemDer = (name: string): Uint8Array => decodePem(fixtureText(name))[0]?.bytes as Uint8Array;

/** Every key of a view appears in the schema's properties (the interfaces ARE the allow-list). */
function assertWithinSchema(view: object, schema: { properties: Record<string, unknown>; required?: readonly string[] }): void {
    for (const key of Object.keys(view)) expect(Object.keys(schema.properties), key).toContain(key);
    for (const key of schema.required ?? []) expect(view, key).toHaveProperty(key);
}

describe('privateKeyView', () => {
    it('describes a plain PKCS#8 key by its algorithm only', () => {
        const info = parsePrivateKeyInfo(fixtureBytes('leaf.key.der'), SILENT);
        const view = privateKeyView(info);
        expect(view).toEqual({ format: 'pkcs8', version: 0, kind: 'ec', curve: 'P-256', algorithm: '1.2.840.10045.2.1', attributes: [], publicKey: false });
        assertNoSecret(JSON.stringify(view), 'privateKeyView');
        assertWithinSchema(view, KEY_VIEW_SCHEMA);
        const rsa = privateKeyView(parsePrivateKeyInfo(pemDer('rsa.key.pem'), SILENT));
        expect(rsa).toMatchObject({ format: 'pkcs8', kind: 'rsa', algorithm: '1.2.840.113549.1.1.1' });
        expect(rsa).not.toHaveProperty('curve');
        assertNoSecret(JSON.stringify(rsa), 'privateKeyView rsa');
        const ed = privateKeyView(parsePrivateKeyInfo(pemDer('ed25519.key.pem'), SILENT));
        expect(ed).toMatchObject({ kind: 'ed25519', algorithm: '1.3.101.112' });
        assertNoSecret(JSON.stringify(ed), 'privateKeyView ed25519');
    });
});

describe('encryptionView / encryptedKeyView', () => {
    it('describes a PBES2 EncryptedPrivateKeyInfo: scheme, KDF parameters, cipher by name, sizes only', () => {
        const info = parseEncryptedPrivateKeyInfo(pemDer('leaf.key.enc.pem'), SILENT);
        const view = encryptedKeyView(info);
        expect(view).toEqual({
            format: 'encrypted-pkcs8',
            encryption: { scheme: info.encryption.scheme, algorithm: '1.2.840.113549.1.5.13', pbes2: { iterations: 2048, prf: 'SHA-256', keyBits: 256, cipher: 'aes256-CBC', saltBytes: 16 } },
            encryptedBytes: 144,
        });
        expect(view.encryption.scheme).toContain('PBES2');
        expect(encryptionView(info.encryption)).toEqual(view.encryption);
        assertNoSecret(JSON.stringify(view), 'encryptedKeyView');
        assertWithinSchema(view, KEY_VIEW_SCHEMA);
        assertWithinSchema(view.encryption, ENCRYPTION_VIEW_SCHEMA);
        assertWithinSchema(view.encryption.pbes2 as Record<string, unknown>, ENCRYPTION_VIEW_SCHEMA.properties.pbes2);
        const rsa = encryptedKeyView(parseEncryptedPrivateKeyInfo(pemDer('rsa.key.enc.pem'), SILENT));
        expect(rsa.encryptedBytes).toBeGreaterThan(1000);
        assertNoSecret(JSON.stringify(rsa), 'encryptedKeyView rsa');
    });
});

describe('macView', () => {
    it('describes a PBMAC1 MAC and is null without one', () => {
        const view = macView(parsePkcs12(fixtureBytes('leaf.p12'), SILENT).mac);
        expect(view).toEqual({ kind: 'pbmac1', algorithm: '1.2.840.113549.1.5.14', iterations: 2048, pbmac1: { iterations: 2048, prf: 'SHA-256', hmac: 'SHA-256', keyLength: 32 } });
        assertNoSecret(JSON.stringify(view), 'macView');
        expect(JSON.stringify(view)).not.toMatch(/"(mac|salt)"/);
        expect(macView(parsePkcs12(fixtureBytes('nomac.p12'), SILENT).mac)).toBeNull();
        expect(macView(undefined)).toBeNull();
        const legacy = macView(parsePkcs12(fixtureBytes('legacy.p12'), SILENT).mac);
        expect(legacy?.kind).toBe('pkcs12-kdf');
        expect(legacy).not.toHaveProperty('pbmac1');
    });
});

describe('bagView', () => {
    it('plain-keybag.p12: the certificate by identity, the unencrypted keyBag by its algorithm only — no needle', () => {
        const p12 = parsePkcs12(fixtureBytes('plain-keybag.p12'), SILENT);
        const bags = p12.contents.flatMap((c) => c.bags);
        expect(bags.map((b) => b.kind)).toEqual(['certBag', 'keyBag']);
        const views = bags.map((b) => bagView(b, SILENT));
        expect(views[0]).toEqual({
            path: 'authSafe[0].bags[0]',
            kind: 'certBag',
            oid: '1.2.840.113549.1.12.10.1.3',
            localKeyId: expect.stringMatching(/^[0-9a-f]{40}$/),
            certificate: { subject: expect.stringContaining('CN=example.test'), issuer: expect.stringContaining('CN=Test Intermediate CA'), serialNumber: '1001' },
        });
        expect(views[1]).toEqual({
            path: 'authSafe[1].bags[0]',
            kind: 'keyBag',
            oid: '1.2.840.113549.1.12.10.1.1',
            localKeyId: views[0]?.localKeyId,
            key: { format: 'pkcs8', version: 0, kind: 'ec', curve: 'P-256', algorithm: '1.2.840.10045.2.1', attributes: [], publicKey: false },
        });
        for (const view of views) {
            assertNoSecret(JSON.stringify(view), `bagView ${view.kind}`);
            expect(JSON.stringify(view)).not.toMatch(/valueDer|privateKey|"der"/);
        }
    });

    it('a certBag holding unreadable bytes is reported by size; friendlyName and crlBytes pass through', () => {
        const base = parsePkcs12(fixtureBytes('nomac.p12'), SILENT).contents[0]?.bags[0];
        expect(base).toBeDefined();
        const bag = base as NonNullable<typeof base>;
        expect(bagView(bag, SILENT)).toEqual({ path: 'authSafe[0].bags[0]', kind: 'certBag', oid: bag.oid, certificate: { subject: expect.stringContaining('Test Intermediate CA'), issuer: expect.stringContaining('Test Root CA'), serialNumber: '02' } });
        const broken = { ...bag, certificateDer: new Uint8Array([1, 2, 3]), friendlyName: 'inter', crlDer: new Uint8Array(10) };
        expect(bagView(broken, SILENT)).toEqual({ path: 'authSafe[0].bags[0]', kind: 'certBag', oid: bag.oid, friendlyName: 'inter', certificate: { unreadable: true, bytes: 3 }, crlBytes: 10 });
        const encrypted = { ...bag, kind: 'pkcs8ShroudedKeyBag' as const, certificateDer: undefined, encryptedKey: parseEncryptedPrivateKeyInfo(pemDer('leaf.key.enc.pem'), SILENT) };
        const view = bagView(encrypted, SILENT);
        expect(view.key).toMatchObject({ format: 'encrypted-pkcs8', encryptedBytes: 144 });
        assertNoSecret(JSON.stringify(view), 'bagView shrouded');
    });
});

describe('signingKeyView', () => {
    it('describes the Web Crypto handle (non-extractable, sign) and the algorithm, never the key', async () => {
        const key = await importPrivateKey(fixtureBytes('leaf.key.der'), { ...SILENT, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });
        const view = signingKeyView(key);
        expect(view).toEqual({ algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }, key: { type: 'private', algorithm: 'ECDSA', extractable: false, usages: ['sign'] } });
        assertNoSecret(JSON.stringify(view), 'signingKeyView');
        assertWithinSchema(view, SIGNING_KEY_VIEW_SCHEMA);
        assertWithinSchema(view.key, SIGNING_KEY_VIEW_SCHEMA.properties.key);
        expect(SIGNING_KEY_VIEW_SCHEMA.properties.key.properties.extractable.enum).toEqual([false]);
    });
});

describe('dn', () => {
    it('renders RFC 4514 and (empty) for an empty name', () => {
        const cert = parseCertificate(fixtureBytes('leaf.crt.der'), SILENT);
        expect(dn(cert.subject)).toBe('CN=example.test,O=pkinative-cli test,C=FR');
        expect(dn(cert.issuer)).toContain('CN=Test Intermediate CA');
        const empty: DistinguishedName = { rdns: [], der: new Uint8Array([0x30, 0x00]) };
        expect(dn(empty)).toBe('(empty)');
    });
});

describe('the JSON Schema fragments', () => {
    it('are closed objects naming every view member', () => {
        expect(ENCRYPTION_VIEW_SCHEMA).toMatchObject({ type: 'object', additionalProperties: false, required: ['scheme', 'algorithm'] });
        expect(Object.keys(ENCRYPTION_VIEW_SCHEMA.properties)).toEqual(['scheme', 'algorithm', 'pbes2']);
        expect(ENCRYPTION_VIEW_SCHEMA.properties.pbes2.required).toEqual(['iterations', 'prf', 'keyBits', 'cipher', 'saltBytes']);
        expect(KEY_VIEW_SCHEMA).toMatchObject({ type: 'object', additionalProperties: false });
        expect(Object.keys(KEY_VIEW_SCHEMA.properties)).toEqual(['format', 'version', 'kind', 'curve', 'algorithm', 'attributes', 'publicKey', 'encryption', 'encryptedBytes']);
        expect(KEY_VIEW_SCHEMA.properties.format.enum).toEqual(['pkcs8', 'encrypted-pkcs8']);
        expect(KEY_VIEW_SCHEMA.properties.encryption).toBe(ENCRYPTION_VIEW_SCHEMA);
        expect(SIGNING_KEY_VIEW_SCHEMA).toMatchObject({ type: 'object', additionalProperties: false, required: ['algorithm', 'key'] });
        expect(SIGNING_KEY_VIEW_SCHEMA.properties.key.required).toEqual(['type', 'algorithm', 'extractable', 'usages']);
        // No schema offers a member that could carry bytes.
        for (const schema of [ENCRYPTION_VIEW_SCHEMA, KEY_VIEW_SCHEMA, SIGNING_KEY_VIEW_SCHEMA]) {
            expect(JSON.stringify(schema)).not.toMatch(/"(der|valueDer|privateKey|bytes|hex|salt|iv|mac)"/);
        }
    });
});
