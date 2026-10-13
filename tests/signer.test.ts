/**
 * Tests for `src/signer.ts` — the SIGNER fragment: the signature algorithm
 * chosen from the key (never guessed), PKCS#8 keys plain and encrypted,
 * PKCS#12 files, and the refusals. No error ever carries a key byte or the
 * password.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { createPublicKey, type webcrypto } from 'node:crypto';
import { decodePem } from 'pkinative';

import { ToolError } from '../src/errors.js';
import { createParseContext } from '../src/parse-context.js';
import { PASSWORD_ENV } from '../src/secrets.js';
import { derivePublicKey, HASHES, isEncryptedPkcs8, KEY_TYPES, loadSigner, SIGNER_INPUT_SCHEMA, signatureAlgorithm, SignerSchema, type SignerInput } from '../src/signer.js';
import { assertNoSecret } from './_pki-assert.js';
import { fixtureBase64, fixtureBytes, fixtureInput, fixtureText, PASSWORD } from './_pki-fixtures.js';

const ctx = createParseContext({});

/** A signer input as the tool receives it after validation. */
function signer(fields: Record<string, unknown>): SignerInput {
    return fields as SignerInput;
}

function nodeSpki(keyPem: string): Uint8Array {
    return new Uint8Array(createPublicKey(keyPem).export({ type: 'spki', format: 'der' }));
}

async function rejectionOf(p: Promise<unknown>): Promise<ToolError> {
    try {
        await p;
    } catch (err) {
        if (err instanceof ToolError) {
            assertNoSecret(JSON.stringify({ message: err.message, data: err.data }), `${err.code} error`);
            return err;
        }
        throw err;
    }
    throw new Error('expected the call to reject');
}

function thrown(fn: () => unknown): ToolError {
    try {
        fn();
    } catch (err) {
        if (err instanceof ToolError) {
            assertNoSecret(JSON.stringify({ message: err.message, data: err.data }), `${err.code} error`);
            return err;
        }
        throw err;
    }
    throw new Error('expected the call to throw');
}

describe('signatureAlgorithm', () => {
    const KEY = { key: { pem: '-----BEGIN PRIVATE KEY-----' } };

    it('EC: ECDSA on the key curve with the curve hash unless hash says otherwise', () => {
        expect(signatureAlgorithm(signer(KEY), false, 'ec', 'P-256')).toEqual({ name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' });
        expect(signatureAlgorithm(signer(KEY), false, 'ec', 'P-384')).toEqual({ name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' });
        expect(signatureAlgorithm(signer(KEY), false, 'ec', 'P-521')).toEqual({ name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' });
        expect(signatureAlgorithm(signer({ ...KEY, hash: 'SHA-512' }), false, 'ec', 'P-256')).toEqual({ name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-256' });
        const err = thrown(() => signatureAlgorithm(signer(KEY), false, 'ec', undefined));
        expect(err.code).toBe('UNSUPPORTED_KEY');
        expect(err.data).toEqual({ errorClass: 'unsupported' });
    });

    it('Ed25519 / Ed448: no hash; a hash is VALIDATION_ERROR', () => {
        expect(signatureAlgorithm(signer(KEY), false, 'ed25519', undefined)).toEqual({ name: 'Ed25519' });
        expect(signatureAlgorithm(signer(KEY), false, 'ed448', undefined)).toEqual({ name: 'Ed448' });
        const err = thrown(() => signatureAlgorithm(signer({ ...KEY, hash: 'SHA-256' }), false, 'ed25519', undefined));
        expect(err.code).toBe('VALIDATION_ERROR');
        expect(err.message).toContain('Ed25519');
        expect(err.data).toEqual({ path: 'signer.hash' });
        expect(thrown(() => signatureAlgorithm(signer({ ...KEY, hash: 'SHA-512' }), false, 'ed448', undefined)).message).toContain('Ed448');
    });

    it('RSA: rsaScheme is required (pkcs1 or pss, SHA-256 default); an id-RSASSA-PSS key signs pss only', () => {
        const noScheme = thrown(() => signatureAlgorithm(signer(KEY), false, 'rsa', undefined));
        expect(noScheme.code).toBe('RSA_SCHEME_REQUIRED');
        expect(noScheme.data).toEqual({ path: 'signer.rsaScheme', remedy: "rsaScheme:'pkcs1'|'pss'" });
        expect(signatureAlgorithm(signer({ ...KEY, rsaScheme: 'pkcs1' }), false, 'rsa', undefined)).toEqual({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' });
        expect(signatureAlgorithm(signer({ ...KEY, rsaScheme: 'pkcs1', hash: 'SHA-384' }), false, 'rsa', undefined)).toEqual({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' });
        expect(signatureAlgorithm(signer({ ...KEY, rsaScheme: 'pss' }), false, 'rsa', undefined)).toEqual({ name: 'RSA-PSS', hash: 'SHA-256' });
        expect(signatureAlgorithm(signer({ ...KEY, rsaScheme: 'pss', saltLength: 32 }), false, 'rsa', undefined)).toEqual({ name: 'RSA-PSS', hash: 'SHA-256', saltLength: 32 });
        expect(signatureAlgorithm(signer({ ...KEY, rsaScheme: 'pss', saltLength: 0 }), false, 'rsa', undefined)).toEqual({ name: 'RSA-PSS', hash: 'SHA-256', saltLength: 0 });
        expect(signatureAlgorithm(signer(KEY), false, 'rsa-pss', undefined)).toEqual({ name: 'RSA-PSS', hash: 'SHA-256' });
        expect(signatureAlgorithm(signer({ ...KEY, rsaScheme: 'pss' }), false, 'rsa-pss', undefined)).toEqual({ name: 'RSA-PSS', hash: 'SHA-256' });
        const pssOnly = thrown(() => signatureAlgorithm(signer({ ...KEY, rsaScheme: 'pkcs1' }), false, 'rsa-pss', undefined));
        expect(pssOnly.code).toBe('VALIDATION_ERROR');
        expect(pssOnly.data).toEqual({ path: 'signer.rsaScheme' });
        const salt = thrown(() => signatureAlgorithm(signer({ ...KEY, rsaScheme: 'pkcs1', saltLength: 20 }), false, 'rsa', undefined));
        expect(salt.code).toBe('VALIDATION_ERROR');
        expect(salt.data).toEqual({ path: 'signer.saltLength' });
    });

    it('rsaScheme / saltLength on a non-RSA key is VALIDATION_ERROR', () => {
        for (const [kind, curve] of [['ec', 'P-256'], ['ed25519', undefined], ['ed448', undefined]] as const) {
            const err = thrown(() => signatureAlgorithm(signer({ ...KEY, rsaScheme: 'pss' }), false, kind, curve));
            expect(err.code, kind).toBe('VALIDATION_ERROR');
            expect(err.data, kind).toEqual({ path: 'signer.rsaScheme' });
            expect(thrown(() => signatureAlgorithm(signer({ ...KEY, saltLength: 1 }), false, kind, curve)).code, kind).toBe('VALIDATION_ERROR');
        }
    });

    it('SHA-1 needs allowSha1 (VALIDATION_ERROR with the remedy otherwise), for every key family', () => {
        const refused = thrown(() => signatureAlgorithm(signer({ ...KEY, hash: 'SHA-1' }), false, 'ec', 'P-256'));
        expect(refused.code).toBe('VALIDATION_ERROR');
        expect(refused.data).toEqual({ path: 'signer.hash', remedy: 'allowSha1:true' });
        expect(thrown(() => signatureAlgorithm(signer({ ...KEY, hash: 'SHA-1', rsaScheme: 'pkcs1' }), false, 'rsa', undefined)).data).toEqual({ path: 'signer.hash', remedy: 'allowSha1:true' });
        expect(signatureAlgorithm(signer({ ...KEY, hash: 'SHA-1' }), true, 'ec', 'P-256')).toEqual({ name: 'ECDSA', hash: 'SHA-1', namedCurve: 'P-256' });
        expect(signatureAlgorithm(signer({ ...KEY, hash: 'SHA-1', rsaScheme: 'pkcs1' }), true, 'rsa', undefined)).toEqual({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' });
        // SHA-1 under allowSha1 is still refused where no hash applies.
        expect(thrown(() => signatureAlgorithm(signer({ ...KEY, hash: 'SHA-1' }), true, 'ed25519', undefined)).data).toEqual({ path: 'signer.hash' });
    });
});

describe('loadSigner — PKCS#8', () => {
    afterEach(() => {
        delete process.env[PASSWORD_ENV];
    });

    it('a plain EC key: ECDSA P-256 / SHA-256, the public key derived, not encrypted, no certificate', async () => {
        const loaded = await loadSigner(signer({ key: fixtureInput('leaf.key.pem') }), false, undefined, ctx);
        expect(loaded.signer.algorithm).toEqual({ name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' });
        expect(loaded.encrypted).toBe(false);
        expect(loaded.certificate).toBeUndefined();
        expect(loaded.chain).toEqual([]);
        expect(loaded.publicKey).toEqual(nodeSpki(fixtureText('leaf.key.pem')));
        const handle = loaded.signer.key as unknown as webcrypto.CryptoKey;
        expect(handle.extractable).toBe(false);
        expect(handle.type).toBe('private');
        expect([...handle.usages]).toEqual(['sign']);
        // DER as base64 and a hash override.
        const der = await loadSigner(signer({ key: { derBase64: fixtureBase64('leaf.key.der') }, hash: 'SHA-384' }), false, undefined, ctx);
        expect(der.signer.algorithm).toEqual({ name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-256' });
        expect(der.publicKey).toEqual(loaded.publicKey);
    });

    it('an RSA key needs rsaScheme; pss and pkcs1 both import', async () => {
        const err = await rejectionOf(loadSigner(signer({ key: fixtureInput('rsa.key.pem') }), false, undefined, ctx));
        expect(err.code).toBe('RSA_SCHEME_REQUIRED');
        const pss = await loadSigner(signer({ key: fixtureInput('rsa.key.pem'), rsaScheme: 'pss' }), false, undefined, ctx);
        expect(pss.signer.algorithm).toEqual({ name: 'RSA-PSS', hash: 'SHA-256' });
        expect(pss.publicKey).toEqual(nodeSpki(fixtureText('rsa.key.pem')));
        expect(pss.encrypted).toBe(false);
        const pkcs1 = await loadSigner(signer({ key: fixtureInput('rsa.key.pem'), rsaScheme: 'pkcs1', hash: 'SHA-512' }), false, undefined, ctx);
        expect(pkcs1.signer.algorithm).toEqual({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' });
    });

    it('an Ed25519 key signs Ed25519; a hash is refused', async () => {
        const loaded = await loadSigner(signer({ key: fixtureInput('ed25519.key.pem') }), false, undefined, ctx);
        expect(loaded.signer.algorithm).toEqual({ name: 'Ed25519' });
        expect(loaded.publicKey).toEqual(nodeSpki(fixtureText('ed25519.key.pem')));
        expect((await rejectionOf(loadSigner(signer({ key: fixtureInput('ed25519.key.pem'), hash: 'SHA-256' }), false, undefined, ctx))).code).toBe('VALIDATION_ERROR');
    });

    it('an encrypted key: SECRET_REQUIRED without a password, KEY_TYPE_REQUIRED without a type, then decrypts under keyType or the hint', async () => {
        const enc = fixtureInput('leaf.key.enc.pem');
        const noPassword = await rejectionOf(loadSigner(signer({ key: enc }), false, undefined, ctx));
        expect(noPassword.code).toBe('SECRET_REQUIRED');
        expect(noPassword.message).toContain('The key is encrypted and needs its password');
        expect(noPassword.data).toEqual({ remedy: 'password' });
        const noType = await rejectionOf(loadSigner(signer({ key: enc, password: PASSWORD }), false, undefined, ctx));
        expect(noType.code).toBe('KEY_TYPE_REQUIRED');
        expect(noType.message).toContain(KEY_TYPES.join('|'));
        expect(noType.data).toEqual({ path: 'signer.keyType', remedy: 'keyType' });
        const typed = await loadSigner(signer({ key: enc, password: PASSWORD, keyType: 'ec-p256' }), false, undefined, ctx);
        expect(typed.signer.algorithm).toEqual({ name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' });
        expect(typed.encrypted).toBe(true);
        expect(typed.publicKey).toBeUndefined();
        expect(typed.certificate).toBeUndefined();
        expect((typed.signer.key as unknown as webcrypto.CryptoKey).extractable).toBe(false);
        const hinted = await loadSigner(signer({ key: enc, password: PASSWORD }), false, { kind: 'ec', curve: 'P-256' }, ctx);
        expect(hinted.signer.algorithm).toEqual({ name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' });
        // keyType wins over the hint; the password may come from the environment.
        process.env[PASSWORD_ENV] = PASSWORD;
        const fromEnv = await loadSigner(signer({ key: enc, keyType: 'ec-p256', hash: 'SHA-512' }), false, { kind: 'rsa' }, ctx);
        expect(fromEnv.signer.algorithm).toEqual({ name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-256' });
        expect((await rejectionOf(loadSigner(signer({ key: enc, password: PASSWORD, keyType: 'ec-p256' }), false, undefined, ctx))).code).toBe('VALIDATION_ERROR');
    });

    it('a wrong password is PKI_CRYPTO_DECRYPTION_FAILED (password class) and a wrong type is a crypto refusal; neither echoes the password', async () => {
        const enc = fixtureInput('leaf.key.enc.pem');
        const wrong = await rejectionOf(loadSigner(signer({ key: enc, password: 'not-the-password', keyType: 'ec-p256' }), false, undefined, ctx));
        expect(wrong.code).toBe('PKI_CRYPTO_DECRYPTION_FAILED');
        expect(wrong.data).toMatchObject({ errorClass: 'password', engineError: 'PkiCryptoError', remedy: expect.stringContaining('PKINATIVE_MCP_PASSWORD') });
        expect(wrong.message).not.toContain('not-the-password');
        const mistyped = await rejectionOf(loadSigner(signer({ key: enc, password: PASSWORD, keyType: 'rsa', rsaScheme: 'pss' }), false, undefined, ctx));
        expect(mistyped.code).toMatch(/^PKI_/);
        // The RSA encrypted fixture needs its scheme like a plain RSA key.
        expect((await rejectionOf(loadSigner(signer({ key: fixtureInput('rsa.key.enc.pem'), password: PASSWORD, keyType: 'rsa' }), false, undefined, ctx))).code).toBe('RSA_SCHEME_REQUIRED');
        const rsa = await loadSigner(signer({ key: fixtureInput('rsa.key.enc.pem'), password: PASSWORD, keyType: 'rsa', rsaScheme: 'pkcs1' }), false, undefined, ctx);
        expect(rsa.signer.algorithm).toEqual({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' });
        expect(rsa.encrypted).toBe(true);
    });

    it('a PUBLIC KEY, a certificate or a non-key DER as signer.key is refused by label / by the PKCS#8 reader', async () => {
        const pub = await rejectionOf(loadSigner(signer({ key: fixtureInput('leaf.pub.pem') }), false, undefined, ctx));
        expect(pub.code).toBe('PKI_PEM_UNEXPECTED_LABEL');
        expect(pub.message).toContain('signer.key (pem) holds no PRIVATE KEY or ENCRYPTED PRIVATE KEY PEM block');
        expect((await rejectionOf(loadSigner(signer({ key: fixtureInput('leaf.crt.pem') }), false, undefined, ctx))).code).toBe('PKI_PEM_UNEXPECTED_LABEL');
        const der = await rejectionOf(loadSigner(signer({ key: { derBase64: fixtureBase64('leaf.crt.der') } }), false, undefined, ctx));
        expect(der.code).toMatch(/^PKI_/);
        expect(der.message).toContain('PKCS#8 expected');
        expect(der.message).toContain('openssl pkcs8 -topk8');
        expect((await rejectionOf(loadSigner(signer({ key: { derBase64: fixtureBase64('leaf.crt.der') }, password: 'x' }), false, undefined, ctx))).code).toMatch(/^PKI_/);
    });
});

describe('loadSigner — PKCS#12', () => {
    it('leaf.p12: the key, its certificate, the chain (the intermediate) and the public key; always encrypted', async () => {
        const loaded = await loadSigner(signer({ p12: { derBase64: fixtureBase64('leaf.p12') }, password: PASSWORD }), false, undefined, ctx);
        expect(loaded.signer.algorithm).toEqual({ name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' });
        expect(loaded.encrypted).toBe(true);
        expect(loaded.certificate?.serialNumber.hex).toBe('1001');
        expect(loaded.chain.map((c) => c.serialNumber.hex)).toEqual(['02']);
        expect(loaded.publicKey).toEqual(loaded.certificate?.subjectPublicKeyInfo.der);
        expect(loaded.publicKey).toEqual(nodeSpki(fixtureText('leaf.key.pem')));
        expect((loaded.signer.key as unknown as webcrypto.CryptoKey).extractable).toBe(false);
        // A hash re-targets an ECDSA key; the scheme inputs are refused on it.
        const sha512 = await loadSigner(signer({ p12: { derBase64: fixtureBase64('leaf.p12') }, password: PASSWORD, hash: 'SHA-512' }), false, undefined, ctx);
        expect(sha512.signer.algorithm).toEqual({ name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-256' });
        expect(sha512.signer.key).toBe(sha512.signer.key);
        const scheme = await rejectionOf(loadSigner(signer({ p12: { derBase64: fixtureBase64('leaf.p12') }, password: PASSWORD, rsaScheme: 'pss' }), false, undefined, ctx));
        expect(scheme.code).toBe('VALIDATION_ERROR');
        expect(scheme.data).toEqual({ path: 'signer.rsaScheme' });
    });

    it('no password is SECRET_REQUIRED before the file is read; a wrong password is PKI_CRYPTO_DECRYPTION_FAILED', async () => {
        const none = await rejectionOf(loadSigner(signer({ p12: { derBase64: fixtureBase64('leaf.p12') } }), false, undefined, ctx));
        expect(none.code).toBe('SECRET_REQUIRED');
        expect(none.message).toContain('A PKCS#12 file needs its password');
        expect((await rejectionOf(loadSigner(signer({ p12: { derBase64: 'AAAA' } }), false, undefined, ctx))).code).toBe('SECRET_REQUIRED');
        const wrong = await rejectionOf(loadSigner(signer({ p12: { derBase64: fixtureBase64('leaf.p12') }, password: 'not-the-password-7f3a' }), false, undefined, ctx));
        expect(wrong.code).toBe('PKI_CRYPTO_DECRYPTION_FAILED');
        expect(wrong.data).toMatchObject({ errorClass: 'password', reasons: [expect.objectContaining({ code: 'PKI_REASON_PKCS12_MAC_MISMATCH' })] });
        expect(JSON.stringify({ message: wrong.message, data: wrong.data })).not.toContain('not-the-password-7f3a');
    });

    it('rsa.p12 needs rsaScheme (RSA_SCHEME_REQUIRED from the report); with pss it opens', async () => {
        const err = await rejectionOf(loadSigner(signer({ p12: { derBase64: fixtureBase64('rsa.p12') }, password: PASSWORD }), false, undefined, ctx));
        expect(err.code).toBe('RSA_SCHEME_REQUIRED');
        expect(err.data).toMatchObject({ remedy: "rsaScheme:'pkcs1'|'pss'", reasons: [expect.objectContaining({ code: 'PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED' })] });
        const pss = await loadSigner(signer({ p12: { derBase64: fixtureBase64('rsa.p12') }, password: PASSWORD, rsaScheme: 'pss', saltLength: 32 }), false, undefined, ctx);
        expect(pss.signer.algorithm).toEqual({ name: 'RSA-PSS', hash: 'SHA-256', saltLength: 32 });
        expect(pss.certificate?.serialNumber.hex).toBe('1003');
        expect(pss.chain).toEqual([]);
        const pkcs1 = await loadSigner(signer({ p12: { derBase64: fixtureBase64('rsa.p12') }, password: PASSWORD, rsaScheme: 'pkcs1', hash: 'SHA-384' }), false, undefined, ctx);
        expect(pkcs1.signer.algorithm).toEqual({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' });
    });

    it('ed25519.p12 signs Ed25519; a hash is refused', async () => {
        const loaded = await loadSigner(signer({ p12: { derBase64: fixtureBase64('ed25519.p12') }, password: PASSWORD }), false, undefined, ctx);
        expect(loaded.signer.algorithm).toEqual({ name: 'Ed25519' });
        expect(loaded.certificate?.serialNumber.hex).toBe('03');
        const err = await rejectionOf(loadSigner(signer({ p12: { derBase64: fixtureBase64('ed25519.p12') }, password: PASSWORD, hash: 'SHA-256' }), false, undefined, ctx));
        expect(err.code).toBe('VALIDATION_ERROR');
        expect(err.data).toEqual({ path: 'signer.hash' });
    });

    it('legacy.p12 is PKI_KEY_ENCRYPTION_UNSUPPORTED (security class) with the OpenSSL 3.4 conversion', async () => {
        const err = await rejectionOf(loadSigner(signer({ p12: { derBase64: fixtureBase64('legacy.p12') }, password: PASSWORD }), false, undefined, ctx));
        expect(err.code).toBe('PKI_KEY_ENCRYPTION_UNSUPPORTED');
        expect(err.data).toMatchObject({ errorClass: 'security', remedy: expect.stringContaining('openssl pkcs12 -in legacy.p12 -legacy') });
        expect(err.message).toContain('PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED');
    });

    it('nomac.p12 is ENGINE_VERDICT with the allowUnverifiedIntegrity remedy', async () => {
        const err = await rejectionOf(loadSigner(signer({ p12: { derBase64: fixtureBase64('nomac.p12') }, password: PASSWORD }), false, undefined, ctx));
        expect(err.code).toBe('ENGINE_VERDICT');
        expect(err.message).toContain('integrity cannot be verified');
        expect(err.data).toMatchObject({ remedy: expect.stringContaining('allowUnverifiedIntegrity:true'), reasons: [expect.objectContaining({ code: 'PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED' })] });
    });

    it('certs-only.p12 opens but holds no key: VALIDATION_ERROR at signer.p12', async () => {
        const err = await rejectionOf(loadSigner(signer({ p12: { derBase64: fixtureBase64('certs-only.p12') }, password: PASSWORD }), false, undefined, ctx));
        expect(err.code).toBe('VALIDATION_ERROR');
        expect(err.message).toBe('The PKCS#12 file holds 0 usable keys; exactly one is needed to sign.');
        expect(err.data).toEqual({ path: 'signer.p12' });
    });

    it('plain-keybag.p12: an unencrypted keyBag imports like any other, and nothing reports its bytes', async () => {
        const loaded = await loadSigner(signer({ p12: { derBase64: fixtureBase64('plain-keybag.p12') }, password: PASSWORD }), false, undefined, ctx);
        expect(loaded.signer.algorithm).toEqual({ name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' });
        expect(loaded.certificate?.serialNumber.hex).toBe('1001');
        assertNoSecret(JSON.stringify({ algorithm: loaded.signer.algorithm, certificate: loaded.certificate?.serialNumber.hex, chain: loaded.chain.length, publicKey: Buffer.from(loaded.publicKey ?? []).toString('hex') }));
    });
});

describe('derivePublicKey / isEncryptedPkcs8', () => {
    it('derivePublicKey matches node:crypto for every key family and refuses non-keys', () => {
        expect(derivePublicKey(fixtureBytes('leaf.key.der'))).toEqual(nodeSpki(fixtureText('leaf.key.pem')));
        for (const name of ['rsa.key.pem', 'ed25519.key.pem']) {
            const der = decodePem(fixtureText(name))[0]?.bytes as Uint8Array;
            expect(derivePublicKey(der), name).toEqual(nodeSpki(fixtureText(name)));
        }
        const err = thrown(() => derivePublicKey(fixtureBytes('leaf.crt.der')));
        expect(err.code).toBe('ENGINE_ERROR');
        expect(err.message).toContain('Cannot derive the public key');
    });

    it('isEncryptedPkcs8: false for a plain key, true for an EncryptedPrivateKeyInfo, the PKCS#8 cause otherwise', () => {
        expect(isEncryptedPkcs8(fixtureBytes('leaf.key.der'), ctx)).toBe(false);
        expect(isEncryptedPkcs8(decodePem(fixtureText('leaf.key.enc.pem'))[0]?.bytes as Uint8Array, ctx)).toBe(true);
        expect(isEncryptedPkcs8(decodePem(fixtureText('rsa.key.enc.pem'))[0]?.bytes as Uint8Array, ctx)).toBe(true);
        const err = thrown(() => isEncryptedPkcs8(fixtureBytes('leaf.crt.der'), ctx));
        expect(err.code).toMatch(/^PKI_/);
        expect(err.message).toContain('convert a SEC1 or PKCS#1 key with openssl pkcs8 -topk8');
        expect(thrown(() => isEncryptedPkcs8(new Uint8Array([1, 2]), ctx)).code).toMatch(/^PKI_ASN1_/);
    });
});

describe('SIGNER_INPUT_SCHEMA / SignerSchema', () => {
    it('are in lock-step and share the enums', () => {
        expect(Object.keys(SIGNER_INPUT_SCHEMA.properties)).toEqual(Object.keys(SignerSchema.shape));
        expect(Object.keys(SIGNER_INPUT_SCHEMA.properties)).toEqual(['key', 'p12', 'password', 'keyType', 'hash', 'rsaScheme', 'saltLength']);
        expect(SIGNER_INPUT_SCHEMA.additionalProperties).toBe(false);
        expect(SIGNER_INPUT_SCHEMA.properties.keyType.enum).toEqual([...KEY_TYPES]);
        expect(SIGNER_INPUT_SCHEMA.properties.hash.enum).toEqual([...HASHES]);
        expect(SIGNER_INPUT_SCHEMA.properties.rsaScheme.enum).toEqual(['pkcs1', 'pss']);
        expect(SIGNER_INPUT_SCHEMA.properties.saltLength).toMatchObject({ type: 'integer', minimum: 0, maximum: 512 });
        expect(SIGNER_INPUT_SCHEMA.description).toContain('NON-EXTRACTABLE');
        expect(KEY_TYPES).toEqual(['ec-p256', 'ec-p384', 'ec-p521', 'ed25519', 'ed448', 'rsa', 'rsa-pss']);
        expect(HASHES).toEqual(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']);
    });

    it('SignerSchema: exactly one of key / p12, saltLength only with pss, the enums enforced', () => {
        const key = { pem: fixtureText('leaf.key.pem') };
        expect(SignerSchema.safeParse({ key }).success).toBe(true);
        expect(SignerSchema.safeParse({ p12: { derBase64: 'AAAA' }, password: 'x' }).success).toBe(true);
        expect(SignerSchema.safeParse({}).success).toBe(false);
        expect(SignerSchema.safeParse({ key, p12: { derBase64: 'AAAA' } }).success).toBe(false);
        expect(SignerSchema.safeParse({ key, saltLength: 32 }).success).toBe(false);
        expect(SignerSchema.safeParse({ key, rsaScheme: 'pkcs1', saltLength: 32 }).success).toBe(false);
        expect(SignerSchema.safeParse({ key, rsaScheme: 'pss', saltLength: 32 }).success).toBe(true);
        expect(SignerSchema.safeParse({ key, rsaScheme: 'pss', saltLength: 513 }).success).toBe(false);
        expect(SignerSchema.safeParse({ key, keyType: 'ec' }).success).toBe(false);
        expect(SignerSchema.safeParse({ key, hash: 'MD5' }).success).toBe(false);
        expect(SignerSchema.safeParse({ key, password: '' }).success).toBe(false);
        expect(SignerSchema.safeParse({ key, extra: 1 }).success).toBe(false);
    });
});
