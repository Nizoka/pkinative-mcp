/**
 * Tests for `inspect_private_key` — plain and encrypted descriptions, the
 * import proof, every error code, projection, path inputs, and the
 * secret-leak matrix: no key byte, scalar, base64 or password in any result
 * or on stderr, whatever the password given.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { ToolError } from '../src/errors.js';
import { callToolDirect } from '../src/server.js';
import { inspectPrivateKey, inspectPrivateKeySummary, INSPECT_PRIVATE_KEY_TOOL } from '../src/tools/inspect-private-key.js';
import { assertNoSecret, assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureBase64, fixtureInput, fixtureText, PASSWORD } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const WRONG = 'definitely-wrong';
const KEY_FIXTURES = ['leaf.key.pem', 'leaf.key.der', 'rsa.key.pem', 'ed25519.key.pem', 'leaf.key.enc.pem', 'rsa.key.enc.pem'] as const;
const P12_FIXTURES = ['leaf.p12', 'rsa.p12', 'ed25519.p12', 'legacy.p12', 'plain-keybag.p12', 'nomac.p12', 'certs-only.p12'] as const;
const handle = (algorithm: string): Record<string, unknown> => ({ type: 'private', algorithm, extractable: false, usages: ['sign'] });

async function thrown(p: Promise<unknown>): Promise<ToolError> {
    try {
        await p;
    } catch (e) {
        if (e instanceof ToolError) return e;
        throw e;
    }
    return expect.unreachable('expected a ToolError');
}

describe('inspect_private_key', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_PASSWORD'];
    });

    afterEach(async () => {
        delete process.env['PKINATIVE_MCP_PASSWORD'];
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('descriptions (no password)', () => {
        it('describes a plain EC key from PEM and DER without a byte of it', async () => {
            const pem = await inspectPrivateKey({ key: fixtureInput('leaf.key.pem') });
            expect(pem).toMatchObject({ format: 'pkcs8', version: 0, kind: 'ec', curve: 'P-256', algorithm: '1.2.840.10045.2.1', algorithmName: 'ecPublicKey', attributes: [], publicKey: false, encrypted: false, diagnostics: [] });
            expect(pem.sizeBytes).toBeGreaterThan(100);
            expect(pem.imported).toBeUndefined();
            expect(pem.encryption).toBeUndefined();
            const der = await inspectPrivateKey({ key: { derBase64: fixtureBase64('leaf.key.der') } });
            expect(der).toMatchObject({ format: 'pkcs8', kind: 'ec', curve: 'P-256', encrypted: false, sizeBytes: pem.sizeBytes });
            assertResultClean(pem);
            assertResultClean(der);
        });

        it.each([
            ['rsa.key.pem', 'rsa', 'rsaEncryption'],
            ['ed25519.key.pem', 'ed25519', 'Ed25519'],
        ])('%s is a %s key (%s)', async (name, kind, algorithmName) => {
            const r = await inspectPrivateKey({ key: fixtureInput(name) });
            expect(r).toMatchObject({ format: 'pkcs8', kind, algorithmName, encrypted: false });
            expect(r.curve).toBeUndefined();
            assertResultClean(r);
        });

        it('describes an encrypted key by its PBES2 parameters only', async () => {
            const r = await inspectPrivateKey({ key: fixtureInput('leaf.key.enc.pem') });
            expect(r).toMatchObject({
                format: 'encrypted-pkcs8',
                encrypted: true,
                encryptedBytes: 144,
                encryption: { scheme: 'PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC)', algorithm: '1.2.840.113549.1.5.13', pbes2: { iterations: 2048, prf: 'SHA-256', keyBits: 256, cipher: expect.stringMatching(/aes/i) } },
            });
            expect(r.encryption?.pbes2?.saltBytes).toBeGreaterThan(0);
            expect(r.kind).toBeUndefined();
            expect(r.algorithmName).toBeUndefined();
            const rsa = await inspectPrivateKey({ key: fixtureInput('rsa.key.enc.pem') });
            expect(rsa).toMatchObject({ format: 'encrypted-pkcs8', encryptedBytes: 1232 });
            assertResultClean(r);
            assertResultClean(rsa);
        });
    });

    describe('tryImport (non-extractable, never exported)', () => {
        it('imports a plain EC key under its curve hash, or the hash asked for', async () => {
            const r = await inspectPrivateKey({ key: fixtureInput('leaf.key.pem'), tryImport: true });
            expect(r.imported).toEqual({ ok: true, encrypted: false, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }, key: handle('ECDSA') });
            const sha384 = await inspectPrivateKey({ key: fixtureInput('leaf.key.pem'), tryImport: true, hash: 'SHA-384' });
            expect(sha384.imported?.algorithm).toEqual({ name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-256' });
            assertResultClean(r);
        });

        it('imports Ed25519 without a hash and refuses one', async () => {
            const r = await inspectPrivateKey({ key: fixtureInput('ed25519.key.pem'), tryImport: true });
            expect(r.imported).toEqual({ ok: true, encrypted: false, algorithm: { name: 'Ed25519' }, key: handle('Ed25519') });
            expect(await codeOf(inspectPrivateKey({ key: fixtureInput('ed25519.key.pem'), tryImport: true, hash: 'SHA-256' }))).toBe('VALIDATION_ERROR');
        });

        it('imports an RSA key under the scheme asked for, and needs one', async () => {
            const pss = await inspectPrivateKey({ key: fixtureInput('rsa.key.pem'), tryImport: true, rsaScheme: 'pss', hash: 'SHA-512', saltLength: 64 });
            expect(pss.imported?.algorithm).toEqual({ name: 'RSA-PSS', hash: 'SHA-512', saltLength: 64 });
            const pkcs1 = await inspectPrivateKey({ key: fixtureInput('rsa.key.pem'), tryImport: true, rsaScheme: 'pkcs1' });
            expect(pkcs1.imported?.algorithm).toEqual({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' });
            const err = await thrown(inspectPrivateKey({ key: fixtureInput('rsa.key.pem'), tryImport: true }));
            expect(err.code).toBe('RSA_SCHEME_REQUIRED');
            expect(err.message).not.toContain('signer.');
            expect(err.data).toMatchObject({ path: 'rsaScheme' });
            expect(await codeOf(inspectPrivateKey({ key: fixtureInput('leaf.key.pem'), tryImport: true, rsaScheme: 'pss' }))).toBe('VALIDATION_ERROR');
            assertResultClean(pss);
        });

        it('decrypts an encrypted key with the password and its type', async () => {
            const ec = await inspectPrivateKey({ key: fixtureInput('leaf.key.enc.pem'), tryImport: true, password: PASSWORD, keyType: 'ec-p256' });
            expect(ec).toMatchObject({ format: 'encrypted-pkcs8', encrypted: true, imported: { ok: true, encrypted: true, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }, key: handle('ECDSA') } });
            const rsa = await inspectPrivateKey({ key: fixtureInput('rsa.key.enc.pem'), tryImport: true, password: PASSWORD, keyType: 'rsa', rsaScheme: 'pkcs1' });
            expect(rsa.imported?.algorithm).toEqual({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' });
            assertResultClean(ec);
            assertResultClean(rsa);
        });

        it('SECRET_REQUIRED without a password, KEY_TYPE_REQUIRED without the type (re-addressed to the top-level inputs)', async () => {
            expect(await codeOf(inspectPrivateKey({ key: fixtureInput('leaf.key.enc.pem'), tryImport: true, keyType: 'ec-p256' }))).toBe('SECRET_REQUIRED');
            const err = await thrown(inspectPrivateKey({ key: fixtureInput('leaf.key.enc.pem'), tryImport: true, password: PASSWORD }));
            expect(err.code).toBe('KEY_TYPE_REQUIRED');
            expect(err.message).not.toContain('signer.');
            expect(err.data).toMatchObject({ path: 'keyType', remedy: 'keyType' });
        });

        it('a wrong password is PKI_CRYPTO_DECRYPTION_FAILED and is never echoed', async () => {
            const result = await callToolDirect('inspect_private_key', { key: fixtureInput('leaf.key.enc.pem'), tryImport: true, password: WRONG, keyType: 'ec-p256' });
            expect(errorCodeOf(result)).toBe('PKI_CRYPTO_DECRYPTION_FAILED');
            expect(JSON.stringify(result)).not.toContain(WRONG);
            expect((result._meta?.['error'] as { data?: { remedy?: string } }).data?.remedy).toContain('password');
            assertResultClean(result);
        });

        it('takes the password from PKINATIVE_MCP_PASSWORD, and refuses two sources', async () => {
            process.env['PKINATIVE_MCP_PASSWORD'] = PASSWORD;
            const r = await inspectPrivateKey({ key: fixtureInput('leaf.key.enc.pem'), tryImport: true, keyType: 'ec-p256' });
            expect(r.imported?.encrypted).toBe(true);
            expect(await codeOf(inspectPrivateKey({ key: fixtureInput('leaf.key.enc.pem'), tryImport: true, keyType: 'ec-p256', password: PASSWORD }))).toBe('VALIDATION_ERROR');
            assertResultClean(r);
        });

        it('SHA-1 needs allowSha1', async () => {
            expect(await codeOf(inspectPrivateKey({ key: fixtureInput('leaf.key.pem'), tryImport: true, hash: 'SHA-1' }))).toBe('VALIDATION_ERROR');
            const r = await inspectPrivateKey({ key: fixtureInput('leaf.key.pem'), tryImport: true, hash: 'SHA-1', allowSha1: true });
            expect(r.imported?.algorithm).toEqual({ name: 'ECDSA', hash: 'SHA-1', namedCurve: 'P-256' });
        });
    });

    describe('projection', () => {
        it('summary keeps the scalars only', async () => {
            const plain = inspectPrivateKeySummary(await inspectPrivateKey({ key: fixtureInput('leaf.key.pem') }));
            expect(plain).toEqual({ format: 'pkcs8', kind: 'ec', curve: 'P-256', encrypted: false, scheme: null, diagnosticCount: 0 });
            const enc = inspectPrivateKeySummary(await inspectPrivateKey({ key: fixtureInput('leaf.key.enc.pem'), tryImport: true, password: PASSWORD, keyType: 'ec-p256' }));
            expect(enc).toEqual({ format: 'encrypted-pkcs8', kind: null, curve: null, encrypted: true, scheme: 'PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC)', imported: true, diagnosticCount: 0 });
        });

        it('fields project over the wire and the text line names the key', async () => {
            const result = await callToolDirect('inspect_private_key', { key: fixtureInput('rsa.key.pem'), verbosity: 'summary', fields: ['kind', 'nope'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ kind: 'rsa' });
            expect(result._meta).toEqual({ unmatchedFields: ['nope'], availableFields: expect.arrayContaining(['format', 'encrypted']) });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('inspect_private_key: plain PKCS#8 v0 rsa key (rsaEncryption)') });
            const enc = await callToolDirect('inspect_private_key', { key: fixtureInput('leaf.key.enc.pem') });
            expect((enc.content[0] as { text: string }).text).toContain('encrypted PKCS#8, PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC), 2048 PBKDF2 iterations, 144 encrypted bytes');
            assertResultClean(result);
            assertResultClean(enc);
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads a key from the sandbox and refuses escapes', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.key.der'), path.join(sandbox, 'leaf.key.der'));
            const r = await inspectPrivateKey({ key: { path: 'leaf.key.der' }, tryImport: true });
            expect(r).toMatchObject({ kind: 'ec', imported: { ok: true } });
            expect(await codeOf(inspectPrivateKey({ key: { path: '../leaf.key.der' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(inspectPrivateKey({ key: { path: 'missing.key' } }))).toBe('INPUT_NOT_FOUND');
        });
    });

    describe('refusals', () => {
        it('VALIDATION_ERROR: unknown key, two input forms, import options without tryImport, saltLength without pss', async () => {
            expect(await codeOf(inspectPrivateKey({ key: fixtureInput('leaf.key.pem'), bogus: 1 }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(inspectPrivateKey({ key: { pem: fixtureText('leaf.key.pem'), derBase64: fixtureBase64('leaf.key.der') } }))).toBe('VALIDATION_ERROR');
            for (const extra of [{ password: PASSWORD }, { keyType: 'ec-p256' }, { hash: 'SHA-256' }, { rsaScheme: 'pss' }, { saltLength: 32 }]) {
                const err = await thrown(inspectPrivateKey({ key: fixtureInput('leaf.key.pem'), ...extra }));
                expect(err.code, JSON.stringify(Object.keys(extra))).toBe('VALIDATION_ERROR');
                expect(JSON.stringify(err.data)).not.toContain(PASSWORD);
            }
            expect(await codeOf(inspectPrivateKey({ key: fixtureInput('rsa.key.pem'), tryImport: true, rsaScheme: 'pkcs1', saltLength: 32 }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(inspectPrivateKey({}))).toBe('VALIDATION_ERROR');
        });

        it('a PUBLIC KEY, a certificate and a PKCS#12 are not private keys', async () => {
            expect(await codeOf(inspectPrivateKey({ key: fixtureInput('leaf.pub.pem') }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(inspectPrivateKey({ key: fixtureInput('leaf.crt.pem') }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(inspectPrivateKey({ key: { derBase64: fixtureBase64('leaf.crt.der') } }))).toBe('PKI_KEY_STRUCTURE_INVALID');
            expect(await codeOf(inspectPrivateKey({ key: { derBase64: fixtureBase64('leaf.p12') } }))).toMatch(/^PKI_/);
        });

        it('strict escalates nothing on a clean key; ber is accepted', async () => {
            const r = await inspectPrivateKey({ key: fixtureInput('leaf.key.pem'), strict: true, encodingRules: 'ber' });
            expect(r.kind).toBe('ec');
        });
    });

    describe('secret-leak matrix (every fixture, every password, every verbosity)', () => {
        it('never writes a key byte, a scalar, a base64 body or the password anywhere', async () => {
            const stderr: string[] = [];
            const spy = vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: unknown) => { stderr.push(String(chunk)); return true; }) as typeof process.stderr.write);
            try {
                for (const name of [...KEY_FIXTURES, ...P12_FIXTURES]) {
                    for (const password of [PASSWORD, WRONG, undefined]) {
                        for (const verbosity of ['full', 'summary']) {
                            const args = { key: fixtureInput(name), tryImport: true, keyType: 'ec-p256', verbosity, ...(password !== undefined ? { password } : {}) };
                            const result = await callToolDirect('inspect_private_key', args);
                            assertResultClean(result, `${name} / ${password ?? 'no password'} / ${verbosity}`);
                            expect(JSON.stringify(result)).not.toContain(WRONG);
                        }
                    }
                    assertResultClean(await callToolDirect('inspect_private_key', { key: fixtureInput(name) }), `${name} / describe`);
                }
            } finally {
                spy.mockRestore();
            }
            assertNoSecret(stderr.join(''), 'stderr');
        });
    });

    describe('definition', () => {
        it('is a read-only, cacheable read tool with two examples', () => {
            expect(INSPECT_PRIVATE_KEY_TOOL.kind).toBe('read');
            expect(INSPECT_PRIVATE_KEY_TOOL.annotations.readOnlyHint).toBe(true);
            expect(INSPECT_PRIVATE_KEY_TOOL.cacheable).toBe(true);
            expect(INSPECT_PRIVATE_KEY_TOOL.examples?.length).toBe(2);
        });
    });
});
