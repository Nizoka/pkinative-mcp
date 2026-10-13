/**
 * Tests for `create_csr` — every signer form (plain EC / RSA / Ed25519
 * keys, an encrypted key with its public key, a PKCS#12 file), the round
 * trip through inspect_csr, every output mode, the proof-of-possession
 * guard, every error code, and no secret in any result.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { ToolError } from '../src/errors.js';
import { callToolDirect } from '../src/server.js';
import { createCsr, CREATE_CSR_TOOL } from '../src/tools/create-csr.js';
import { inspectCsr } from '../src/tools/inspect-csr.js';
import { artefactBytes, assertResultClean, assertValidDer, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureInput, PASSWORD } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const SPEC = { subject: { C: 'FR', O: 'Acme', CN: 'svc.example.test' }, extensions: { subjectAltName: { dns: ['svc.example.test', '*.svc.example.test'], ip: ['192.0.2.7'] }, keyUsage: ['digitalSignature'], extendedKeyUsage: ['serverAuth', 'clientAuth'] } };

/** Create through the server and read the request back through inspect_csr. */
async function roundTrip(args: Record<string, unknown>): Promise<{ result: Awaited<ReturnType<typeof callToolDirect>>; csr: Awaited<ReturnType<typeof inspectCsr>> }> {
    const result = await callToolDirect('create_csr', args);
    expect(result.isError, JSON.stringify(result._meta)).toBeUndefined();
    assertResultClean(result);
    const bytes = artefactBytes(result);
    assertValidDer(bytes);
    const csr = await inspectCsr({ request: { derBase64: Buffer.from(bytes).toString('base64') } });
    expect(csr.signature).toEqual({ valid: true, reasons: [], signatureVerifications: 1 });
    return { result, csr };
}

describe('create_csr', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_PASSWORD'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('signers', () => {
        it('a plain EC key: the request carries the key, the subject and the requested extensions', async () => {
            const { result, csr } = await roundTrip({ spec: SPEC, signer: { key: fixtureInput('leaf.key.pem') } });
            expect(result.structuredContent).toMatchObject({ mode: 'base64', encoding: 'pem', summary: { subject: 'CN=svc.example.test,O=Acme,C=FR', signatureAlgorithm: { oid: '1.2.840.10045.4.3.2', name: 'ecdsa-with-SHA256' }, extensions: ['keyUsage', 'extendedKeyUsage', 'subjectAltName'], signatureVerified: true, publicKeyFrom: 'signer' } });
            expect(result.structuredContent).not.toHaveProperty('base64');
            expect(csr.subjectString).toBe('CN=svc.example.test,O=Acme,C=FR');
            expect(csr.subjectPublicKeyInfo['curve']).toBe('P-256');
            expect(csr.extensions?.map((e) => e['kind'])).toEqual(['keyUsage', 'extendedKeyUsage', 'subjectAltName']);
            expect((csr.extensions?.[2]?.['names'] as Array<Record<string, unknown>>).map((n) => n['value'] ?? n['address'])).toEqual(['svc.example.test', '*.svc.example.test', '192.0.2.7']);
            expect(csr.attributes.map((a) => a.name)).toEqual(['extensionRequest']);
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('create_csr: request for CN=svc.example.test,O=Acme,C=FR (ecdsa-with-SHA256, 3 extension(s) requested, key from signer)') });
        });

        it('a bare request (no extensions) carries no attribute; subjectKeyIdentifier:true is computed from the key', async () => {
            const bare = await roundTrip({ spec: { subject: { CN: 'bare' } }, signer: { key: fixtureInput('ed25519.key.pem') } });
            expect(bare.csr.extensions).toBeNull();
            expect(bare.csr.attributes).toEqual([]);
            expect(bare.csr.signatureAlgorithm.oid).toBe('1.3.101.112');
            const ski = await roundTrip({ spec: { subject: { CN: 'ski' }, extensions: { subjectKeyIdentifier: true, basicConstraints: { ca: false } } }, signer: { key: fixtureInput('leaf.key.pem') } });
            expect(ski.csr.extensions?.map((e) => e['kind'])).toEqual(['basicConstraints', 'subjectKeyIdentifier']);
            expect(ski.csr.extensions?.[1]?.['keyIdentifier']).toMatch(/^[0-9a-f]{40}$/);
        });

        it('an RSA key needs rsaScheme; pss and pkcs1 both verify', async () => {
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: fixtureInput('rsa.key.pem') } }))).toBe('RSA_SCHEME_REQUIRED');
            const pss = await roundTrip({ spec: SPEC, signer: { key: fixtureInput('rsa.key.pem'), rsaScheme: 'pss' } });
            expect(pss.csr.signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.10');
            expect(pss.csr.subjectPublicKeyInfo['kind']).toBe('rsa');
            const pkcs1 = await roundTrip({ spec: SPEC, signer: { key: fixtureInput('rsa.key.pem'), rsaScheme: 'pkcs1', hash: 'SHA-384' } });
            expect(pkcs1.csr.signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.12');
        });

        it('an encrypted key needs its password and the public key (which also names the key type)', async () => {
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: fixtureInput('leaf.key.enc.pem'), keyType: 'ec-p256' } }))).toBe('SECRET_REQUIRED');
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: fixtureInput('leaf.key.enc.pem'), password: PASSWORD } }))).toBe('KEY_TYPE_REQUIRED');
            const noKey = await callToolDirect('create_csr', { spec: SPEC, signer: { key: fixtureInput('leaf.key.enc.pem'), password: PASSWORD, keyType: 'ec-p256' } });
            expect(errorCodeOf(noKey)).toBe('VALIDATION_ERROR');
            expect(noKey._meta).toMatchObject({ error: { data: { path: 'subjectPublicKey' } } });
            assertResultClean(noKey);
            const spki = await roundTrip({ spec: SPEC, subjectPublicKey: fixtureInput('leaf.pub.pem'), signer: { key: fixtureInput('leaf.key.enc.pem'), password: PASSWORD } });
            expect(spki.result.structuredContent).toMatchObject({ summary: { publicKeyFrom: 'spki' } });
            const fromCsr = await roundTrip({ spec: SPEC, subjectPublicKey: fixtureInput('leaf.csr.pem'), signer: { key: fixtureInput('leaf.key.enc.pem'), password: PASSWORD, keyType: 'ec-p256' } });
            expect(fromCsr.result.structuredContent).toMatchObject({ summary: { publicKeyFrom: 'csr' } });
            const fromCert = await roundTrip({ spec: SPEC, subjectPublicKey: fixtureInput('leaf.crt.der'), signer: { key: fixtureInput('leaf.key.pem') } });
            expect(fromCert.result.structuredContent).toMatchObject({ summary: { publicKeyFrom: 'certificate' } });
            const wrong = await callToolDirect('create_csr', { spec: SPEC, subjectPublicKey: fixtureInput('leaf.pub.pem'), signer: { key: fixtureInput('leaf.key.enc.pem'), password: 'not-it' } });
            expect(errorCodeOf(wrong)).toBe('PKI_CRYPTO_DECRYPTION_FAILED');
            assertResultClean(wrong);
        });

        it('a PKCS#12 file: the key and its certificate\'s public key', async () => {
            expect(await codeOf(createCsr({ spec: SPEC, signer: { p12: fixtureInput('leaf.p12') } }))).toBe('SECRET_REQUIRED');
            const { result, csr } = await roundTrip({ spec: SPEC, signer: { p12: fixtureInput('leaf.p12'), password: PASSWORD } });
            expect(result.structuredContent).toMatchObject({ summary: { publicKeyFrom: 'pkcs12', signatureAlgorithm: { name: 'ecdsa-with-SHA256' } } });
            expect(csr.subjectPublicKeyInfo['curve']).toBe('P-256');
            const legacy = await callToolDirect('create_csr', { spec: SPEC, signer: { p12: fixtureInput('legacy.p12'), password: PASSWORD } });
            expect(errorCodeOf(legacy)).toBe('PKI_KEY_ENCRYPTION_UNSUPPORTED');
            assertResultClean(legacy);
        });

        it('KEY_MISMATCH when the signing key is not the public key named (proof of possession)', async () => {
            const result = await callToolDirect('create_csr', { spec: SPEC, subjectPublicKey: fixtureInput('ed25519.crt.pem'), signer: { key: fixtureInput('leaf.key.pem') } });
            expect(errorCodeOf(result)).toBe('KEY_MISMATCH');
            expect(result._meta).toMatchObject({ error: { data: { remedy: 'signer', reasons: ['PKI_REASON_SIGNATURE_INVALID'] } } });
            assertResultClean(result);
        });

        it('SHA-1 is produced only under allowSha1, and the proof of possession still verifies', async () => {
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: fixtureInput('leaf.key.pem'), hash: 'SHA-1' } }))).toBe('VALIDATION_ERROR');
            const r = await createCsr({ spec: SPEC, signer: { key: fixtureInput('leaf.key.pem'), hash: 'SHA-1' }, allowSha1: true });
            expect(r.summary.signatureAlgorithm.oid).toBe('1.2.840.10045.4.1');
            const back = await inspectCsr({ request: { derBase64: Buffer.from(artefactBytes(await callToolDirect('create_csr', { spec: SPEC, signer: { key: fixtureInput('leaf.key.pem'), hash: 'SHA-1' }, allowSha1: true }))).toString('base64') } });
            expect(back.signature?.reasons.map((x) => x['code'])).toEqual(['PKI_REASON_SIGNATURE_NOT_CHECKED']);
        });
    });

    describe('output modes', () => {
        it('der and hex inline; a sandbox file (.csr) written once, never overwritten', async () => {
            const der = await callToolDirect('create_csr', { spec: SPEC, signer: { key: fixtureInput('leaf.key.pem') }, encoding: 'der' });
            expect(der.structuredContent).toMatchObject({ encoding: 'der', mode: 'base64' });
            assertValidDer(artefactBytes(der));
            const hex = await callToolDirect('create_csr', { spec: SPEC, signer: { key: fixtureInput('leaf.key.pem') }, encoding: 'hex' });
            expect((hex.structuredContent as { hex: string }).hex).toMatch(/^30[0-9a-f]+$/);
            assertResultClean(hex);
            sandbox = await makeSandbox();
            const file = await callToolDirect('create_csr', { spec: SPEC, signer: { key: fixtureInput('leaf.key.pem') }, encoding: 'der', outputMode: 'file', outputPath: 'req/svc.csr' });
            expect(file.isError).toBeUndefined();
            expect(file.content.some((c) => c.type === 'resource_link')).toBe(true);
            const written = await fs.readFile(path.join(sandbox, 'req', 'svc.csr'));
            assertValidDer(new Uint8Array(written));
            expect((await inspectCsr({ request: { path: 'req/svc.csr' } })).subjectString).toBe('CN=svc.example.test,O=Acme,C=FR');
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: fixtureInput('leaf.key.pem') }, encoding: 'der', outputMode: 'file', outputPath: 'req/svc.csr' }))).toBe('OUTPUT_EXISTS');
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: fixtureInput('leaf.key.pem') }, encoding: 'der', outputMode: 'file', outputPath: 'req/svc.key' }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: fixtureInput('leaf.key.pem') }, outputMode: 'file', outputPath: 'req/svc.csr' }))).toBe('INVALID_EXTENSION');
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: fixtureInput('leaf.key.pem') }, outputMode: 'file' }))).toBe('MISSING_OUTPUT_PATH');
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: fixtureInput('leaf.key.pem') }, encoding: 'hex', outputMode: 'file', outputPath: 'req/x.csr' }))).toBe('VALIDATION_ERROR');
            await fs.copyFile(fixture('leaf.key.pem'), path.join(sandbox, 'leaf.key.pem'));
            expect((await createCsr({ spec: SPEC, signer: { key: { path: 'leaf.key.pem' } } })).summary.publicKeyFrom).toBe('signer');
        });

        it('refuses a key path when the sandbox is unset', async () => {
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: { path: 'leaf.key.pem' } } }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('spec refusals (VALIDATION_ERROR naming the path)', () => {
        it.each([
            [{ extensions: {} }, 'spec.subject'],
            [{ subject: { CN: 'x' }, notBefore: 1 }, 'spec notBefore: unknown member'],
            [{ subject: { CN: 'x' }, extensions: { authorityKeyIdentifier: true } }, 'spec extensions.authorityKeyIdentifier: is written by the issuer'],
            [{ subject: { CN: 'x' }, extensions: { issuerAltName: { dns: ['a'] } } }, 'spec extensions.issuerAltName: is written by the issuer'],
            [{ subject: { CN: 'x' }, extensions: { frob: 1 } }, 'spec extensions.frob: unknown extension'],
            [{ subject: { CN: 'x' }, extensions: [] }, 'spec extensions: expected an object'],
            [{ subject: { CN: 'x' }, extensions: { keyUsage: ['frob'] } }, 'unknown key usage'],
            [{ subject: { CN: 'x' }, extensions: { subjectAltName: { ip: ['999.1.1.1'] } } }, 'not an IPv4 or IPv6 address'],
            [{ subject: {} }, 'at least one RDN'],
            [{ subject: { FROB: 'x' } }, 'unknown attribute type'],
        ])('%j', async (spec, message) => {
            try {
                await createCsr({ spec, signer: { key: fixtureInput('leaf.key.pem') } });
                expect.unreachable();
            } catch (e) {
                expect(e).toBeInstanceOf(ToolError);
                expect((e as ToolError).code).toBe('VALIDATION_ERROR');
                expect((e as ToolError).message).toContain(message);
            }
        });

        it('VALIDATION_ERROR: no signer, both signer forms, rsaScheme on an EC key, an unknown key, nothing', async () => {
            expect(await codeOf(createCsr({ spec: SPEC }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: fixtureInput('leaf.key.pem'), p12: fixtureInput('leaf.p12') } }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: fixtureInput('leaf.key.pem'), rsaScheme: 'pss' } }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: fixtureInput('leaf.key.pem') }, bogus: 1 }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(createCsr({}))).toBe('VALIDATION_ERROR');
        });

        it('a certificate given as the signing key is PKI_PEM_UNEXPECTED_LABEL; a public key as subjectPublicKey must be one', async () => {
            expect(await codeOf(createCsr({ spec: SPEC, signer: { key: fixtureInput('leaf.crt.pem') } }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            const result = await callToolDirect('create_csr', { spec: SPEC, subjectPublicKey: fixtureInput('leaf.key.pem'), signer: { key: fixtureInput('leaf.key.pem') } });
            expect(errorCodeOf(result)).toBe('PKI_PEM_UNEXPECTED_LABEL');
            assertResultClean(result);
        });
    });

    describe('definition', () => {
        it('produces a non-idempotent artefact, never cached, with two validating examples', () => {
            expect(CREATE_CSR_TOOL.kind).toBe('artefact');
            expect(CREATE_CSR_TOOL.annotations).toEqual({ readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false });
            expect(CREATE_CSR_TOOL.cacheable).toBe(false);
            expect(CREATE_CSR_TOOL.examples?.length).toBe(2);
        });
    });
});
