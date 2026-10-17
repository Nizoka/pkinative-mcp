/**
 * Tests for `create_certificate` — self-signed CAs, issued leaves, every key
 * family and signer form, the post-signature self-check, determinism, output
 * modes, every error code, and no secret in any result.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { parseCertificate, verifyCertificateSignature, verifySelfSignature } from 'pkinative';

import { callToolDirect } from '../src/server.js';
import { createCertificateTool, CREATE_CERTIFICATE_TOOL } from '../src/tools/create-certificate.js';
import { inspectCertificate } from '../src/tools/inspect-certificate.js';
import { verifyCertificateChainTool } from '../src/tools/verify-certificate-chain.js';
import { artefactBytes, assertResultClean, assertValidDer, codeOf, errorCodeOf } from './_pki-assert.js';
import { AT, fixture, fixtureInput, fixtureText, PASSWORD } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const CA_SPEC = { serialNumber: 1, subject: { C: 'FR', O: 'Acme', CN: 'Acme Test CA' }, notBefore: AT, validityDays: 3650, extensions: { basicConstraints: { ca: true, pathLen: 0 }, keyUsage: ['keyCertSign', 'cRLSign'] } };
const ED = { key: fixtureInput('ed25519.key.pem') };

describe('create_certificate', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_AT'];
        delete process.env['PKINATIVE_MCP_PASSWORD'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
        delete process.env['PKINATIVE_MCP_AT'];
    });

    describe('self-signed', () => {
        it('issues a CA from a plain Ed25519 key: deterministic bytes, SKI added, verified', async () => {
            const a = await createCertificateTool({ spec: CA_SPEC, signer: ED, encoding: 'der' });
            const b = await createCertificateTool({ spec: CA_SPEC, signer: ED, encoding: 'der' });
            expect(a.sha256).toBe(b.sha256);
            expect(a.summary).toMatchObject({ serialNumber: '01', randomSerial: false, subject: 'CN=Acme Test CA,O=Acme,C=FR', issuer: 'CN=Acme Test CA,O=Acme,C=FR', selfSigned: true, notBefore: '2027-01-01T00:00:00.000Z', notBeforeSource: 'input', extensions: ['basicConstraints', 'keyUsage', 'subjectKeyIdentifier'], signatureVerified: true, publicKeyFrom: 'signer' });
            expect(a.summary.signatureAlgorithm.name).toBe('Ed25519');
            const der = new Uint8Array(Buffer.from(a.base64 ?? '', 'base64'));
            assertValidDer(der);
            const cert = parseCertificate(der);
            expect(await verifySelfSignature(cert)).toBe(true);
            expect(cert.validity.notAfter.epochMilliseconds - cert.validity.notBefore.epochMilliseconds).toBe(3650 * 86_400_000);
        });

        it.each([
            ['leaf.key.pem', {}, 'ecdsa-with-SHA256'],
            ['rsa.key.pem', { rsaScheme: 'pss' }, 'RSASSA-PSS'],
            ['rsa.key.pem', { rsaScheme: 'pkcs1', hash: 'SHA-384' }, 'sha384WithRSAEncryption'],
        ] as const)('signs with %s %j', async (name, extra, algorithmName) => {
            const r = await createCertificateTool({ spec: { subject: { CN: 'k' }, notBefore: AT }, signer: { key: fixtureInput(name), ...extra } });
            expect(r.summary.signatureVerified).toBe(true);
            expect(r.summary.signatureAlgorithm.name).toBe(algorithmName);
            expect(r.encoding).toBe('pem');
            expect(Buffer.from(r.base64 ?? '', 'base64').toString('utf8')).toMatch(/^-----BEGIN CERTIFICATE-----/);
        });

        it('uses a random 127-bit serial and the clock (or the pin) when the spec omits them', async () => {
            const r = await createCertificateTool({ spec: { subject: { CN: 'r' } }, signer: ED });
            expect(r.summary.randomSerial).toBe(true);
            expect(r.summary.serialNumber).toMatch(/^[0-7][0-9a-f]{31}$/);
            expect(r.summary.notBeforeSource).toBe('clock');
            process.env['PKINATIVE_MCP_AT'] = '2028-06-01T12:00:00Z';
            const pinned = await createCertificateTool({ spec: { subject: { CN: 'r' } }, signer: ED });
            expect(pinned.summary).toMatchObject({ notBefore: '2028-06-01T12:00:00.000Z', notBeforeSource: 'pinned' });
        });
    });

    describe('issued', () => {
        it('issues a leaf from a CSR under a CA, with AKI from the issuer SKI, and the chain verifies', async () => {
            const ca = await createCertificateTool({ spec: CA_SPEC, signer: ED });
            const caPem = Buffer.from(ca.base64 ?? '', 'base64').toString('utf8');
            const leaf = await createCertificateTool({
                spec: { serialNumber: '0x1234', subject: { CN: 'svc.example.test' }, notBefore: AT, validityDays: 90, extensions: { subjectAltName: { dns: ['svc.example.test'], ip: ['192.0.2.9'] }, extendedKeyUsage: ['serverAuth'], keyUsage: ['digitalSignature'] } },
                issuerCertificate: { pem: caPem },
                subjectPublicKey: fixtureInput('leaf.csr.pem'),
                signer: ED,
            });
            expect(leaf.summary).toMatchObject({ serialNumber: '1234', selfSigned: false, issuer: 'CN=Acme Test CA,O=Acme,C=FR', signatureVerified: true, publicKeyFrom: 'csr', extensions: ['keyUsage', 'extendedKeyUsage', 'subjectAltName', 'subjectKeyIdentifier', 'authorityKeyIdentifier'] });
            const leafPem = Buffer.from(leaf.base64 ?? '', 'base64').toString('utf8');
            const inspected = await inspectCertificate({ certificate: { pem: leafPem }, issuer: { pem: caPem }, extension: 'authorityKeyIdentifier' });
            expect(inspected.signature?.valid).toBe(true);
            const caSki = (await inspectCertificate({ certificate: { pem: caPem }, extension: 'subjectKeyIdentifier' })).extension?.['keyIdentifier'];
            expect(inspected.extension?.['keyIdentifier']).toBe(caSki);
            const verdict = await verifyCertificateChainTool({ leaf: { pem: leafPem }, trustAnchors: [{ pem: caPem }], at: AT, serverName: { host: 'svc.example.test' }, purposes: ['serverAuth'] });
            expect(verdict.valid).toBe(true);
        });

        it('takes the subject key from a certificate or a PUBLIC KEY, and the signer from a PKCS#12', async () => {
            const fromCert = await createCertificateTool({ spec: { subject: { CN: 'c' }, notBefore: AT }, issuerCertificate: fixtureInput('leaf.crt.pem'), subjectPublicKey: fixtureInput('rsa.crt.pem'), signer: { p12: fixtureInput('leaf.p12'), password: PASSWORD } });
            expect(fromCert.summary).toMatchObject({ publicKeyFrom: 'certificate', signatureVerified: true });
            const fromSpki = await createCertificateTool({ spec: { subject: { CN: 'p' }, notBefore: AT }, issuerCertificate: fixtureInput('leaf.crt.pem'), subjectPublicKey: fixtureInput('leaf.pub.pem'), signer: { key: fixtureInput('leaf.key.pem') } });
            expect(fromSpki.summary).toMatchObject({ publicKeyFrom: 'spki', signatureVerified: true });
            const cert = parseCertificate(new Uint8Array(Buffer.from(Buffer.from(fromSpki.base64 ?? '', 'base64').toString('utf8').replace(/-----[^-]+-----/g, ''), 'base64')));
            expect(await verifyCertificateSignature(cert, parseCertificate(new Uint8Array(Buffer.from(fixtureText('leaf.crt.pem').replace(/-----[^-]+-----/g, ''), 'base64'))))).toBe(true);
        });

        it('an encrypted signing key takes its type from the issuer certificate (no keyType needed)', async () => {
            const r = await createCertificateTool({ spec: { subject: { CN: 'e' }, notBefore: AT }, issuerCertificate: fixtureInput('leaf.crt.pem'), subjectPublicKey: fixtureInput('leaf.pub.pem'), signer: { key: fixtureInput('leaf.key.enc.pem'), password: PASSWORD } });
            expect(r.summary.signatureVerified).toBe(true);
        });

        it('KEY_MISMATCH when the signing key is not the issuer key', async () => {
            expect(await codeOf(createCertificateTool({ spec: { subject: { CN: 'm' }, notBefore: AT }, issuerCertificate: fixtureInput('inter.crt.pem'), subjectPublicKey: fixtureInput('leaf.pub.pem'), signer: { key: fixtureInput('leaf.key.pem') } }))).toBe('KEY_MISMATCH');
        });
    });

    describe('output modes', () => {
        it('writes a PEM or DER file into the sandbox once, with a resource_link', async () => {
            sandbox = await makeSandbox();
            const r = await callToolDirect('create_certificate', { spec: CA_SPEC, signer: ED, outputMode: 'file', outputPath: 'out/ca.crt.pem' });
            expect(r.isError).toBeUndefined();
            expect(r.content.some((c) => c.type === 'resource_link' && (c as { uri: string }).uri === 'pkinative://output/out/ca.crt.pem')).toBe(true);
            expect(await fs.readFile(path.join(sandbox, 'out', 'ca.crt.pem'), 'utf8')).toMatch(/^-----BEGIN CERTIFICATE-----/);
            expect(errorCodeOf(await callToolDirect('create_certificate', { spec: CA_SPEC, signer: ED, outputMode: 'file', outputPath: 'out/ca.crt.pem' }))).toBe('OUTPUT_EXISTS');
            expect(errorCodeOf(await callToolDirect('create_certificate', { spec: CA_SPEC, signer: ED, outputMode: 'file', outputPath: 'out/ca.der', encoding: 'pem' }))).toBe('INVALID_EXTENSION');
            expect(errorCodeOf(await callToolDirect('create_certificate', { spec: CA_SPEC, signer: ED, outputMode: 'file', outputPath: 'out/ca.key', encoding: 'der' }))).toBe('SECURITY_VIOLATION');
            expect(errorCodeOf(await callToolDirect('create_certificate', { spec: CA_SPEC, signer: ED, outputMode: 'file' }))).toBe('MISSING_OUTPUT_PATH');
            const der = await callToolDirect('create_certificate', { spec: CA_SPEC, signer: { key: { path: 'keys/ed.key' } }, outputMode: 'file', outputPath: 'out/ca.cer', encoding: 'der' });
            expect(errorCodeOf(der)).toBe('INPUT_NOT_FOUND');
            await fs.mkdir(path.join(sandbox, 'keys'));
            await fs.copyFile(fixture('ed25519.key.pem'), path.join(sandbox, 'keys', 'ed.key'));
            const ok = await callToolDirect('create_certificate', { spec: CA_SPEC, signer: { key: { path: 'keys/ed.key' } }, outputMode: 'file', outputPath: 'out/ca.cer', encoding: 'der' });
            expect(ok.isError).toBeUndefined();
            assertValidDer(new Uint8Array(await fs.readFile(path.join(sandbox, 'out', 'ca.cer'))));
        });

        it('delivers the bytes once as an embedded resource (PEM as text, DER as blob, hex inline) and never in structuredContent', async () => {
            const pem = await callToolDirect('create_certificate', { spec: CA_SPEC, signer: ED });
            const block = pem.content.find((c) => c.type === 'resource') as { resource: { mimeType: string; text?: string; blob?: string } };
            expect(block.resource.mimeType).toBe('application/x-pem-file');
            expect(block.resource.text).toMatch(/^-----BEGIN CERTIFICATE-----/);
            expect(JSON.stringify(pem.structuredContent)).not.toContain('BEGIN CERTIFICATE');
            expect(pem.structuredContent).toMatchObject({ mode: 'base64', encoding: 'pem', sha256: expect.stringMatching(/^[0-9a-f]{64}$/), summary: { selfSigned: true } });
            const der = await callToolDirect('create_certificate', { spec: CA_SPEC, signer: ED, encoding: 'der' });
            assertValidDer(artefactBytes(der));
            expect((der.content.find((c) => c.type === 'resource') as { resource: { mimeType: string } }).resource.mimeType).toBe('application/pkix-cert');
            const hex = await callToolDirect('create_certificate', { spec: CA_SPEC, signer: ED, encoding: 'hex' });
            expect(hex.content.some((c) => c.type === 'resource')).toBe(false);
            expect((hex.structuredContent as { hex: string }).hex).toMatch(/^30[0-9a-f]+$/);
        });
    });

    describe('refusals', () => {
        it('RSA_SCHEME_REQUIRED, SECRET_REQUIRED, KEY_TYPE_REQUIRED, wrong password, legacy PKCS#12', async () => {
            expect(await codeOf(createCertificateTool({ spec: { subject: { CN: 'x' } }, signer: { key: fixtureInput('rsa.key.pem') } }))).toBe('RSA_SCHEME_REQUIRED');
            expect(await codeOf(createCertificateTool({ spec: { subject: { CN: 'x' } }, signer: { key: fixtureInput('leaf.key.enc.pem') } }))).toBe('SECRET_REQUIRED');
            expect(await codeOf(createCertificateTool({ spec: { subject: { CN: 'x' } }, signer: { key: fixtureInput('leaf.key.enc.pem'), password: PASSWORD } }))).toBe('KEY_TYPE_REQUIRED');
            expect(await codeOf(createCertificateTool({ spec: { subject: { CN: 'x' } }, signer: { key: fixtureInput('leaf.key.enc.pem'), password: PASSWORD, keyType: 'ec-p256' } }))).toBe('VALIDATION_ERROR'); // encrypted key: no public key to derive
            expect(await codeOf(createCertificateTool({ spec: { subject: { CN: 'x' } }, signer: { p12: fixtureInput('leaf.p12'), password: 'definitely-wrong' } }))).toBe('PKI_CRYPTO_DECRYPTION_FAILED');
            expect(await codeOf(createCertificateTool({ spec: { subject: { CN: 'x' } }, signer: { p12: fixtureInput('legacy.p12'), password: PASSWORD } }))).toBe('PKI_KEY_ENCRYPTION_UNSUPPORTED');
            expect(await codeOf(createCertificateTool({ spec: { subject: { CN: 'x' } }, signer: { key: fixtureInput('leaf.key.pem'), hash: 'SHA-1' } }))).toBe('VALIDATION_ERROR');
        });

        it('spec defects are VALIDATION_ERROR naming the path', async () => {
            const cases: Array<[Record<string, unknown>, string]> = [
                [{ subject: { CN: 'x' }, bogus: 1 }, 'bogus'],
                [{ subject: { CN: 'x' }, notBefore: '2027-02-31' }, 'notBefore'],
                [{ subject: { CN: 'x' }, notBefore: AT, notAfter: '2026-01-01T00:00:00Z' }, 'notAfter'],
                [{ subject: { CN: 'x' }, validityDays: 0 }, 'validityDays'],
                [{ subject: { CN: 'x' }, serialNumber: 0 }, 'serialNumber'],
                [{ subject: { CN: 'x' }, extensions: { nope: true } }, 'extensions.nope'],
                [{ subject: { CN: 'x' }, extensions: { keyUsage: ['fly'] } }, 'keyUsage'],
                [{ subject: { CN: 'x' }, extensions: { subjectAltName: { ip: ['999.1.1.1'] } } }, 'ip'],
                [{ subject: { QQ: 'x' } }, 'QQ'],
                [{ subject: { CN: 'x' }, issuer: { CN: 'i' } }, 'spec.issuer'],
            ];
            for (const [spec, needle] of cases) {
                const input: Record<string, unknown> = { spec, signer: ED };
                if (needle === 'spec.issuer') input['issuerCertificate'] = fixtureInput('leaf.crt.pem');
                const r = await callToolDirect('create_certificate', input);
                expect(errorCodeOf(r), JSON.stringify(spec)).toBe('VALIDATION_ERROR');
                expect((r.content[0] as { text: string }).text, JSON.stringify(spec)).toContain(needle);
            }
            expect(await codeOf(createCertificateTool({ spec: { subject: { CN: 'x' } }, issuerCertificate: fixtureInput('leaf.crt.pem'), signer: ED }))).toBe('VALIDATION_ERROR'); // subjectPublicKey required
            expect(await codeOf(createCertificateTool({ spec: 'nope', signer: ED }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(createCertificateTool({ spec: { subject: { CN: 'x' } } }))).toBe('VALIDATION_ERROR');
        });

        it('no result or error ever carries a key byte or the password', async () => {
            for (const input of [
                { spec: CA_SPEC, signer: { p12: fixtureInput('leaf.p12'), password: PASSWORD } },
                { spec: CA_SPEC, signer: { p12: fixtureInput('leaf.p12'), password: 'definitely-wrong' } },
                { spec: CA_SPEC, signer: { key: fixtureInput('leaf.key.enc.pem'), password: PASSWORD, keyType: 'ec-p256' } },
                { spec: CA_SPEC, signer: { key: fixtureInput('leaf.key.pem'), password: PASSWORD, bogus: true } },
                { spec: CA_SPEC, signer: { key: fixtureInput('rsa.key.pem') } },
            ]) {
                assertResultClean(await callToolDirect('create_certificate', input));
            }
        });
    });

    it('is a PRODUCES tool that is never cached (signer) and declares its instant input', () => {
        expect(CREATE_CERTIFICATE_TOOL.kind).toBe('artefact');
        expect(CREATE_CERTIFICATE_TOOL.annotations.idempotentHint).toBe(false);
        expect(CREATE_CERTIFICATE_TOOL.cacheable).toBe(false);
        expect(CREATE_CERTIFICATE_TOOL.instantInputs).toEqual(['spec.notBefore']);
        expect(CREATE_CERTIFICATE_TOOL.examples?.length).toBe(2);
    });
});
