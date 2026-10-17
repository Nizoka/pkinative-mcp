/**
 * Tests for `encode_x509_structure` — every structure against the bytes
 * the CLI pins, the signer form, every output encoding and mode, every
 * spec refusal naming its path, every error code, no secret.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { ToolError } from '../src/errors.js';
import { callToolDirect } from '../src/server.js';
import { encodeX509Structure, ENCODE_X509_STRUCTURE_TOOL, X509_STRUCTURES } from '../src/tools/encode-x509-structure.js';
import { inspectCertificate } from '../src/tools/inspect-certificate.js';
import { artefactBytes, assertResultClean, assertValidDer, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureInput, PASSWORD } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const hexOf = async (structure: string, spec: unknown): Promise<string> => (await encodeX509Structure({ structure, spec })).hex ?? '';

describe('encode_x509_structure', () => {
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

    describe('every building block (the bytes pkinative-cli pins)', () => {
        it.each([
            ['name', { CN: 'x' }, '300c310a300806035504030c0178'],
            ['name', [[{ type: 'CN', value: 'x', stringType: 'utf8' }]], '300c310a300806035504030c0178'],
            ['name-attribute', { type: 'C', value: 'FR' }, '3009060355040613024652'],
            ['validity', { notBefore: '2026-01-01T00:00:00Z', notAfter: '2027-01-01T00:00:00Z' }, '301e170d3236303130313030303030305a170d3237303130313030303030305a'],
            ['validity', { notBefore: 1767225600000, notAfter: '2027-01-01T00:00:00.500Z' }, '301e170d3236303130313030303030305a170d3237303130313030303030305a'],
            ['algorithm-identifier', { oid: '1.2.840.113549.1.1.11', parameters: '0500' }, '300d06092a864886f70d01010b0500'],
            ['algorithm-identifier', { oid: '1.3.101.112' }, '300506032b6570'],
            ['attribute', { oid: '1.2.840.113549.1.9.14', values: ['3000'] }, '300f06092a864886f70d01090e31023000'],
            ['extension', { oid: '2.5.29.19', critical: true, value: '3000' }, '300c0603551d130101ff04023000'],
            ['extension', { oid: '2.5.29.19', value: '30:00' }, '30090603551d1304023000'],
            ['basic-constraints', { ca: true, pathLen: 0 }, '30060101ff020100'],
            ['basic-constraints', { ca: false }, '3000'],
            ['key-usage', ['digitalSignature'], '03020780'],
            ['key-usage', { usages: ['digitalSignature'] }, '03020780'],
            ['extended-key-usage', ['serverAuth'], '300a06082b06010505070301'],
            ['extended-key-usage', { purposes: ['1.3.6.1.5.5.7.3.1'] }, '300a06082b06010505070301'],
            ['subject-alt-name', { dns: ['a.test'] }, '30088206612e74657374'],
            ['subject-key-identifier', { keyId: 'a1b2' }, '0402a1b2'],
            ['authority-key-identifier', { keyId: '0xA1:B2' }, '30048002a1b2'],
        ])('%s %j', async (structure, spec, expected) => {
            const r = await encodeX509Structure({ structure, spec });
            expect(r.hex).toBe(expected);
            expect(r.mode).toBe('base64');
            expect(r.encoding).toBe('hex');
            expect(r.summary).toEqual({ structure, sizeBytes: expected.length / 2 });
            expect(r.sizeBytes).toBe(expected.length / 2);
            expect(r.base64).toBeUndefined();
            expect(r.diagnostics).toEqual([]);
        });

        it('spki, extensions and a SAN with every name kind encode', async () => {
            expect(await hexOf('spki', { algorithm: '1.3.101.112', publicKey: '00'.repeat(32) })).toMatch(/^302a300506032b6570032100/);
            expect(await hexOf('spki', { algorithm: '1.2.840.10045.2.1', parameters: '06082a8648ce3d030107', publicKey: '04' })).toMatch(/^30/);
            const exts = await encodeX509Structure({ structure: 'extensions', spec: { basicConstraints: { ca: true }, keyUsage: { usages: ['keyCertSign'], critical: true }, subjectAltName: { dns: ['a.test'], critical: true }, subjectKeyIdentifier: 'a1b2', authorityKeyIdentifier: false, raw: [{ oid: '1.2.3', value: '0500' }] } });
            expect(exts.hex).toMatch(/^30/);
            expect(exts.hex).toContain('0603551d130101ff');
            const san = await hexOf('subject-alt-name', { dns: ['a.test'], email: ['a@b.test'], uri: ['https://a.test'], ip: ['192.0.2.1', '2001:db8::1'], registeredId: ['1.2.3'], directoryName: [{ CN: 'x' }] });
            expect(san).toContain('8704c0000201');
            expect(san).toContain('8710');
        });

        it('computes a subject key identifier from a certificate, a CSR or a public key, and an AKI from the issuer', async () => {
            const leaf = await inspectCertificate({ certificate: fixtureInput('leaf.crt.pem'), extension: 'subjectKeyIdentifier' });
            const ski = leaf.extension?.['keyIdentifier'] as string;
            expect(await hexOf('subject-key-identifier', { publicKey: fixtureInput('leaf.crt.pem') })).toBe(`0414${ski}`);
            expect(await hexOf('subject-key-identifier', { publicKey: fixtureInput('leaf.pub.pem') })).toBe(`0414${ski}`);
            expect(await hexOf('subject-key-identifier', { publicKey: fixtureInput('leaf.csr.der') })).toMatch(/^0414[0-9a-f]{40}$/);
            const inter = await inspectCertificate({ certificate: fixtureInput('inter.crt.pem'), extension: 'subjectKeyIdentifier' });
            expect(await hexOf('authority-key-identifier', { issuerCertificate: fixtureInput('inter.crt.pem') })).toBe(`30168014${inter.extension?.['keyIdentifier'] as string}`);
            // A certificate without a subjectKeyIdentifier falls back to the SHA-1 of its key bits (same rule, same bytes for the leaf).
            expect(await hexOf('authority-key-identifier', { issuerCertificate: fixtureInput('leaf.crt.der') })).toBe(`30168014${ski}`);
        });
    });

    describe('signature-algorithm (the key decides)', () => {
        it('encodes the identifier of every key type and never echoes the key', async () => {
            expect((await encodeX509Structure({ structure: 'signature-algorithm', signer: { key: fixtureInput('ed25519.key.pem') } })).hex).toBe('300506032b6570');
            expect((await encodeX509Structure({ structure: 'signature-algorithm', signer: { key: fixtureInput('leaf.key.pem') } })).hex).toBe('300a06082a8648ce3d040302');
            expect((await encodeX509Structure({ structure: 'signature-algorithm', signer: { key: fixtureInput('leaf.key.pem'), hash: 'SHA-384' } })).hex).toBe('300a06082a8648ce3d040303');
            expect((await encodeX509Structure({ structure: 'signature-algorithm', signer: { key: fixtureInput('rsa.key.pem'), rsaScheme: 'pkcs1' } })).hex).toBe('300d06092a864886f70d01010b0500');
            const pss = await callToolDirect('encode_x509_structure', { structure: 'signature-algorithm', signer: { key: fixtureInput('rsa.key.pem'), rsaScheme: 'pss', saltLength: 32 } });
            expect(pss.isError).toBeUndefined();
            expect((pss.structuredContent as { hex: string }).hex).toMatch(/^30.*06092a864886f70d01010a30/);
            assertResultClean(pss);
            const enc = await callToolDirect('encode_x509_structure', { structure: 'signature-algorithm', signer: { key: fixtureInput('leaf.key.enc.pem'), password: PASSWORD, keyType: 'ec-p256' } });
            expect((enc.structuredContent as { hex: string }).hex).toBe('300a06082a8648ce3d040302');
            assertResultClean(enc);
            const p12 = await callToolDirect('encode_x509_structure', { structure: 'signature-algorithm', signer: { p12: fixtureInput('leaf.p12'), password: PASSWORD } });
            expect((p12.structuredContent as { hex: string }).hex).toBe('300a06082a8648ce3d040302');
            assertResultClean(p12);
        });

        it('RSA_SCHEME_REQUIRED, SECRET_REQUIRED, KEY_TYPE_REQUIRED, SHA-1 without allowSha1', async () => {
            expect(await codeOf(encodeX509Structure({ structure: 'signature-algorithm', signer: { key: fixtureInput('rsa.key.pem') } }))).toBe('RSA_SCHEME_REQUIRED');
            expect(await codeOf(encodeX509Structure({ structure: 'signature-algorithm', signer: { key: fixtureInput('leaf.key.enc.pem'), keyType: 'ec-p256' } }))).toBe('SECRET_REQUIRED');
            expect(await codeOf(encodeX509Structure({ structure: 'signature-algorithm', signer: { key: fixtureInput('leaf.key.enc.pem'), password: PASSWORD } }))).toBe('KEY_TYPE_REQUIRED');
            expect(await codeOf(encodeX509Structure({ structure: 'signature-algorithm', signer: { p12: fixtureInput('leaf.p12') } }))).toBe('SECRET_REQUIRED');
            expect(await codeOf(encodeX509Structure({ structure: 'signature-algorithm', signer: { key: fixtureInput('leaf.key.pem'), hash: 'SHA-1' } }))).toBe('VALIDATION_ERROR');
            expect((await encodeX509Structure({ structure: 'signature-algorithm', signer: { key: fixtureInput('leaf.key.pem'), hash: 'SHA-1' }, allowSha1: true })).hex).toBe('300906072a8648ce3d0401');
            const wrong = await callToolDirect('encode_x509_structure', { structure: 'signature-algorithm', signer: { key: fixtureInput('leaf.key.enc.pem'), password: 'not-it', keyType: 'ec-p256' } });
            expect(errorCodeOf(wrong)).toBe('PKI_CRYPTO_DECRYPTION_FAILED');
            assertResultClean(wrong);
        });
    });

    describe('output encodings and modes', () => {
        it('der and pem (with a label) are delivered once as an embedded resource', async () => {
            const der = await callToolDirect('encode_x509_structure', { structure: 'basic-constraints', spec: { ca: true }, encoding: 'der' });
            expect(der.isError).toBeUndefined();
            const bytes = artefactBytes(der);
            assertValidDer(bytes);
            expect(Buffer.from(bytes).toString('hex')).toBe('30030101ff');
            expect(der.structuredContent).toMatchObject({ encoding: 'der', sizeBytes: 5, summary: { structure: 'basic-constraints' } });
            expect(der.structuredContent).not.toHaveProperty('base64');
            const pem = await callToolDirect('encode_x509_structure', { structure: 'basic-constraints', spec: { ca: true }, encoding: 'pem', label: 'X509 BASIC CONSTRAINTS' });
            const block = pem.content.find((c) => c.type === 'resource') as { resource: { text: string } };
            expect(block.resource.text).toMatch(/^-----BEGIN X509 BASIC CONSTRAINTS-----\n/);
            expect(Buffer.from(artefactBytes(pem)).toString('hex')).toBe('30030101ff');
        });

        it('writes a sandbox file once (never overwritten) and refuses the wrong extension', async () => {
            sandbox = await makeSandbox();
            const r = await callToolDirect('encode_x509_structure', { structure: 'key-usage', spec: ['cRLSign'], encoding: 'der', outputMode: 'file', outputPath: 'out/ku.der' });
            expect(r.isError).toBeUndefined();
            expect(r.content.some((c) => c.type === 'resource_link')).toBe(true);
            const written = await fs.readFile(path.join(sandbox, 'out', 'ku.der'));
            expect(written.toString('hex')).toBe('03020102');
            expect(await codeOf(encodeX509Structure({ structure: 'key-usage', spec: ['cRLSign'], encoding: 'der', outputMode: 'file', outputPath: 'out/ku.der' }))).toBe('OUTPUT_EXISTS');
            expect(await codeOf(encodeX509Structure({ structure: 'key-usage', spec: ['cRLSign'], encoding: 'der', outputMode: 'file', outputPath: 'out/ku.crt' }))).toBe('INVALID_EXTENSION');
            expect(await codeOf(encodeX509Structure({ structure: 'key-usage', spec: ['cRLSign'], encoding: 'pem', label: 'KU', outputMode: 'file', outputPath: 'out/ku.der' }))).toBe('INVALID_EXTENSION');
            expect(await codeOf(encodeX509Structure({ structure: 'key-usage', spec: ['cRLSign'], encoding: 'der', outputMode: 'file' }))).toBe('MISSING_OUTPUT_PATH');
            expect(await codeOf(encodeX509Structure({ structure: 'key-usage', spec: ['cRLSign'], outputMode: 'file', outputPath: 'out/ku.bin' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(encodeX509Structure({ structure: 'key-usage', spec: ['cRLSign'], encoding: 'der', outputMode: 'file', outputPath: '../ku.der' }))).toBe('SECURITY_VIOLATION');
        });

        it('reads a spec input from the sandbox and refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(encodeX509Structure({ structure: 'subject-key-identifier', spec: { publicKey: { path: 'leaf.crt.der' } } }))).toBe('SECURITY_VIOLATION');
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.crt.der'), path.join(sandbox, 'leaf.crt.der'));
            expect(await hexOf('subject-key-identifier', { publicKey: { path: 'leaf.crt.der' } })).toMatch(/^0414/);
            expect(await codeOf(encodeX509Structure({ structure: 'subject-key-identifier', spec: { publicKey: { path: 'missing.crt.der' } } }))).toBe('INPUT_NOT_FOUND');
        });

        it('OUTPUT_TOO_LARGE past the inline hex cap (der still works)', async () => {
            const octets = `048301117${'0'}${'00'.repeat(70000)}`;
            expect(await codeOf(encodeX509Structure({ structure: 'attribute', spec: { oid: '1.2.3', values: [octets] } }))).toBe('OUTPUT_TOO_LARGE');
            expect((await encodeX509Structure({ structure: 'attribute', spec: { oid: '1.2.3', values: [octets] }, encoding: 'der' })).sizeBytes).toBeGreaterThan(70000);
        });
    });

    describe('refusals', () => {
        it.each([
            ['spki', { publicKey: '00' }, 'spec algorithm:'],
            ['spki', { algorithm: '1.3.101.112', publicKey: '00', curve: 'x' }, 'spec curve: unknown member'],
            ['spki', { algorithm: '1.2', publicKey: 'zz' }, 'spec publicKey: expected a hexadecimal'],
            ['algorithm-identifier', {}, 'spec oid:'],
            ['algorithm-identifier', { oid: '1.3.101.112', params: '0500' }, 'spec params: unknown member'],
            ['attribute', { values: [] }, 'spec oid:'],
            ['attribute', { oid: '1.2', values: 'x' }, 'spec values: expected an array'],
            ['extension', { oid: 'x', value: '00' }, 'spec oid:'],
            ['extension', { oid: '1.2.3', critical: 'true', value: '0500' }, 'spec critical: expected a boolean'],
            ['extension', { oid: '1.2.3', value: '0500', critcal: true }, 'spec critcal: unknown member'],
            ['extension', { oid: '1.2.3' }, 'spec value: required'],
            ['basic-constraints', { ca: 'yes' }, 'spec ca:'],
            ['basic-constraints', { ca: true, pathLen: -1 }, 'spec pathLen:'],
            ['basic-constraints', { ca: true, critical: true }, 'spec critical: unknown member'],
            ['validity', { notAfter: '2027-01-01T00:00:00Z' }, 'spec notBefore: required'],
            ['validity', { notBefore: '2027-01-01T00:00:00Z', notafter: '2028-01-01T00:00:00Z' }, 'spec notafter: unknown member'],
            ['validity', { notBefore: 'now', notAfter: '2028-01-01T00:00:00Z' }, 'spec notBefore: expected an explicit instant'],
            ['validity', { notBefore: '2027-02-31T00:00:00Z', notAfter: '2028-01-01T00:00:00Z' }, 'spec notBefore: expected an instant'],
            ['validity', { notBefore: '2028-01-01T00:00:00Z', notAfter: '2027-01-01T00:00:00Z' }, 'spec notAfter: must be after'],
            ['validity', [1], 'spec $: expected an object'],
            ['key-usage', { usages: 'x' }, 'spec usages: expected an array of strings'],
            ['key-usage', ['frob'], 'unknown key usage'],
            ['extended-key-usage', ['frob'], 'unknown purpose'],
            ['subject-alt-name', { dns: ['a.test'], critical: true }, 'spec critical: unknown member'],
            ['subject-alt-name', { ip: ['999.1.1.1'] }, 'not an IPv4 or IPv6 address'],
            ['subject-key-identifier', { keyId: 'a1b2', critical: false }, 'spec critical: unknown member'],
            ['subject-key-identifier', {}, 'exactly one of "keyId" or "publicKey"'],
            ['subject-key-identifier', { keyId: 'a1b2', publicKey: { pem: 'x' } }, 'exactly one of "keyId" or "publicKey"'],
            ['subject-key-identifier', { publicKey: 'leaf.crt.pem' }, 'spec publicKey: expected exactly one of pem / derBase64 / path'],
            ['authority-key-identifier', { keyId: 'a1b2', issuer: 'x' }, 'spec issuer: unknown member'],
            ['name-attribute', { type: 'CN', value: 'x', critical: true }, 'spec $.critical: unknown member'],
            ['name', {}, 'at least one RDN'],
            ['extensions', { basicConstraints: { ca: true, pathlen: 1 } }, 'spec extensions.basicConstraints.pathlen: unknown member'],
            ['extensions', { subjectKeyIdentifier: true }, 'cannot be computed here'],
            ['extensions', [1], 'spec $: expected the extensions object'],
        ] as const)('VALIDATION_ERROR naming the path: %s %j', async (structure, spec, message) => {
            try {
                await encodeX509Structure({ structure, spec });
                expect.unreachable();
            } catch (e) {
                expect(e).toBeInstanceOf(ToolError);
                expect((e as ToolError).code).toBe('VALIDATION_ERROR');
                expect((e as ToolError).message).toContain(message);
            }
        });

        it('VALIDATION_ERROR: structure / spec / signer / label combinations', async () => {
            expect(await codeOf(encodeX509Structure({ structure: 'frob', spec: {} }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(encodeX509Structure({ structure: 'name' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(encodeX509Structure({ structure: 'name', spec: { CN: 'x' }, signer: { key: fixtureInput('leaf.key.pem') } }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(encodeX509Structure({ structure: 'signature-algorithm' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(encodeX509Structure({ structure: 'signature-algorithm', spec: {}, signer: { key: fixtureInput('leaf.key.pem') } }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(encodeX509Structure({ structure: 'name', spec: { CN: 'x' }, encoding: 'pem' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(encodeX509Structure({ structure: 'name', spec: { CN: 'x' }, label: 'NAME' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(encodeX509Structure({ structure: 'name', spec: { CN: 'x' }, encoding: 'pem', label: 'bad label' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(encodeX509Structure({ structure: 'name', spec: { CN: 'x' }, encoding: 'pem', label: 'PRIVATE KEY' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(encodeX509Structure({ structure: 'name', spec: { CN: 'x' }, bogus: 1 }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(encodeX509Structure({}))).toBe('VALIDATION_ERROR');
        });

        it('engine refusals carry the PKI_* code; a wrong PEM label is PKI_PEM_UNEXPECTED_LABEL', async () => {
            expect(await codeOf(encodeX509Structure({ structure: 'name-attribute', spec: { type: 'C', value: 'FR', stringType: 'utf8' } }))).toBe('PKI_API_MISUSE');
            expect(await codeOf(encodeX509Structure({ structure: 'extension', spec: { oid: '1.2.3', value: '0500' + '00' } }))).toBe('PKI_API_MISUSE');
            expect(await codeOf(encodeX509Structure({ structure: 'authority-key-identifier', spec: { issuerCertificate: fixtureInput('leaf.csr.pem') } }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            const key = await callToolDirect('encode_x509_structure', { structure: 'subject-key-identifier', spec: { publicKey: fixtureInput('leaf.key.pem') } });
            expect(errorCodeOf(key)).toBe('PKI_PEM_UNEXPECTED_LABEL');
            assertResultClean(key);
        });
    });

    describe('definition', () => {
        it('is a deterministic WRITES artefact, cacheable, with the 15 CLI structures and two validating examples', () => {
            expect(ENCODE_X509_STRUCTURE_TOOL.kind).toBe('artefact');
            expect(ENCODE_X509_STRUCTURE_TOOL.annotations).toEqual({ readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false });
            expect(ENCODE_X509_STRUCTURE_TOOL.cacheable).toBe(true);
            expect(X509_STRUCTURES).toHaveLength(15);
            expect(ENCODE_X509_STRUCTURE_TOOL.examples?.length).toBe(2);
        });
    });
});
