/**
 * Tests for `inspect_certificate` — facts, extensions, fingerprints, the
 * signature check, projection, path inputs, every error code, no secret.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { ToolError } from '../src/errors.js';
import { callToolDirect } from '../src/server.js';
import { inspectCertificate, inspectCertificateSummary, INSPECT_CERTIFICATE_TOOL } from '../src/tools/inspect-certificate.js';
import { assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureBase64, fixtureInput, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

describe('inspect_certificate', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('facts', () => {
        it('reports the leaf certificate (PEM input)', async () => {
            const r = await inspectCertificate({ certificate: fixtureInput('leaf.crt.pem') });
            expect(r.version).toBe(3);
            expect(r.serialNumber.hex).toBe('1001');
            expect(r.serialNumber.decimal).toBe('4097');
            expect(r.subjectString).toContain('CN=example.test');
            expect(r.issuerString).toContain('CN=Test Intermediate CA');
            expect(r.validity.notBefore.iso).toBe('2026-01-01T00:00:00.000Z');
            expect(r.validity.notAfter.iso).toBe('2046-01-01T00:00:00.000Z');
            expect(r.subjectPublicKeyInfo['kind']).toBe('ec');
            expect(r.subjectPublicKeyInfo['curve']).toBe('P-256');
            expect(r.extensions.map((e) => e['kind'])).toEqual([
                'basicConstraints', 'keyUsage', 'extendedKeyUsage', 'subjectAltName', 'subjectKeyIdentifier', 'authorityKeyIdentifier', 'crlDistributionPoints', 'authorityInfoAccess',
            ]);
            expect(r.selfIssued).toBe(false);
            expect(r.fingerprints['SHA-256']).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
            expect(r.signature).toBeUndefined();
            expect(r.diagnostics).toEqual([]);
            expect(r.diagnosticCounts).toEqual({});
        });

        it('accepts DER as base64 and reports every requested fingerprint', async () => {
            const r = await inspectCertificate({ certificate: { derBase64: fixtureBase64('leaf.crt.der') }, fingerprints: ['SHA-1', 'SHA-256', 'SHA-512'] });
            expect(Object.keys(r.fingerprints).sort()).toEqual(['SHA-1', 'SHA-256', 'SHA-512']);
            expect(r.fingerprints['SHA-1']).toMatch(/^([0-9A-F]{2}:){19}[0-9A-F]{2}$/);
        });

        it('returns one extension on demand and the raw form on request', async () => {
            const one = await inspectCertificate({ certificate: fixtureInput('leaf.crt.pem'), extension: 'subjectAltName' });
            expect(one.extension?.['kind']).toBe('subjectAltName');
            expect((one.extension?.['names'] as Array<Record<string, unknown>>).map((n) => n['value'] ?? n['address'])).toEqual(['example.test', '*.wild.example.test', '192.0.2.1', 'leaf@example.test']);
            const raw = await inspectCertificate({ certificate: fixtureInput('leaf.crt.pem'), rawExtensions: true });
            expect(raw.extensions.every((e) => e['kind'] === 'raw' && typeof e['valueDer'] === 'string')).toBe(true);
        });

        it('reports a self-issued root', async () => {
            const r = await inspectCertificate({ certificate: fixtureInput('root.crt.pem'), checkSelfSignature: true });
            expect(r.selfIssued).toBe(true);
            expect(r.signature).toEqual({ checked: 'self', valid: true });
        });
    });

    describe('signature check (one key, not trust)', () => {
        it('verifies against the right issuer', async () => {
            const r = await inspectCertificate({ certificate: fixtureInput('leaf.crt.pem'), issuer: fixtureInput('inter.crt.pem') });
            expect(r.signature).toEqual({ checked: 'issuer', valid: true, issuerSubject: expect.stringContaining('Test Intermediate CA') });
        });

        it('reports an invalid signature against the wrong issuer (no isError)', async () => {
            const r = await inspectCertificate({ certificate: fixtureInput('leaf.crt.pem'), issuer: fixtureInput('root.crt.pem') });
            expect(r.signature?.valid).toBe(false);
        });
    });

    describe('projection', () => {
        it('summary keeps the scalars only', async () => {
            const r = await inspectCertificate({ certificate: fixtureInput('leaf.crt.pem'), issuer: fixtureInput('inter.crt.pem') });
            const s = inspectCertificateSummary(r);
            expect(s).toEqual({
                serialNumberHex: '1001',
                subjectString: r.subjectString,
                issuerString: r.issuerString,
                notBefore: '2026-01-01T00:00:00.000Z',
                notAfter: '2046-01-01T00:00:00.000Z',
                publicKey: 'ec',
                extensionKinds: r.extensions.map((e) => e['kind']),
                selfIssued: false,
                signatureValid: true,
                diagnosticCount: 0,
            });
        });

        it('fields project over the wire and unmatched paths are reported', async () => {
            const result = await callToolDirect('inspect_certificate', { certificate: fixtureInput('leaf.crt.pem'), verbosity: 'summary', fields: ['serialNumberHex', 'nope'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ serialNumberHex: '1001' });
            expect(result._meta).toEqual({ unmatchedFields: ['nope'], availableFields: expect.arrayContaining(['serialNumberHex', 'notAfter']) });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('inspect_certificate: CN=example.test') });
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads a certificate from the sandbox and refuses escapes', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.crt.der'), path.join(sandbox, 'leaf.crt.der'));
            const r = await inspectCertificate({ certificate: { path: 'leaf.crt.der' } });
            expect(r.serialNumber.hex).toBe('1001');
            expect(await codeOf(inspectCertificate({ certificate: { path: '../leaf.crt.der' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(inspectCertificate({ certificate: { path: 'missing.crt.pem' } }))).toBe('INPUT_NOT_FOUND');
            expect(await codeOf(inspectCertificate({ certificate: { path: 'leaf.exe' } }))).toBe('INVALID_EXTENSION');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(inspectCertificate({ certificate: { path: 'leaf.crt.der' } }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it('VALIDATION_ERROR: unknown key, two input forms, both signature checks, extension + rawExtensions', async () => {
            expect(await codeOf(inspectCertificate({ certificate: fixtureInput('leaf.crt.pem'), bogus: 1 }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(inspectCertificate({ certificate: { pem: fixtureText('leaf.crt.pem'), derBase64: fixtureBase64('leaf.crt.der') } }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(inspectCertificate({ certificate: fixtureInput('leaf.crt.pem'), issuer: fixtureInput('inter.crt.pem'), checkSelfSignature: true }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(inspectCertificate({ certificate: fixtureInput('leaf.crt.pem'), extension: 'keyUsage', rawExtensions: true }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(inspectCertificate({ certificate: { derBase64: fixtureText('leaf.crt.pem') } }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(inspectCertificate({}))).toBe('VALIDATION_ERROR');
        });

        it('NOT_FOUND for an absent extension, naming the present ones', async () => {
            try {
                await inspectCertificate({ certificate: fixtureInput('root.crt.pem'), extension: 'subjectAltName' });
                expect.unreachable();
            } catch (e) {
                expect(e).toBeInstanceOf(ToolError);
                expect((e as ToolError).code).toBe('NOT_FOUND');
                expect((e as ToolError).data).toMatchObject({ extension: 'subjectAltName', present: expect.arrayContaining(['basicConstraints']) });
            }
        });

        it('PKI_PEM_UNEXPECTED_LABEL for a PEM without a certificate block, PKI_* for non-certificate DER', async () => {
            expect(await codeOf(inspectCertificate({ certificate: fixtureInput('leaf.csr.pem') }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            const code = await codeOf(inspectCertificate({ certificate: { derBase64: fixtureBase64('leaf.csr.der') } }));
            expect(code).toMatch(/^PKI_/);
        });

        it('a private key is refused as a certificate and never echoed', async () => {
            const result = await callToolDirect('inspect_certificate', { certificate: fixtureInput('leaf.key.pem') });
            expect(errorCodeOf(result)).toBe('PKI_PEM_UNEXPECTED_LABEL');
            assertResultClean(result);
        });

        it('strict escalates a diagnostic; ber is accepted as an encoding rule', async () => {
            const r = await inspectCertificate({ certificate: fixtureInput('leaf.crt.pem'), strict: true, encodingRules: 'ber' });
            expect(r.serialNumber.hex).toBe('1001');
        });
    });

    describe('definition', () => {
        it('is read-only, cacheable, with two validating examples', () => {
            expect(INSPECT_CERTIFICATE_TOOL.kind).toBe('read');
            expect(INSPECT_CERTIFICATE_TOOL.annotations.readOnlyHint).toBe(true);
            expect(INSPECT_CERTIFICATE_TOOL.cacheable).toBe(true);
            expect(INSPECT_CERTIFICATE_TOOL.examples?.length).toBe(2);
        });
    });
});
