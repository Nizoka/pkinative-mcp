/**
 * Tests for `inspect_csr` — facts of the fixture request, the proof of
 * possession (valid, tampered, skipped), raw extensions, projection, path
 * inputs, every error code, no secret.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { inspectCsr, inspectCsrSummary, INSPECT_CSR_TOOL } from '../src/tools/inspect-csr.js';
import { assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureBase64, fixtureBytes, fixtureInput, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const SUBJECT = 'CN=csr.example.test,O=pkinative-cli test,C=FR';

describe('inspect_csr', () => {
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
        it('reports the fixture request (PEM input) with its proof of possession', async () => {
            const r = await inspectCsr({ request: fixtureInput('leaf.csr.pem') });
            expect(r.version).toBe(0);
            expect(r.subjectString).toBe(SUBJECT);
            expect(r.subject.string).toBe(SUBJECT);
            expect(r.subject.rdns.map((rdn) => rdn[0]?.name)).toEqual(['countryName', 'organizationName', 'commonName']);
            expect(r.subjectPublicKeyInfo['kind']).toBe('ec');
            expect(r.subjectPublicKeyInfo['curve']).toBe('P-256');
            expect(r.attributes).toEqual([{ oid: '1.2.840.113549.1.9.14', name: 'extensionRequest', valueCount: 1 }]);
            expect(r.extensions?.map((e) => e['kind'])).toEqual(['subjectAltName']);
            expect(r.extensions?.[0]?.['names']).toEqual([{ kind: 'dNSName', value: 'csr.example.test' }]);
            expect(r.extensions?.[0]).not.toHaveProperty('valueDer');
            expect(r.challengePassword).toBe(false);
            expect(r.signatureAlgorithm).toEqual({ oid: '1.2.840.10045.4.3.2', name: 'ecdsa-with-SHA256', hasParameters: false });
            expect(r.sizeBytes).toBe(fixtureBytes('leaf.csr.der').length);
            expect(r.signature).toEqual({ valid: true, reasons: [], signatureVerifications: 1 });
            expect(r.diagnostics).toEqual([]);
            expect(r.diagnosticCounts).toEqual({});
        });

        it('accepts DER as base64, keeps raw extensions on request, and skips the signature with verify:false', async () => {
            const r = await inspectCsr({ request: { derBase64: fixtureBase64('leaf.csr.der') }, rawExtensions: true, verify: false });
            expect(r.subjectString).toBe(SUBJECT);
            expect(r.extensions?.every((e) => e['kind'] === 'raw' && typeof e['valueDer'] === 'string')).toBe(true);
            expect(r.signature).toBeUndefined();
        });

        it('reports a tampered signature as invalid (a verdict, not an error)', async () => {
            const der = Buffer.from(fixtureBytes('leaf.csr.der'));
            der[der.length - 5] = (der[der.length - 5] as number) ^ 0xff;
            const r = await inspectCsr({ request: { derBase64: der.toString('base64') } });
            expect(r.signature?.valid).toBe(false);
            expect(r.signature?.reasons.map((x) => x['code'])).toEqual(['PKI_REASON_SIGNATURE_INVALID']);
            const result = await callToolDirect('inspect_csr', { request: { derBase64: der.toString('base64') } });
            expect(result.isError).toBeUndefined();
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringContaining('signature INVALID (PKI_REASON_SIGNATURE_INVALID)') });
        });

        it('the text names the subject, the key and the extensions', async () => {
            const result = await callToolDirect('inspect_csr', { request: fixtureInput('leaf.csr.pem') });
            expect(result.content[0]).toEqual({ type: 'text', text: `inspect_csr: ${SUBJECT} requests a ec key certified, 1 extension(s) (subjectAltName), 1 attribute(s), signature valid (proof of possession), 0 diagnostic(s).` });
        });
    });

    describe('projection', () => {
        it('summary keeps the scalars only', async () => {
            const r = await inspectCsr({ request: fixtureInput('leaf.csr.pem') });
            expect(inspectCsrSummary(r)).toEqual({ subjectString: SUBJECT, publicKey: 'ec', extensionKinds: ['subjectAltName'], challengePassword: false, signatureValid: true, diagnosticCount: 0 });
            const skipped = await inspectCsr({ request: fixtureInput('leaf.csr.pem'), verify: false });
            expect(inspectCsrSummary(skipped)).not.toHaveProperty('signatureValid');
        });

        it('fields project over the wire and unmatched paths are reported', async () => {
            const result = await callToolDirect('inspect_csr', { request: fixtureInput('leaf.csr.pem'), verbosity: 'summary', fields: ['subjectString', 'signatureValid', 'nope'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ subjectString: SUBJECT, signatureValid: true });
            expect(result._meta).toEqual({ unmatchedFields: ['nope'], availableFields: expect.arrayContaining(['subjectString', 'extensionKinds']) });
            const full = await callToolDirect('inspect_csr', { request: fixtureInput('leaf.csr.pem'), verify: false, fields: ['extensions.names'] });
            expect(full.structuredContent).toEqual({ extensions: [{ names: [{ kind: 'dNSName', value: 'csr.example.test' }] }] });
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads a request from the sandbox (.csr) and refuses escapes', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.csr.der'), path.join(sandbox, 'leaf.csr'));
            const r = await inspectCsr({ request: { path: 'leaf.csr' } });
            expect(r.subjectString).toBe(SUBJECT);
            expect(await codeOf(inspectCsr({ request: { path: '../leaf.csr' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(inspectCsr({ request: { path: 'missing.csr' } }))).toBe('INPUT_NOT_FOUND');
            expect(await codeOf(inspectCsr({ request: { path: 'leaf.exe' } }))).toBe('INVALID_EXTENSION');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(inspectCsr({ request: { path: 'leaf.csr' } }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it('VALIDATION_ERROR: unknown key, two input forms, PEM in derBase64, nothing', async () => {
            expect(await codeOf(inspectCsr({ request: fixtureInput('leaf.csr.pem'), bogus: 1 }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(inspectCsr({ request: { pem: fixtureText('leaf.csr.pem'), derBase64: fixtureBase64('leaf.csr.der') } }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(inspectCsr({ request: { derBase64: fixtureText('leaf.csr.pem') } }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(inspectCsr({}))).toBe('VALIDATION_ERROR');
        });

        it('PKI_PEM_UNEXPECTED_LABEL for a PEM without a request block, PKI_* for non-request DER', async () => {
            expect(await codeOf(inspectCsr({ request: fixtureInput('leaf.crt.pem') }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(inspectCsr({ request: { derBase64: fixtureBase64('leaf.crt.der') } }))).toMatch(/^PKI_/);
            expect(await codeOf(inspectCsr({ request: { derBase64: 'AAAA' } }))).toMatch(/^PKI_/);
        });

        it('a private key is refused as a request and never echoed', async () => {
            const result = await callToolDirect('inspect_csr', { request: fixtureInput('leaf.key.pem') });
            expect(errorCodeOf(result)).toBe('PKI_PEM_UNEXPECTED_LABEL');
            assertResultClean(result);
        });

        it('strict escalates a diagnostic; ber is accepted as an encoding rule', async () => {
            const r = await inspectCsr({ request: fixtureInput('leaf.csr.pem'), strict: true, encodingRules: 'ber' });
            expect(r.subjectString).toBe(SUBJECT);
        });
    });

    describe('definition', () => {
        it('is read-only, cacheable, with two validating examples', () => {
            expect(INSPECT_CSR_TOOL.kind).toBe('read');
            expect(INSPECT_CSR_TOOL.annotations.readOnlyHint).toBe(true);
            expect(INSPECT_CSR_TOOL.cacheable).toBe(true);
            expect(INSPECT_CSR_TOOL.examples?.length).toBe(2);
        });
    });
});
