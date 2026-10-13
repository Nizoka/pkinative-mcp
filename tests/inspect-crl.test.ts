/**
 * Tests for `inspect_crl` — facts of a base and a delta CRL, the entry
 * lookup by serial and by certificate, the signature check, projection,
 * sandbox paths, every error code.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { INSPECT_CRL_TOOL, inspectCrl, inspectCrlSummary } from '../src/tools/inspect-crl.js';
import { assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureBase64, fixtureInput, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const CRL = fixtureInput('inter.crl.pem');

describe('inspect_crl', () => {
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
        it('reports the intermediate CRL (PEM input)', async () => {
            const r = await inspectCrl({ crl: CRL });
            expect(r.version).toBe(2);
            expect(r.issuerString).toContain('CN=Test Intermediate CA');
            expect(r.issuer.string).toBe(r.issuerString);
            expect(r.signatureAlgorithm.oid).toBe('1.2.840.10045.4.3.2');
            expect(r.thisUpdate.iso).toBe('2026-10-04T19:05:34.000Z');
            expect(r.nextUpdate?.iso).toBe('2046-09-29T19:05:34.000Z');
            expect(r.crlNumber).toBe('1');
            expect(r.isDelta).toBe(false);
            expect(r.baseCrlNumber).toBeNull();
            expect(r.issuingDistributionPoint).toBeNull();
            expect(r.entryCount).toBe(1);
            expect(r.extensions.map((e) => e['kind'])).toEqual(['authorityKeyIdentifier', 'unknown']);
            expect(r.sizeBytes).toBeGreaterThan(100);
            expect(r.entry).toBeUndefined();
            expect(r.signature).toBeUndefined();
            expect(r.diagnostics).toEqual([]);
        });

        it('reports a delta CRL (DER input) with its base number', async () => {
            const r = await inspectCrl({ crl: { derBase64: fixtureBase64('ed25519-delta.crl.der') } });
            expect(r.isDelta).toBe(true);
            expect(r.crlNumber).toBe('2');
            expect(r.baseCrlNumber).toBe('1');
            expect(r.issuerString).toContain('CN=Test Ed25519 Root');
            expect(r.entryCount).toBe(2);
        });
    });

    describe('entry lookup', () => {
        it('finds a revoked serial by hex (0x prefix and colons tolerated)', async () => {
            const r = await inspectCrl({ crl: { derBase64: fixtureBase64('inter.crl.der') }, find: { serialHex: '0x10:02' } });
            expect(r.entry).toEqual({
                revoked: true,
                serialNumber: '1002',
                revocationDate: expect.objectContaining({ iso: '2026-06-01T00:00:00.000Z' }),
                reason: 'keyCompromise',
                invalidityDate: null,
                extensions: [expect.objectContaining({ oid: '2.5.29.21' })],
            });
        });

        it('reports a serial that is not listed', async () => {
            const r = await inspectCrl({ crl: CRL, find: { serialHex: '1001' } });
            expect(r.entry).toEqual({ revoked: false, serialNumber: '1001' });
        });

        it('looks a certificate up by its serial and issuer', async () => {
            const revoked = await inspectCrl({ crl: CRL, find: { certificate: fixtureInput('revoked.crt.pem') } });
            expect(revoked.entry?.revoked).toBe(true);
            expect(revoked.entry?.reason).toBe('keyCompromise');
            const clean = await inspectCrl({ crl: CRL, find: { certificate: fixtureInput('leaf.crt.pem') } });
            expect(clean.entry).toEqual({ revoked: false, serialNumber: '1001' });
        });
    });

    describe('signature check (one key, not trust)', () => {
        it('verifies against the issuer and reports the wrong one as invalid', async () => {
            const ok = await inspectCrl({ crl: CRL, issuer: fixtureInput('inter.crt.pem') });
            expect(ok.signature).toEqual({ valid: true, issuerSubject: expect.stringContaining('CN=Test Intermediate CA') });
            const bad = await inspectCrl({ crl: CRL, issuer: fixtureInput('root.crt.pem'), allowSha1: true });
            expect(bad.signature?.valid).toBe(false);
        });
    });

    describe('projection', () => {
        it('summary keeps the scalars only', async () => {
            const r = await inspectCrl({ crl: CRL, find: { serialHex: '1002' }, issuer: fixtureInput('inter.crt.pem') });
            expect(inspectCrlSummary(r)).toEqual({
                issuerString: r.issuerString,
                thisUpdateIso: '2026-10-04T19:05:34.000Z',
                nextUpdateIso: '2046-09-29T19:05:34.000Z',
                crlNumber: '1',
                entryCount: 1,
                isDelta: false,
                revoked: true,
                signatureValid: true,
                diagnosticCount: 0,
            });
        });

        it('fields project over the wire and the text line names the lookup', async () => {
            const result = await callToolDirect('inspect_crl', { crl: CRL, find: { serialHex: '1002' }, verbosity: 'summary', fields: ['crlNumber', 'revoked', 'nope'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ crlNumber: '1', revoked: true });
            expect(result._meta).toEqual({ unmatchedFields: ['nope'], availableFields: expect.arrayContaining(['entryCount', 'isDelta']) });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringMatching(/^inspect_crl: CRL v2 by CN=Test Intermediate CA.*number 1, 1 entry.*serial 1002 REVOKED \(keyCompromise\)/) });
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads a CRL from the sandbox and refuses escapes', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('inter.crl.der'), path.join(sandbox, 'inter.crl'));
            const r = await inspectCrl({ crl: { path: 'inter.crl' } });
            expect(r.crlNumber).toBe('1');
            expect(await codeOf(inspectCrl({ crl: { path: '../inter.crl' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(inspectCrl({ crl: { path: 'missing.crl' } }))).toBe('INPUT_NOT_FOUND');
            expect(await codeOf(inspectCrl({ crl: { path: 'inter.exe' } }))).toBe('INVALID_EXTENSION');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(inspectCrl({ crl: { path: 'inter.crl' } }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it.each([
            ['nothing', {}],
            ['unknown key', { crl: CRL, bogus: 1 }],
            ['two input forms', { crl: { pem: fixtureText('inter.crl.pem'), derBase64: fixtureBase64('inter.crl.der') } }],
            ['find with neither member', { crl: CRL, find: {} }],
            ['find with both members', { crl: CRL, find: { serialHex: '1002', certificate: fixtureInput('leaf.crt.pem') } }],
            ['find.serialHex not hex', { crl: CRL, find: { serialHex: 'zz' } }],
            ['find.serialHex empty', { crl: CRL, find: { serialHex: '' } }],
            ['find.serialHex only a prefix', { crl: CRL, find: { serialHex: '0x' } }],
        ])('VALIDATION_ERROR: %s', async (_what, input) => {
            expect(await codeOf(inspectCrl(input))).toBe('VALIDATION_ERROR');
        });

        it('PKI_PEM_UNEXPECTED_LABEL for a PEM without a CRL block, PKI_* for non-CRL DER', async () => {
            expect(await codeOf(inspectCrl({ crl: fixtureInput('inter.crt.pem') }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(inspectCrl({ crl: CRL, issuer: fixtureInput('inter.crl.pem') }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(inspectCrl({ crl: CRL, find: { certificate: fixtureInput('leaf.csr.pem') } }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(inspectCrl({ crl: { derBase64: fixtureBase64('leaf.crt.der') } }))).toMatch(/^PKI_/);
        });

        it('a private key is refused as a CRL and never echoed', async () => {
            const result = await callToolDirect('inspect_crl', { crl: fixtureInput('leaf.key.pem') });
            expect(errorCodeOf(result)).toBe('PKI_PEM_UNEXPECTED_LABEL');
            assertResultClean(result);
        });
    });

    describe('definition', () => {
        it('is read-only, cacheable, with two validating examples', () => {
            expect(INSPECT_CRL_TOOL.kind).toBe('read');
            expect(INSPECT_CRL_TOOL.annotations.readOnlyHint).toBe(true);
            expect(INSPECT_CRL_TOOL.cacheable).toBe(true);
            expect(INSPECT_CRL_TOOL.instantInputs).toBeUndefined();
            expect(INSPECT_CRL_TOOL.examples?.length).toBe(2);
        });
    });
});
