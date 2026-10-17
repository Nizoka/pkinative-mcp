/**
 * Tests for `check_crl_revocation` — the positive and the revoked verdict,
 * the signature report, staleness, the delta CRL pair of the Ed25519 CA,
 * projection, sandbox paths, every error code.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { CHECK_CRL_REVOCATION_TOOL, checkCrlRevocation, checkCrlRevocationSummary } from '../src/tools/check-crl-revocation.js';
import { createCertificateTool } from '../src/tools/create-certificate.js';
import { assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { AT, fixture, fixtureBase64, fixtureInput, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const LEAF = fixtureInput('leaf.crt.pem');
const CRL = fixtureInput('inter.crl.pem');
const INTER = fixtureInput('inter.crt.pem');
const ED_CA = fixtureInput('ed25519.crt.pem');
const ED_BASE = fixtureInput('ed25519.crl.der');
const ED_DELTA = fixtureInput('ed25519-delta.crl.der');

/** A certificate with the given serial issued by the Ed25519 test CA (its key is public test material). */
async function issue(serialNumber: string): Promise<{ pem: string }> {
    const r = await createCertificateTool({
        spec: { serialNumber, subject: { CN: serialNumber }, notBefore: '2026-01-01T00:00:00Z', validityDays: 3650 },
        issuerCertificate: ED_CA,
        subjectPublicKey: fixtureInput('leaf.pub.pem'),
        signer: { key: fixtureInput('ed25519.key.pem') },
    });
    return { pem: Buffer.from(r.base64 as string, 'base64').toString('utf8') };
}

describe('check_crl_revocation', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_AT'];
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('verdicts', () => {
        it('the leaf is not revoked according to the signature-verified intermediate CRL', async () => {
            const r = await checkCrlRevocation({ certificate: LEAF, crl: CRL, issuer: INTER, at: AT });
            expect(r.valid).toBe(true);
            expect(r.reasons).toEqual([]);
            expect(r.signatureVerified).toBe(true);
            expect(r.deltaSignatureVerified).toBeUndefined();
            expect(r.deltaCrlNumber).toBeUndefined();
            expect(r.crlNumber).toBe('1');
            expect(r.isDelta).toBe(false);
            expect(r.evaluatedAt).toBe('2027-01-01T00:00:00.000Z');
            expect(r.evaluatedAtSource).toBe('input');
            expect(r.diagnostics).toEqual([]);
        });

        it('the revoked leaf is PKI_REASON_REVOKED (with the reason), never isError', async () => {
            const r = await checkCrlRevocation({ certificate: fixtureInput('revoked.crt.pem'), crl: { derBase64: fixtureBase64('inter.crl.der') }, issuer: INTER, at: AT });
            expect(r.valid).toBe(false);
            expect(r.reasons.map((x) => x['code'])).toContain('PKI_REASON_REVOKED');
            expect(r.reasons.find((x) => x['code'] === 'PKI_REASON_REVOKED')?.['message']).toMatch(/keyCompromise/);
            const result = await callToolDirect('check_crl_revocation', { certificate: fixtureInput('revoked.crt.pem'), crl: CRL, issuer: INTER, at: AT });
            expect(result.isError).toBeUndefined();
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringMatching(/^check_crl_revocation: NOT OK — .*PKI_REASON_REVOKED/) });
        });

        it('without an issuer the list is unverified (signatureVerified null) and the verdict negative; a wrong issuer is reported false', async () => {
            const unverified = await checkCrlRevocation({ certificate: LEAF, crl: CRL, at: AT });
            expect(unverified.signatureVerified).toBeNull();
            expect(unverified.valid).toBe(false);
            expect(unverified.reasons.map((x) => x['code']).join()).toMatch(/PKI_REASON_/);
            const wrong = await checkCrlRevocation({ certificate: LEAF, crl: CRL, issuer: fixtureInput('root.crt.pem'), at: AT, allowSha1: true });
            expect(wrong.signatureVerified).toBe(false);
            expect(wrong.valid).toBe(false);
        });

        it('judges staleness past nextUpdate with the tolerance', async () => {
            const stale = await checkCrlRevocation({ certificate: LEAF, crl: CRL, issuer: INTER, at: '2047-01-01', staleTolerance: 1000 });
            expect(stale.valid).toBe(false);
            expect(stale.reasons.map((x) => x['code']).join()).toMatch(/PKI_REASON_/);
            const fresh = await checkCrlRevocation({ certificate: LEAF, crl: CRL, issuer: INTER, at: '2046-09-29T19:05:35Z', staleTolerance: 2000 });
            expect(fresh.valid).toBe(true);
        });

        it('applies a delta CRL over the base (the Ed25519 pair)', async () => {
            const inDelta = await issue('0x99');
            const clean = await issue('0x22');
            const base = await checkCrlRevocation({ certificate: inDelta, crl: ED_BASE, issuer: ED_CA, at: AT });
            expect(base.valid).toBe(true);
            const revoked = await checkCrlRevocation({ certificate: inDelta, crl: ED_BASE, delta: ED_DELTA, issuer: ED_CA, at: AT });
            expect(revoked.valid).toBe(false);
            expect(revoked.reasons.map((x) => x['code'])).toContain('PKI_REASON_REVOKED');
            expect(revoked).toMatchObject({ signatureVerified: true, deltaSignatureVerified: true, crlNumber: '1', deltaCrlNumber: '2', isDelta: false });
            const still = await checkCrlRevocation({ certificate: clean, crl: ED_BASE, delta: ED_DELTA, issuer: ED_CA, at: AT });
            expect(still.valid).toBe(true);
            const unverified = await checkCrlRevocation({ certificate: clean, crl: ED_BASE, delta: ED_DELTA, at: AT });
            expect(unverified.valid).toBe(false);
            expect(unverified).toMatchObject({ signatureVerified: null, deltaSignatureVerified: null });
            const inBase = await checkCrlRevocation({ certificate: await issue('0x77'), crl: ED_BASE, delta: ED_DELTA, issuer: ED_CA, at: AT });
            expect(inBase.reasons.map((x) => x['code'])).toContain('PKI_REASON_REVOKED');
        });

        it('refuses a base CRL given as the delta (VALIDATION_ERROR naming it)', async () => {
            const result = await callToolDirect('check_crl_revocation', { certificate: ED_CA, crl: ED_BASE, delta: ED_BASE, issuer: ED_CA, at: AT });
            expect(errorCodeOf(result)).toBe('VALIDATION_ERROR');
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringMatching(/not a delta CRL/) });
        });
    });

    describe('B2-083: a delta whose signature fails is not applied', () => {
        it('B2-083: a delta CRL issued by another CA is refused as evidence — valid false, PKI_REASON_REVOCATION_UNKNOWN on delta, deltaSignatureVerified false', async () => {
            const result = await callToolDirect('check_crl_revocation', { certificate: fixtureInput('leaf.crt.pem'), crl: fixtureInput('inter.crl.pem'), delta: fixtureInput('ed25519-delta.crl.der'), issuer: fixtureInput('inter.crt.pem'), at: AT });
            expect(result.isError).not.toBe(true);
            const s = result.structuredContent as { valid: boolean; deltaSignatureVerified: boolean | null; reasons: Array<{ code: string; path: string }> };
            expect(s.valid).toBe(false);
            expect(s.deltaSignatureVerified).toBe(false);
            expect(s.reasons.find((r) => r.path === 'delta')?.code).toBe('PKI_REASON_REVOCATION_UNKNOWN');
            assertResultClean(result);
        });

        it('B2-081: the issuer description names a real reason code', () => {
            const text = JSON.stringify(CHECK_CRL_REVOCATION_TOOL.inputSchema);
            expect(text).not.toContain('PKI_REASON_CRL_SIGNATURE_UNVERIFIED');
            expect(text).toContain('PKI_REASON_REVOCATION_UNKNOWN');
        });
    });

    describe('projection', () => {
        it('summary keeps the scalars only', async () => {
            const r = await checkCrlRevocation({ certificate: LEAF, crl: CRL, issuer: INTER, at: AT });
            expect(checkCrlRevocationSummary(r)).toEqual({ valid: true, reasonCodes: [], signatureVerified: true, evaluatedAt: '2027-01-01T00:00:00.000Z', crlNumber: '1', diagnosticCount: 0 });
            const d = await checkCrlRevocation({ certificate: ED_CA, crl: ED_BASE, delta: ED_DELTA, issuer: ED_CA, at: AT });
            expect(checkCrlRevocationSummary(d)).toMatchObject({ deltaSignatureVerified: true });
        });

        it('verbosity and fields project over the wire', async () => {
            const result = await callToolDirect('check_crl_revocation', { certificate: LEAF, crl: CRL, issuer: INTER, at: AT, verbosity: 'summary', fields: ['valid', 'signatureVerified'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ valid: true, signatureVerified: true });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringMatching(/^check_crl_revocation: OK — not revoked at 2027-01-01T00:00:00.000Z \(CRL number 1, signature verified\)/) });
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads the inputs from the sandbox and refuses escapes', async () => {
            sandbox = await makeSandbox();
            for (const f of ['revoked.crt.pem', 'inter.crl.der', 'inter.crt.pem']) await fs.copyFile(fixture(f), path.join(sandbox, f));
            const r = await checkCrlRevocation({ certificate: { path: 'revoked.crt.pem' }, crl: { path: 'inter.crl.der' }, issuer: { path: 'inter.crt.pem' }, at: AT });
            expect(r.reasons.map((x) => x['code'])).toContain('PKI_REASON_REVOKED');
            expect(await codeOf(checkCrlRevocation({ certificate: LEAF, crl: { path: '../inter.crl.der' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(checkCrlRevocation({ certificate: LEAF, crl: { path: 'missing.crl' } }))).toBe('INPUT_NOT_FOUND');
            expect(await codeOf(checkCrlRevocation({ certificate: LEAF, crl: CRL, delta: { path: 'delta.txt' } }))).toBe('INVALID_EXTENSION');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(checkCrlRevocation({ certificate: { path: 'leaf.crt.pem' }, crl: CRL }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it.each([
            ['nothing', {}],
            ['no crl', { certificate: LEAF }],
            ['no certificate', { crl: CRL }],
            ['unknown key', { certificate: LEAF, crl: CRL, trustAnchors: [INTER] }],
            ['two input forms', { certificate: LEAF, crl: { pem: fixtureText('inter.crl.pem'), derBase64: fixtureBase64('inter.crl.der') } }],
            ['negative staleTolerance', { certificate: LEAF, crl: CRL, staleTolerance: -1 }],
            ['fractional staleTolerance', { certificate: LEAF, crl: CRL, staleTolerance: 1.5 }],
            ['bad instant', { certificate: LEAF, crl: CRL, at: '2027-13-01' }],
        ])('VALIDATION_ERROR: %s', async (_what, input) => {
            expect(await codeOf(checkCrlRevocation(input))).toBe('VALIDATION_ERROR');
        });

        it('PKI_PEM_UNEXPECTED_LABEL for swapped inputs, PKI_* for non-CRL DER', async () => {
            expect(await codeOf(checkCrlRevocation({ certificate: CRL, crl: LEAF }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(checkCrlRevocation({ certificate: LEAF, crl: CRL, issuer: CRL }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(checkCrlRevocation({ certificate: LEAF, crl: { derBase64: fixtureBase64('leaf.crt.der') } }))).toMatch(/^PKI_/);
        });

        it('a private key is refused as the certificate and never echoed', async () => {
            const result = await callToolDirect('check_crl_revocation', { certificate: fixtureInput('leaf.key.pem'), crl: CRL });
            expect(errorCodeOf(result)).toBe('PKI_PEM_UNEXPECTED_LABEL');
            assertResultClean(result);
        });
    });

    describe('definition', () => {
        it('is a read-only cacheable verdict pinned on at, with two validating examples', () => {
            expect(CHECK_CRL_REVOCATION_TOOL.kind).toBe('verdict');
            expect(CHECK_CRL_REVOCATION_TOOL.annotations.readOnlyHint).toBe(true);
            expect(CHECK_CRL_REVOCATION_TOOL.cacheable).toBe(true);
            expect(CHECK_CRL_REVOCATION_TOOL.instantInputs).toEqual(['at']);
            expect(CHECK_CRL_REVOCATION_TOOL.examples?.length).toBe(2);
        });
    });
});
