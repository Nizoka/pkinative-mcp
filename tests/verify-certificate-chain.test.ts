/**
 * Tests for `verify_certificate_chain` — the RFC 5280 §6 verdict with
 * offline revocation; a negative verdict is a report, never an error.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { __resetCeilingsForTests } from '../src/caps.js';
import { callToolDirect } from '../src/server.js';
import { chainSummary, nonceBytes, serverIdentity, verifyCertificateChainTool, VERIFY_CERTIFICATE_CHAIN_TOOL } from '../src/tools/verify-certificate-chain.js';
import { assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { AT, fixture, fixtureBase64, fixtureInput, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const LEAF = fixtureInput('leaf.crt.pem');
const INTER = fixtureInput('inter.crt.pem');
const ROOT = fixtureInput('root.crt.pem');
const BASE = { leaf: LEAF, candidates: [INTER], trustAnchors: [ROOT], at: AT };

describe('verify_certificate_chain', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_AT'];
        delete process.env['PKINATIVE_MCP_MAX_PATHS_EXPLORED'];
        __resetCeilingsForTests();
    });

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
        delete process.env['PKINATIVE_MCP_AT'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_MAX_PATHS_EXPLORED'];
        __resetCeilingsForTests();
    });

    describe('verdicts', () => {
        it('a valid chain at a pinned instant, with server name and purpose', async () => {
            const r = await verifyCertificateChainTool({ ...BASE, serverName: { host: 'a.wild.example.test' }, purposes: ['serverAuth'] });
            expect(r.valid).toBe(true);
            expect(r.reasons).toEqual([]);
            expect(r.path.map((c) => c.subject)).toEqual([expect.stringContaining('CN=example.test'), expect.stringContaining('CN=Test Intermediate CA'), expect.stringContaining('CN=Test Root CA')]);
            expect(r.pathLength).toBe(3);
            expect(r.signatureVerifications).toBe(2);
            expect(r.evaluatedAt).toBe('2027-01-01T00:00:00.000Z');
            expect(r.evaluatedAtSource).toBe('input');
            expect(r.revocationEvidence).toEqual({ crls: 0, ocspResponses: 0, required: false });
            expect(r.diagnostics).toEqual([]);
        });

        it('the IP identity and the purposes table', async () => {
            expect((await verifyCertificateChainTool({ ...BASE, serverName: { ip: '192.0.2.1' } })).valid).toBe(true);
            const wrongName = await verifyCertificateChainTool({ ...BASE, serverName: { host: 'evil.test' } });
            expect(wrongName.valid).toBe(false);
            expect(wrongName.reasons.map((x) => x['code'])).toContain('PKI_REASON_NAME_MISMATCH');
            const wrongPurpose = await verifyCertificateChainTool({ ...BASE, purposes: ['codeSigning'] });
            expect(wrongPurpose.valid).toBe(false);
            expect(wrongPurpose.reasons.map((x) => x['code']).some((c) => String(c).includes('PURPOSE') || String(c).includes('KEY_USAGE'))).toBe(true);
            expect((await verifyCertificateChainTool({ ...BASE, purposes: ['1.3.6.1.5.5.7.3.1'] })).valid).toBe(true);
            // 'any' asks for anyExtendedKeyUsage, which this leaf does not carry: a negative verdict, never an error.
            expect((await verifyCertificateChainTool({ ...BASE, purposes: ['any'] })).valid).toBe(false);
        });

        it('expiry: outside the validity window the verdict is negative, not an error', async () => {
            const r = await verifyCertificateChainTool({ ...BASE, at: '2050-01-01T00:00:00Z' });
            expect(r.valid).toBe(false);
            expect(r.reasons.map((x) => x['code'])).toContain('PKI_REASON_EXPIRED');
            expect(r.evaluatedAt).toBe('2050-01-01T00:00:00.000Z');
        });

        it('no path to the anchors (wrong root) is a negative verdict', async () => {
            const r = await verifyCertificateChainTool({ leaf: LEAF, candidates: [INTER], trustAnchors: [fixtureInput('ed25519.crt.pem')], at: AT });
            expect(r.valid).toBe(false);
            // The partial path explored (leaf, intermediate) is reported; no anchor closes it.
            expect(r.pathLength).toBeLessThanOrEqual(2);
            expect(r.path.map((c) => c.subject)).not.toContainEqual(expect.stringContaining('Test Root CA'));
            expect(r.reasons.length).toBeGreaterThan(0);
        });

        it('revocation from a CRL: revoked leaf refused, good leaf accepted, missing evidence reported when required', async () => {
            const revoked = await verifyCertificateChainTool({ leaf: fixtureInput('revoked.crt.pem'), candidates: [INTER], trustAnchors: [ROOT], crls: [fixtureInput('inter.crl.pem')], requireRevocation: true, at: AT });
            expect(revoked.valid).toBe(false);
            expect(revoked.reasons.map((x) => x['code'])).toContain('PKI_REASON_REVOKED');
            expect(revoked.revocationEvidence).toEqual({ crls: 1, ocspResponses: 0, required: true });
            const good = await verifyCertificateChainTool({ ...BASE, crls: [{ derBase64: fixtureBase64('inter.crl.der') }], requireRevocation: true });
            expect(good.valid).toBe(true);
            const none = await verifyCertificateChainTool({ ...BASE, requireRevocation: true });
            expect(none.valid).toBe(false);
            expect(none.reasons.map((x) => x['code'])).toContain('PKI_REASON_REVOCATION_UNKNOWN');
        });

        it('revocation from an OCSP response (delegated responder), with and without a nonce', async () => {
            const good = await verifyCertificateChainTool({ ...BASE, ocspResponses: [fixtureInput('leaf.ocsp.der')], requireRevocation: true });
            expect(good.valid).toBe(true);
            expect(good.revocationEvidence.ocspResponses).toBe(1);
            const revoked = await verifyCertificateChainTool({ leaf: fixtureInput('revoked.crt.pem'), candidates: [INTER], trustAnchors: [ROOT], ocspResponses: [fixtureInput('revoked.ocsp.der')], requireRevocation: true, at: AT });
            expect(revoked.valid).toBe(false);
            expect(revoked.reasons.map((x) => x['code'])).toContain('PKI_REASON_REVOKED');
            const nonce = await verifyCertificateChainTool({ ...BASE, ocspResponses: [fixtureInput('leaf.ocsp.der')], ocspNonce: '0102030405060708', requireOcspNonce: true, requireRevocation: true });
            expect(nonce.valid).toBe(false);
        });

        it('policy inputs are passed through; the instant falls back to the pin, then the clock', async () => {
            const policy = await verifyCertificateChainTool({ ...BASE, policy: { requireExplicitPolicy: true } });
            expect(policy.valid).toBe(false);
            process.env['PKINATIVE_MCP_AT'] = AT;
            const pinned = await verifyCertificateChainTool({ leaf: LEAF, candidates: [INTER], trustAnchors: [ROOT] });
            expect(pinned).toMatchObject({ valid: true, evaluatedAtSource: 'pinned', evaluatedAt: '2027-01-01T00:00:00.000Z' });
            delete process.env['PKINATIVE_MCP_AT'];
            const clock = await verifyCertificateChainTool({ leaf: LEAF, candidates: [INTER], trustAnchors: [ROOT] });
            expect(clock.evaluatedAtSource).toBe('clock');
        });
    });

    describe('inputs', () => {
        it('reads a bundle of several PEM blocks from one item and from sandbox files', async () => {
            sandbox = await makeSandbox();
            await fs.writeFile(path.join(sandbox, 'bundle.pem'), fixtureText('inter.crt.pem') + fixtureText('root.crt.pem'));
            await fs.copyFile(fixture('leaf.crt.der'), path.join(sandbox, 'leaf.crt.der'));
            await fs.copyFile(fixture('root.crt.pem'), path.join(sandbox, 'root.crt.pem'));
            const r = await verifyCertificateChainTool({ leaf: { path: 'leaf.crt.der' }, candidates: [{ path: 'bundle.pem' }], trustAnchors: [{ path: 'root.crt.pem' }], at: AT });
            expect(r.valid).toBe(true);
            expect(r.pathLength).toBe(3);
            // The intermediate listed as an anchor itself closes the path one link earlier.
            const short = await verifyCertificateChainTool({ leaf: { path: 'leaf.crt.der' }, candidates: [{ path: 'bundle.pem' }], trustAnchors: [{ path: 'bundle.pem' }], at: AT });
            expect(short).toMatchObject({ valid: true, pathLength: 2 });
        });

        it('serverIdentity and nonceBytes helpers', () => {
            expect(serverIdentity(undefined)).toBeUndefined();
            expect(serverIdentity({ host: 'a' })).toEqual({ kind: 'dns', value: 'a' });
            expect(serverIdentity({ ip: '::1' })).toEqual({ kind: 'ip', value: expect.any(Uint8Array) });
            expect(nonceBytes(undefined, 'x')).toBeUndefined();
            expect(nonceBytes('0x0a0b', 'x')).toEqual(new Uint8Array([10, 11]));
            expect(() => nonceBytes('0'.repeat(66), 'ocspNonce')).toThrow(/1 to 32 bytes/);
        });
    });

    describe('refusals (caller mistakes and engine refusals only)', () => {
        it('VALIDATION_ERROR: no anchors, two identities, bad purpose, bad instant, unknown key', async () => {
            expect(await codeOf(verifyCertificateChainTool({ leaf: LEAF, at: AT }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(verifyCertificateChainTool({ ...BASE, trustAnchors: [] }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(verifyCertificateChainTool({ ...BASE, serverName: { host: 'a', ip: '1.1.1.1' } }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(verifyCertificateChainTool({ ...BASE, purposes: ['flying'] }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(verifyCertificateChainTool({ ...BASE, at: 'yesterday' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(verifyCertificateChainTool({ ...BASE, serverName: { ip: 'not-an-ip' } }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(verifyCertificateChainTool({ ...BASE, nope: 1 }))).toBe('VALIDATION_ERROR');
        });

        it('a non-certificate input is the engine refusal; a private key is never read as a certificate', async () => {
            expect(await codeOf(verifyCertificateChainTool({ ...BASE, leaf: fixtureInput('leaf.csr.pem') }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(verifyCertificateChainTool({ ...BASE, crls: [LEAF] }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            const r = await callToolDirect('verify_certificate_chain', { ...BASE, candidates: [fixtureInput('leaf.key.pem')] });
            expect(errorCodeOf(r)).toBe('PKI_PEM_UNEXPECTED_LABEL');
            assertResultClean(r);
        });

        it('LIMIT_CEILING_EXCEEDED for maxPathsExplored above the ceiling; a tight engine limit is a PKI_* refusal', async () => {
            process.env['PKINATIVE_MCP_MAX_PATHS_EXPLORED'] = '5';
            __resetCeilingsForTests();
            expect(await codeOf(verifyCertificateChainTool({ ...BASE, limits: { maxPathsExplored: 6 } }))).toBe('LIMIT_CEILING_EXCEEDED');
            expect((await verifyCertificateChainTool({ ...BASE, limits: { maxPathsExplored: 5 } })).valid).toBe(true);
            const tight = await codeOf(verifyCertificateChainTool({ ...BASE, limits: { maxDepth: 2 } }));
            expect(tight).toMatch(/^PKI_/);
        });
    });

    describe('wire', () => {
        it('summary and text; a negative verdict is not isError; a pinned verdict is cached, a clock one is not', async () => {
            const full = await verifyCertificateChainTool({ ...BASE, crls: [fixtureInput('inter.crl.pem')] });
            expect(chainSummary(full)).toEqual({ valid: true, reasonCodes: [], pathLength: 3, evaluatedAt: '2027-01-01T00:00:00.000Z', revocationEvidence: { crls: 1, ocspResponses: 0, required: false }, diagnosticCount: 0 });
            const neg = await callToolDirect('verify_certificate_chain', { ...BASE, at: '2050-01-01T00:00:00Z', verbosity: 'summary' });
            expect(neg.isError).toBeUndefined();
            expect(neg.structuredContent).toMatchObject({ valid: false, reasonCodes: expect.arrayContaining(['PKI_REASON_EXPIRED']) });
            expect((neg.content[0] as { text: string }).text).toMatch(/^verify_certificate_chain: NOT OK — PKI_REASON_EXPIRED/);
            sandbox = await makeSandbox();
            process.env['PKINATIVE_MCP_CACHE_DIR'] = sandbox;
            await callToolDirect('verify_certificate_chain', BASE);
            expect((await callToolDirect('verify_certificate_chain', BASE))._meta).toMatchObject({ cached: true });
            const clock = { leaf: LEAF, candidates: [INTER], trustAnchors: [ROOT] };
            await callToolDirect('verify_certificate_chain', clock);
            expect(((await callToolDirect('verify_certificate_chain', clock))._meta as { cached?: boolean } | undefined)?.cached).toBeUndefined();
            expect(VERIFY_CERTIFICATE_CHAIN_TOOL.instantInputs).toEqual(['at']);
            expect(VERIFY_CERTIFICATE_CHAIN_TOOL.annotations.readOnlyHint).toBe(true);
        });
    });
});
