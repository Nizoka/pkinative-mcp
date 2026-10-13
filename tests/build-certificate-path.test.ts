/**
 * Tests for `build_certificate_path` — path discovery without signatures:
 * found / not found, the structural reasons, purposes and policy, projection,
 * sandbox paths, every error code.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { BUILD_CERTIFICATE_PATH_TOOL, buildCertificatePathSummary, buildCertificatePathTool, SIGNATURE_NOT_CHECKED } from '../src/tools/build-certificate-path.js';
import { assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { AT, fixture, fixtureBase64, fixtureInput, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const LEAF = fixtureInput('leaf.crt.pem');
const INTER = [fixtureInput('inter.crt.pem')];
const ROOT = [fixtureInput('root.crt.pem')];

describe('build_certificate_path', () => {
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

    describe('discovery', () => {
        it('finds leaf → intermediate → root without checking a signature', async () => {
            const r = await buildCertificatePathTool({ leaf: LEAF, candidates: INTER, trustAnchors: ROOT, at: AT, purposes: ['clientAuth'] });
            expect(r.found).toBe(true);
            expect(r.valid).toBe(false);
            expect(r.reasons.map((x) => x['code'])).toEqual([SIGNATURE_NOT_CHECKED, SIGNATURE_NOT_CHECKED]);
            expect(r.structuralReasons).toEqual([]);
            expect(r.path.map((c) => c.subject)).toEqual([
                expect.stringContaining('CN=example.test'),
                expect.stringContaining('CN=Test Intermediate CA'),
                expect.stringContaining('CN=Test Root CA'),
            ]);
            expect(r.pathLength).toBe(3);
            expect(r.explored).toBeGreaterThan(0);
            expect(r.signaturesChecked).toBe(false);
            expect(r.evaluatedAt).toBe('2027-01-01T00:00:00.000Z');
            expect(r.evaluatedAtSource).toBe('input');
            expect(r.diagnostics).toEqual([]);
        });

        it('reports the leaf alone with PKI_REASON_NO_TRUST_ANCHOR when no candidate links to an anchor', async () => {
            const r = await buildCertificatePathTool({ leaf: LEAF, trustAnchors: ROOT, at: AT });
            expect(r.found).toBe(false);
            expect(r.structuralReasons.map((x) => x['code'])).toEqual(['PKI_REASON_NO_TRUST_ANCHOR']);
            expect(r.reasons.map((x) => x['code'])).toContain(SIGNATURE_NOT_CHECKED);
            expect(r.pathLength).toBe(1);
            const wrongAnchor = await buildCertificatePathTool({ leaf: LEAF, candidates: INTER, trustAnchors: [fixtureInput('ed25519.crt.pem')], at: AT });
            expect(wrongAnchor.found).toBe(false);
        });

        it('applies the instant, the purposes and the policy inputs', async () => {
            const expired = await buildCertificatePathTool({ leaf: LEAF, candidates: INTER, trustAnchors: ROOT, at: '2050-01-01' });
            expect(expired.found).toBe(false);
            expect(expired.structuralReasons.map((x) => x['code']).join()).toMatch(/PKI_REASON_/);
            // The engine's path builder takes the purposes to steer discovery but does not judge the leaf's EKU
            // (verify_certificate_chain does: PKI_REASON_PURPOSE_NOT_PERMITTED); the inputs are accepted and passed through.
            const purpose = await buildCertificatePathTool({ leaf: LEAF, candidates: INTER, trustAnchors: ROOT, at: AT, purposes: ['codeSigning', '1.3.6.1.5.5.7.3.8'] });
            expect(purpose.pathLength).toBe(3);
            // The policy inputs likewise (the test PKI carries no certificatePolicies, so discovery is unchanged).
            const policy = await buildCertificatePathTool({ leaf: LEAF, candidates: INTER, trustAnchors: ROOT, at: AT, policy: { initialPolicySet: ['2.5.29.32.0'], requireExplicitPolicy: true, inhibitPolicyMapping: true, inhibitAnyPolicy: true } });
            expect(policy.pathLength).toBe(3);
        });

        it('takes anchors and candidates from one PEM bundle and from DER', async () => {
            const bundle = { pem: fixtureText('root.crt.pem') + fixtureText('inter.crt.pem') };
            const r = await buildCertificatePathTool({ leaf: { derBase64: fixtureBase64('leaf.crt.der') }, candidates: [bundle], trustAnchors: ROOT, at: AT });
            expect(r.found).toBe(true);
            expect(r.pathLength).toBe(3);
            // The intermediate trusted directly: the path stops at it.
            const short = await buildCertificatePathTool({ leaf: LEAF, trustAnchors: [bundle], at: AT });
            expect(short.found).toBe(true);
            expect(short.pathLength).toBe(2);
        });

        it('falls back to the operator pin, then the clock', async () => {
            process.env['PKINATIVE_MCP_AT'] = AT;
            try {
                const pinned = await buildCertificatePathTool({ leaf: LEAF, candidates: INTER, trustAnchors: ROOT });
                expect(pinned.evaluatedAtSource).toBe('pinned');
                expect(pinned.evaluatedAt).toBe('2027-01-01T00:00:00.000Z');
            } finally {
                delete process.env['PKINATIVE_MCP_AT'];
            }
            const clock = await buildCertificatePathTool({ leaf: LEAF, candidates: INTER, trustAnchors: ROOT, at: 'now' });
            expect(clock.evaluatedAtSource).toBe('clock');
        });
    });

    describe('projection and wire', () => {
        it('summary keeps the scalars only', async () => {
            const r = await buildCertificatePathTool({ leaf: LEAF, candidates: INTER, trustAnchors: ROOT, at: AT });
            expect(buildCertificatePathSummary(r)).toEqual({
                found: true,
                valid: false,
                reasonCodes: [SIGNATURE_NOT_CHECKED, SIGNATURE_NOT_CHECKED],
                structuralReasonCodes: [],
                pathLength: 3,
                explored: r.explored,
                signaturesChecked: false,
                evaluatedAt: '2027-01-01T00:00:00.000Z',
                diagnosticCount: 0,
            });
        });

        it('a negative result is not isError; verbosity and fields project', async () => {
            const result = await callToolDirect('build_certificate_path', { leaf: LEAF, trustAnchors: ROOT, at: AT, verbosity: 'summary', fields: ['found', 'structuralReasonCodes'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ found: false, structuralReasonCodes: ['PKI_REASON_NO_TRUST_ANCHOR'] });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringMatching(/^build_certificate_path: NOT OK — PKI_REASON_NO_TRUST_ANCHOR/) });
            const ok = await callToolDirect('build_certificate_path', { leaf: LEAF, candidates: INTER, trustAnchors: ROOT, at: AT });
            expect(ok.content[0]).toEqual({ type: 'text', text: expect.stringMatching(/^build_certificate_path: OK — path of 3 found \(signatures NOT checked/) });
            expect((ok.structuredContent as Record<string, unknown>)['found']).toBe(true);
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads the certificates from the sandbox and refuses escapes', async () => {
            sandbox = await makeSandbox();
            for (const f of ['leaf.crt.pem', 'inter.crt.pem', 'root.crt.der']) await fs.copyFile(fixture(f), path.join(sandbox, f));
            const r = await buildCertificatePathTool({ leaf: { path: 'leaf.crt.pem' }, candidates: [{ path: 'inter.crt.pem' }], trustAnchors: [{ path: 'root.crt.der' }], at: AT });
            expect(r.found).toBe(true);
            expect(await codeOf(buildCertificatePathTool({ leaf: { path: '../leaf.crt.pem' }, trustAnchors: ROOT }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(buildCertificatePathTool({ leaf: LEAF, trustAnchors: [{ path: 'missing.crt.pem' }] }))).toBe('INPUT_NOT_FOUND');
            expect(await codeOf(buildCertificatePathTool({ leaf: { path: 'leaf.exe' }, trustAnchors: ROOT }))).toBe('INVALID_EXTENSION');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(buildCertificatePathTool({ leaf: { path: 'leaf.crt.pem' }, trustAnchors: ROOT }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it.each([
            ['no trust anchors', { leaf: LEAF }],
            ['empty trust anchors', { leaf: LEAF, trustAnchors: [] }],
            ['unknown key', { leaf: LEAF, trustAnchors: ROOT, bogus: 1 }],
            ['two input forms', { leaf: { pem: fixtureText('leaf.crt.pem'), derBase64: fixtureBase64('leaf.crt.der') }, trustAnchors: ROOT }],
            ['crls is not an input here', { leaf: LEAF, trustAnchors: ROOT, crls: [fixtureInput('inter.crl.pem')] }],
            ['requireRevocation is not an input here', { leaf: LEAF, trustAnchors: ROOT, requireRevocation: true }],
            ['bad policy OID', { leaf: LEAF, trustAnchors: ROOT, policy: { initialPolicySet: ['x'] } }],
            ['unknown purpose', { leaf: LEAF, trustAnchors: ROOT, purposes: ['flying'] }],
            ['bad instant', { leaf: LEAF, trustAnchors: ROOT, at: '2027-02-31' }],
            ['nothing', {}],
        ])('VALIDATION_ERROR: %s', async (_what, input) => {
            expect(await codeOf(buildCertificatePathTool(input))).toBe('VALIDATION_ERROR');
        });

        it('PKI_PEM_UNEXPECTED_LABEL for a non-certificate PEM, PKI_* for non-certificate DER, LIMIT_CEILING_EXCEEDED above the ceiling', async () => {
            expect(await codeOf(buildCertificatePathTool({ leaf: fixtureInput('leaf.csr.pem'), trustAnchors: ROOT }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(buildCertificatePathTool({ leaf: LEAF, trustAnchors: [fixtureInput('inter.crl.pem')] }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(buildCertificatePathTool({ leaf: { derBase64: fixtureBase64('leaf.csr.der') }, trustAnchors: ROOT }))).toMatch(/^PKI_/);
            expect(await codeOf(buildCertificatePathTool({ leaf: LEAF, trustAnchors: ROOT, limits: { maxPathsExplored: 1_000_000 } }))).toBe('LIMIT_CEILING_EXCEEDED');
        });

        it('a private key is refused as a leaf and never echoed', async () => {
            const result = await callToolDirect('build_certificate_path', { leaf: fixtureInput('leaf.key.pem'), trustAnchors: ROOT });
            expect(errorCodeOf(result)).toBe('PKI_PEM_UNEXPECTED_LABEL');
            assertResultClean(result);
        });
    });

    describe('definition', () => {
        it('is a read-only cacheable verdict pinned on at, with two validating examples', () => {
            expect(BUILD_CERTIFICATE_PATH_TOOL.kind).toBe('verdict');
            expect(BUILD_CERTIFICATE_PATH_TOOL.annotations.readOnlyHint).toBe(true);
            expect(BUILD_CERTIFICATE_PATH_TOOL.cacheable).toBe(true);
            expect(BUILD_CERTIFICATE_PATH_TOOL.instantInputs).toEqual(['at']);
            expect(BUILD_CERTIFICATE_PATH_TOOL.examples?.length).toBe(2);
        });
    });
});
