/**
 * Tests for `validate_certificate_path` — an ordered path with its link
 * signatures, the structural mode, the failing reasons, projection, sandbox
 * paths, every error code.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { callToolDirect } from '../src/server.js';
import { SIGNATURE_NOT_CHECKED } from '../src/tools/build-certificate-path.js';
import { VALIDATE_CERTIFICATE_PATH_TOOL, validateCertificatePathSummary, validateCertificatePathTool } from '../src/tools/validate-certificate-path.js';
import { assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { AT, fixture, fixtureBase64, fixtureInput, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const LEAF = fixtureInput('leaf.crt.pem');
const INTER = fixtureInput('inter.crt.pem');
const ROOT = [fixtureInput('root.crt.pem')];

describe('validate_certificate_path', () => {
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
        it('validates leaf → intermediate against the root, every link signature verified', async () => {
            const r = await validateCertificatePathTool({ path: [LEAF, { derBase64: fixtureBase64('inter.crt.der') }], trustAnchors: ROOT, at: AT });
            expect(r.valid).toBe(true);
            expect(r.reasons).toEqual([]);
            expect(r.failingReasons).toEqual([]);
            expect(r.signaturesChecked).toBe(true);
            expect(r.signatures).toEqual([
                { index: 0, subject: expect.stringContaining('CN=example.test'), issuer: expect.stringContaining('CN=Test Intermediate CA'), verdict: 'valid' },
                { index: 1, subject: expect.stringContaining('CN=Test Intermediate CA'), issuer: expect.stringContaining('CN=Test Root CA'), verdict: 'valid' },
            ]);
            expect(r.pathLength).toBe(3);
            expect(r.path[2]?.subject).toContain('CN=Test Root CA');
            expect(r.evaluatedAt).toBe('2027-01-01T00:00:00.000Z');
            expect(r.evaluatedAtSource).toBe('input');
            expect(r.diagnostics).toEqual([]);
        });

        it('takes the whole path from one PEM bundle, in order', async () => {
            const r = await validateCertificatePathTool({ path: [{ pem: fixtureText('leaf.crt.pem') + fixtureText('inter.crt.pem') }], trustAnchors: ROOT, at: AT });
            expect(r.valid).toBe(true);
            expect(r.signatures.map((s) => s.verdict)).toEqual(['valid', 'valid']);
        });

        it('fails a path whose link signature is wrong (PKI_REASON_SIGNATURE_INVALID)', async () => {
            const r = await validateCertificatePathTool({ path: [LEAF, fixtureInput('rsa.crt.pem')], trustAnchors: ROOT, at: AT });
            expect(r.valid).toBe(false);
            expect(r.failingReasons.map((x) => x['code'])).toContain('PKI_REASON_SIGNATURE_INVALID');
            expect(r.signatures[0]?.verdict).toBe('invalid');
        });

        it('marks a certificate whose issuer is neither next nor an anchor as not-checked', async () => {
            const r = await validateCertificatePathTool({ path: [LEAF], trustAnchors: ROOT, at: AT });
            expect(r.valid).toBe(false);
            expect(r.signatures).toEqual([{ index: 0, subject: expect.stringContaining('CN=example.test'), issuer: null, verdict: 'not-checked' }]);
            expect(r.failingReasons.map((x) => x['code']).join()).toMatch(/PKI_REASON_/);
        });

        it('checkSignatures:false is a structural verdict that says so', async () => {
            const r = await validateCertificatePathTool({ path: [LEAF, INTER], trustAnchors: ROOT, at: AT, checkSignatures: false });
            expect(r.valid).toBe(false);
            expect(r.reasons.map((x) => x['code'])).toEqual([SIGNATURE_NOT_CHECKED, SIGNATURE_NOT_CHECKED]);
            expect(r.failingReasons).toEqual([]);
            expect(r.signaturesChecked).toBe(false);
            expect(r.signatures.map((s) => s.verdict)).toEqual(['not-checked', 'not-checked']);
            expect(VALIDATE_CERTIFICATE_PATH_TOOL.text(r as unknown as Record<string, unknown>)).toMatch(/^validate_certificate_path: OK — path structure \(signatures NOT checked\) valid/);
            const expired = await validateCertificatePathTool({ path: [LEAF, INTER], trustAnchors: ROOT, at: '2050-01-01', checkSignatures: false });
            expect(expired.failingReasons.map((x) => x['code'])).toContain('PKI_REASON_EXPIRED');
            expect(VALIDATE_CERTIFICATE_PATH_TOOL.text(expired as unknown as Record<string, unknown>)).toMatch(/^validate_certificate_path: NOT OK — .*PKI_REASON_EXPIRED.*\(signatures NOT checked\)/);
        });

        it('applies the policy inputs and allowSha1', async () => {
            const policy = await validateCertificatePathTool({ path: [LEAF, INTER], trustAnchors: ROOT, at: AT, policy: { initialPolicySet: ['2.5.29.32.0'], requireExplicitPolicy: true }, allowSha1: true });
            expect(policy.valid).toBe(false);
            expect(policy.failingReasons.map((x) => x['code']).join()).toMatch(/PKI_REASON_/);
        });
    });

    describe('projection and wire', () => {
        it('summary keeps the scalars only', async () => {
            const r = await validateCertificatePathTool({ path: [LEAF, INTER], trustAnchors: ROOT, at: AT });
            expect(validateCertificatePathSummary(r)).toEqual({
                valid: true,
                reasonCodes: [],
                failingReasonCodes: [],
                pathLength: 3,
                signaturesChecked: true,
                signatureVerdicts: ['valid', 'valid'],
                evaluatedAt: '2027-01-01T00:00:00.000Z',
                diagnosticCount: 0,
            });
        });

        it('a negative verdict is not isError; verbosity and fields project', async () => {
            const result = await callToolDirect('validate_certificate_path', { path: [LEAF, fixtureInput('rsa.crt.pem')], trustAnchors: ROOT, at: AT, verbosity: 'summary', fields: ['valid', 'failingReasonCodes'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ valid: false, failingReasonCodes: expect.arrayContaining(['PKI_REASON_SIGNATURE_INVALID']) });
            expect(result.content[0]).toEqual({ type: 'text', text: expect.stringMatching(/^validate_certificate_path: NOT OK — /) });
            const ok = await callToolDirect('validate_certificate_path', { path: [LEAF, INTER], trustAnchors: ROOT, at: AT });
            expect(ok.content[0]).toEqual({ type: 'text', text: expect.stringMatching(/^validate_certificate_path: OK — path valid at 2027-01-01T00:00:00.000Z; path of 3/) });
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads the path from the sandbox and refuses escapes', async () => {
            sandbox = await makeSandbox();
            for (const f of ['leaf.crt.pem', 'inter.crt.der', 'root.crt.pem']) await fs.copyFile(fixture(f), path.join(sandbox, f));
            const r = await validateCertificatePathTool({ path: [{ path: 'leaf.crt.pem' }, { path: 'inter.crt.der' }], trustAnchors: [{ path: 'root.crt.pem' }], at: AT });
            expect(r.valid).toBe(true);
            expect(await codeOf(validateCertificatePathTool({ path: [{ path: '../leaf.crt.pem' }], trustAnchors: ROOT }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(validateCertificatePathTool({ path: [LEAF], trustAnchors: [{ path: 'missing.crt.pem' }] }))).toBe('INPUT_NOT_FOUND');
            expect(await codeOf(validateCertificatePathTool({ path: [{ path: 'leaf.exe' }], trustAnchors: ROOT }))).toBe('INVALID_EXTENSION');
        });

        it('refuses a path when the sandbox is unset', async () => {
            expect(await codeOf(validateCertificatePathTool({ path: [{ path: 'leaf.crt.pem' }], trustAnchors: ROOT }))).toBe('SECURITY_VIOLATION');
        });
    });

    describe('refusals', () => {
        it.each([
            ['no path', { trustAnchors: ROOT }],
            ['empty path', { path: [], trustAnchors: ROOT }],
            ['no trust anchors', { path: [LEAF] }],
            ['unknown key', { path: [LEAF], trustAnchors: ROOT, candidates: [INTER] }],
            ['two input forms', { path: [{ pem: fixtureText('leaf.crt.pem'), derBase64: fixtureBase64('leaf.crt.der') }], trustAnchors: ROOT }],
            ['checkSignatures not boolean', { path: [LEAF], trustAnchors: ROOT, checkSignatures: 'no' }],
            ['bad instant', { path: [LEAF], trustAnchors: ROOT, at: 'yesterday' }],
            ['nothing', {}],
        ])('VALIDATION_ERROR: %s', async (_what, input) => {
            expect(await codeOf(validateCertificatePathTool(input))).toBe('VALIDATION_ERROR');
        });

        it('PKI_PEM_UNEXPECTED_LABEL for a non-certificate PEM, PKI_* for non-certificate DER', async () => {
            expect(await codeOf(validateCertificatePathTool({ path: [fixtureInput('leaf.csr.pem')], trustAnchors: ROOT }))).toBe('PKI_PEM_UNEXPECTED_LABEL');
            expect(await codeOf(validateCertificatePathTool({ path: [{ derBase64: fixtureBase64('leaf.csr.der') }], trustAnchors: ROOT }))).toMatch(/^PKI_/);
        });

        it('a private key is refused in the path and never echoed', async () => {
            const result = await callToolDirect('validate_certificate_path', { path: [fixtureInput('leaf.key.pem')], trustAnchors: ROOT });
            expect(errorCodeOf(result)).toBe('PKI_PEM_UNEXPECTED_LABEL');
            assertResultClean(result);
        });
    });

    describe('definition', () => {
        it('is a read-only cacheable verdict pinned on at, with two validating examples', () => {
            expect(VALIDATE_CERTIFICATE_PATH_TOOL.kind).toBe('verdict');
            expect(VALIDATE_CERTIFICATE_PATH_TOOL.annotations.readOnlyHint).toBe(true);
            expect(VALIDATE_CERTIFICATE_PATH_TOOL.cacheable).toBe(true);
            expect(VALIDATE_CERTIFICATE_PATH_TOOL.instantInputs).toEqual(['at']);
            expect(VALIDATE_CERTIFICATE_PATH_TOOL.examples?.length).toBe(2);
        });
    });
});
