/**
 * Tests for `inspect_pkcs12` — descriptions without a password (MAC kind,
 * SafeContents, bags), the MAC check and the opening with one, every error
 * code, projection, path inputs, and the secret-leak matrix: no key byte
 * from any bag (not even an unencrypted keyBag), no password, anywhere.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { ToolError } from '../src/errors.js';
import { callToolDirect } from '../src/server.js';
import { inspectPkcs12, inspectPkcs12Summary, INSPECT_PKCS12_TOOL } from '../src/tools/inspect-pkcs12.js';
import { assertNoSecret, assertResultClean, codeOf, errorCodeOf } from './_pki-assert.js';
import { fixture, fixtureBase64, fixtureInput, fixtureText, PASSWORD } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

const WRONG = 'definitely-wrong';
const KEY_FIXTURES = ['leaf.key.pem', 'leaf.key.der', 'rsa.key.pem', 'ed25519.key.pem', 'leaf.key.enc.pem', 'rsa.key.enc.pem'] as const;
const P12_FIXTURES = ['leaf.p12', 'rsa.p12', 'ed25519.p12', 'legacy.p12', 'plain-keybag.p12', 'nomac.p12', 'certs-only.p12'] as const;
const PBES2 = 'PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC)';

const p12 = (name: string): { derBase64: string } => ({ derBase64: fixtureBase64(name) });

describe('inspect_pkcs12', () => {
    let sandbox: string | null = null;

    beforeAll(() => {
        delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
        delete process.env['PKINATIVE_MCP_CACHE_DIR'];
        delete process.env['PKINATIVE_MCP_PASSWORD'];
    });

    afterEach(async () => {
        delete process.env['PKINATIVE_MCP_PASSWORD'];
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    describe('descriptions (no password)', () => {
        it('describes leaf.p12: PBMAC1, one encrypted SafeContents, one shrouded key bag', async () => {
            const r = await inspectPkcs12({ pkcs12: p12('leaf.p12') });
            expect(r.version).toBe(3);
            expect(r.mac).toMatchObject({ kind: 'pbmac1', iterations: 2048, pbmac1: { prf: 'SHA-256', hmac: 'SHA-256', keyLength: 32 } });
            expect(r.contents).toHaveLength(2);
            expect(r.contents[0]).toEqual({ path: 'authSafe[0]', encrypted: true, encryption: { scheme: PBES2, algorithm: '1.2.840.113549.1.5.13', pbes2: expect.objectContaining({ iterations: 2048, prf: 'SHA-256', keyBits: 256 }) }, bags: [] });
            expect(r.contents[1]).toMatchObject({ path: 'authSafe[1]', encrypted: false, encryption: null, bags: [{ path: 'authSafe[1].bags[0]', kind: 'pkcs8ShroudedKeyBag', friendlyName: 'test leaf', key: { format: 'encrypted-pkcs8', encryption: { scheme: PBES2 } } }] });
            expect(r.contents[1]?.bags[0]?.localKeyId).toMatch(/^[0-9a-f]+$/);
            expect(r.bagCount).toBe(1);
            expect(r.sizeBytes).toBeGreaterThan(1000);
            expect(r.macVerified).toBeUndefined();
            expect(r.opened).toBeUndefined();
            expect(r.diagnostics).toEqual([]);
            assertResultClean(r);
        });

        it('names a legacy MAC and a legacy cipher without opening anything', async () => {
            const r = await inspectPkcs12({ pkcs12: p12('legacy.p12') });
            expect(r.mac?.kind).toBe('pkcs12-kdf');
            expect(r.mac?.pbmac1).toBeUndefined();
            expect(r.contents[0]).toMatchObject({ encrypted: true, encryption: { scheme: 'pbeWithSHAAnd40BitRC2-CBC' } });
            expect(r.contents[0]?.encryption?.pbes2).toBeUndefined();
            expect(r.contents[1]?.bags[0]?.kind).toBe('pkcs8ShroudedKeyBag');
            assertResultClean(r);
        });

        it('reports a file without a MAC, and a plain keyBag by its description only', async () => {
            const nomac = await inspectPkcs12({ pkcs12: p12('nomac.p12') });
            expect(nomac.mac).toBeNull();
            expect(nomac.contents[0]?.bags[0]).toMatchObject({ kind: 'certBag', certificate: { subject: expect.stringContaining('CN=Test Intermediate CA'), issuer: expect.stringContaining('CN=Test Root CA') } });
            const plain = await inspectPkcs12({ pkcs12: p12('plain-keybag.p12') });
            expect(plain.contents.map((c) => c.bags.map((b) => b.kind))).toEqual([['certBag'], ['keyBag']]);
            expect(plain.contents[1]?.bags[0]?.key).toEqual({ format: 'pkcs8', version: 0, kind: 'ec', curve: 'P-256', algorithm: '1.2.840.10045.2.1', attributes: [], publicKey: false });
            expect(plain.bagCount).toBe(2);
            assertResultClean(nomac);
            assertResultClean(plain);
        });

        it('certs-only.p12 holds one encrypted SafeContents and no key bag', async () => {
            const r = await inspectPkcs12({ pkcs12: p12('certs-only.p12') });
            expect(r.contents).toHaveLength(1);
            expect(r.contents[0]?.encrypted).toBe(true);
            expect(r.bagCount).toBe(0);
        });
    });

    describe('with a password', () => {
        it('verifies the MAC and opens every SafeContents, bags as allow-list views', async () => {
            const r = await inspectPkcs12({ pkcs12: p12('leaf.p12'), password: PASSWORD });
            expect(r.macVerified).toBe(true);
            expect(r.opened).toHaveLength(2);
            expect(r.opened?.[0]).toMatchObject({ path: 'authSafe[0]', encrypted: true });
            expect(r.opened?.[0]?.bags.map((b) => [b.kind, b.certificate && 'subject' in b.certificate ? b.certificate.subject : null, b.friendlyName ?? null])).toEqual([
                ['certBag', 'CN=example.test,O=pkinative-cli test,C=FR', 'test leaf'],
                ['certBag', 'CN=Test Intermediate CA,O=pkinative-cli test,C=FR', null],
            ]);
            expect(r.opened?.[1]?.bags[0]).toMatchObject({ kind: 'pkcs8ShroudedKeyBag', key: { format: 'encrypted-pkcs8' } });
            expect(r.bagCount).toBe(3);
            assertResultClean(r);
        });

        it('a wrong password on a file with nothing encrypted is a report: macVerified false, not an error', async () => {
            const result = await callToolDirect('inspect_pkcs12', { pkcs12: p12('plain-keybag.p12'), password: WRONG });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toMatchObject({ macVerified: false, opened: [{ bags: [{ kind: 'certBag' }] }, { bags: [{ kind: 'keyBag', key: { format: 'pkcs8', kind: 'ec' } }] }] });
            expect((result.content[0] as { text: string }).text).toContain('MAC MISMATCH');
            expect(JSON.stringify(result)).not.toContain(WRONG);
            assertResultClean(result);
        });

        it('a wrong password on an encrypted SafeContents is PKI_CRYPTO_DECRYPTION_FAILED, never echoed', async () => {
            const result = await callToolDirect('inspect_pkcs12', { pkcs12: p12('leaf.p12'), password: WRONG });
            expect(errorCodeOf(result)).toBe('PKI_CRYPTO_DECRYPTION_FAILED');
            expect(JSON.stringify(result)).not.toContain(WRONG);
            expect((result._meta?.['error'] as { data?: { remedy?: string } }).data?.remedy).toContain('password');
            assertResultClean(result);
        });

        it('a file without a MAC opens with macVerified null', async () => {
            const r = await inspectPkcs12({ pkcs12: p12('nomac.p12'), password: PASSWORD });
            expect(r.macVerified).toBeNull();
            expect(r.opened?.[0]?.bags[0]?.kind).toBe('certBag');
        });

        it('a legacy MAC is refused with PKI_KEY_MAC_UNSUPPORTED and the conversion remedy', async () => {
            try {
                await inspectPkcs12({ pkcs12: p12('legacy.p12'), password: PASSWORD });
                expect.unreachable();
            } catch (e) {
                expect(e).toBeInstanceOf(ToolError);
                expect((e as ToolError).code).toBe('PKI_KEY_MAC_UNSUPPORTED');
                expect((e as ToolError).data).toMatchObject({ remedy: expect.stringContaining('pbmac1_pbkdf2') });
            }
        });

        it('takes the password from PKINATIVE_MCP_PASSWORD, and refuses two sources', async () => {
            process.env['PKINATIVE_MCP_PASSWORD'] = PASSWORD;
            expect((await inspectPkcs12({ pkcs12: p12('leaf.p12') })).macVerified).toBe(true);
            expect(await codeOf(inspectPkcs12({ pkcs12: p12('leaf.p12'), password: PASSWORD }))).toBe('VALIDATION_ERROR');
        });

        it('limits.maxPkcs12KdfIterations bounds the PBKDF2 work of the whole file', async () => {
            expect(await codeOf(inspectPkcs12({ pkcs12: p12('leaf.p12'), limits: { maxPkcs12KdfIterations: 1000 } }))).toBe('PKI_LIMIT_EXCEEDED');
        });
    });

    describe('projection', () => {
        it('summary keeps the scalars only', async () => {
            const plain = inspectPkcs12Summary(await inspectPkcs12({ pkcs12: p12('leaf.p12') }));
            expect(plain).toEqual({ version: 3, macKind: 'pbmac1', contentCount: 2, bagCount: 1, bagKinds: ['pkcs8ShroudedKeyBag'], diagnosticCount: 0 });
            const opened = inspectPkcs12Summary(await inspectPkcs12({ pkcs12: p12('leaf.p12'), password: PASSWORD }));
            expect(opened).toEqual({ version: 3, macKind: 'pbmac1', macVerified: true, contentCount: 2, bagCount: 3, bagKinds: ['certBag', 'pkcs8ShroudedKeyBag'], diagnosticCount: 0 });
            expect(inspectPkcs12Summary(await inspectPkcs12({ pkcs12: p12('nomac.p12') }))).toMatchObject({ macKind: null, bagKinds: ['certBag'] });
        });

        it('fields project over the wire and the text line describes the file', async () => {
            const result = await callToolDirect('inspect_pkcs12', { pkcs12: p12('leaf.p12'), verbosity: 'summary', fields: ['macKind', 'nope'] });
            expect(result.isError).toBeUndefined();
            expect(result.structuredContent).toEqual({ macKind: 'pbmac1' });
            expect(result._meta).toEqual({ unmatchedFields: ['nope'], availableFields: expect.arrayContaining(['bagKinds', 'contentCount']) });
            expect(result.content[0]).toEqual({ type: 'text', text: `inspect_pkcs12: PKCS#12 v3, MAC pbmac1 (2048 iteration(s)); 2 SafeContents (authSafe[0]: encrypted, ${PBES2}; authSafe[1]: 1 bag(s)), ${(await inspectPkcs12({ pkcs12: p12('leaf.p12') })).sizeBytes} bytes, 0 diagnostic(s).` });
            const full = await callToolDirect('inspect_pkcs12', { pkcs12: p12('leaf.p12'), password: PASSWORD, fields: ['opened.bags.kind'] });
            expect(full.structuredContent).toEqual({ opened: [{ bags: [{ kind: 'certBag' }, { kind: 'certBag' }] }, { bags: [{ kind: 'pkcs8ShroudedKeyBag' }] }] });
            expect((full.content[0] as { text: string }).text).toContain('MAC verified; 2 SafeContents');
            assertResultClean(full);
        });
    });

    describe('path inputs (sandbox)', () => {
        it('reads a .p12 from the sandbox and refuses escapes', async () => {
            sandbox = await makeSandbox();
            await fs.copyFile(fixture('leaf.p12'), path.join(sandbox, 'leaf.p12'));
            const r = await inspectPkcs12({ pkcs12: { path: 'leaf.p12' }, password: PASSWORD });
            expect(r.macVerified).toBe(true);
            expect(await codeOf(inspectPkcs12({ pkcs12: { path: '../leaf.p12' } }))).toBe('SECURITY_VIOLATION');
            expect(await codeOf(inspectPkcs12({ pkcs12: { path: 'missing.p12' } }))).toBe('INPUT_NOT_FOUND');
        });
    });

    describe('refusals', () => {
        it('VALIDATION_ERROR: unknown key, two input forms, empty password, nothing', async () => {
            expect(await codeOf(inspectPkcs12({ pkcs12: p12('leaf.p12'), bogus: 1 }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(inspectPkcs12({ pkcs12: { derBase64: fixtureBase64('leaf.p12'), pem: fixtureText('leaf.crt.pem') } }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(inspectPkcs12({ pkcs12: p12('leaf.p12'), password: '' }))).toBe('VALIDATION_ERROR');
            expect(await codeOf(inspectPkcs12({}))).toBe('VALIDATION_ERROR');
        });

        it('a certificate or a private key is not a PKCS#12, and a key is never echoed', async () => {
            expect(await codeOf(inspectPkcs12({ pkcs12: { derBase64: fixtureBase64('leaf.crt.der') } }))).toMatch(/^PKI_/);
            const result = await callToolDirect('inspect_pkcs12', { pkcs12: fixtureInput('leaf.key.pem') });
            expect(errorCodeOf(result)).toMatch(/^PKI_/);
            assertResultClean(result);
        });

        it('ber is accepted as an encoding rule; strict escalates nothing on a clean file', async () => {
            const r = await inspectPkcs12({ pkcs12: p12('leaf.p12'), encodingRules: 'ber', strict: true });
            expect(r.version).toBe(3);
        });
    });

    describe('secret-leak matrix (every fixture, every password, every verbosity)', () => {
        it('never writes a key byte, a bag value or the password anywhere', async () => {
            const stderr: string[] = [];
            const spy = vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: unknown) => { stderr.push(String(chunk)); return true; }) as typeof process.stderr.write);
            try {
                for (const name of [...P12_FIXTURES, ...KEY_FIXTURES]) {
                    for (const password of [PASSWORD, WRONG, undefined]) {
                        for (const verbosity of ['full', 'summary']) {
                            const result = await callToolDirect('inspect_pkcs12', { pkcs12: fixtureInput(name), verbosity, ...(password !== undefined ? { password } : {}) });
                            assertResultClean(result, `${name} / ${password ?? 'no password'} / ${verbosity}`);
                            expect(JSON.stringify(result)).not.toContain(WRONG);
                        }
                    }
                }
            } finally {
                spy.mockRestore();
            }
            assertNoSecret(stderr.join(''), 'stderr');
        });
    });

    describe('definition', () => {
        it('is a read-only, cacheable read tool with two examples', () => {
            expect(INSPECT_PKCS12_TOOL.kind).toBe('read');
            expect(INSPECT_PKCS12_TOOL.annotations.readOnlyHint).toBe(true);
            expect(INSPECT_PKCS12_TOOL.cacheable).toBe(true);
            expect(INSPECT_PKCS12_TOOL.examples?.length).toBe(2);
        });
    });
});
