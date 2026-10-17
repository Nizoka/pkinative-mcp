// Interoperability: what the tools write, a foreign implementation (OpenSSL
// 3.x) reads and verifies — and what OpenSSL wrote (the 42 fixtures), the
// read tools parse. The vitest form of scripts/validate-pki.ts level 1 for
// the interop-critical artefacts. Skipped when a usable OpenSSL is absent,
// unless PKINATIVE_INTEROP_REQUIRED=1 (the gate's `interop` step sets it),
// where an absent tool is a failure.

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { CORPUS_ATTIME } from '../../scripts/lib/pki-corpus.js';
import { COMMANDS, judgeWithOpenssl, opensslMissing, type CommandContext, type CommandId } from '../../scripts/lib/interop-tools.js';
import { callToolDirect, toolNames } from '../../src/server.js';
import { AT, FIXTURE_FILES, PASSWORD, fixture, fixtureInput } from '../_pki-fixtures.js';

const missing = opensslMissing();
const required = process.env['PKINATIVE_INTEROP_REQUIRED'] === '1';
const tools = toolNames();
const has = (name: string): boolean => tools.includes(name);

const NOT_BEFORE = '2026-01-01T00:00:00Z';
const CA_EXT = { basicConstraints: { ca: true, critical: true }, keyUsage: { usages: ['keyCertSign', 'cRLSign'], critical: true } };

interface Produced {
    readonly bytes: Buffer;
    readonly structured: Record<string, unknown>;
}

/** Call an artefact tool and return its DER bytes (the embedded resource blob). */
async function produce(tool: string, args: Record<string, unknown>): Promise<Produced> {
    const r = await callToolDirect(tool, { ...args, encoding: 'der' });
    expect(r.isError, `${tool}: ${(r.content[0] as { text?: string }).text ?? ''}`).not.toBe(true);
    const blob = r.content.find((c) => c.type === 'resource') as { resource?: { blob?: string } } | undefined;
    expect(blob?.resource?.blob, `${tool}: no DER resource`).toBeTypeOf('string');
    return { bytes: Buffer.from(blob?.resource?.blob ?? '', 'base64'), structured: (r.structuredContent ?? {}) as Record<string, unknown> };
}

describe('has OpenSSL when PKINATIVE_INTEROP_REQUIRED=1', () => {
    it('finds a usable OpenSSL 3.x (or the variable is unset)', () => {
        if (required) expect(missing, `OpenSSL is required (PKINATIVE_INTEROP_REQUIRED=1): ${missing ?? ''}`).toBeNull();
    });
});

describe.skipIf(missing !== null)('OpenSSL reads and verifies what the tools write', () => {
    let dir = '';
    beforeAll(() => { dir = mkdtempSync(join(tmpdir(), 'pkinative-mcp-interop-')); });
    afterAll(() => { if (dir) rmSync(dir, { recursive: true, force: true }); });

    const file = (name: string, bytes: Buffer | string): string => {
        const p = join(dir, name);
        writeFileSync(p, bytes);
        return p;
    };
    const openssl = (id: CommandId, ctx: CommandContext): void => {
        const r = judgeWithOpenssl(id, { attime: CORPUS_ATTIME, outFile: join(dir, `${id}.out`), ...ctx });
        expect(r.ok, `openssl ${COMMANDS[id].describe}: ${r.detail}\n${r.run.stderr}`).toBe(true);
    };

    const families = [
        ['ed25519', { key: fixtureInput('ed25519.key.pem') }],
        ['rsa-pkcs1', { key: fixtureInput('rsa.key.pem'), rsaScheme: 'pkcs1' }],
        ['rsa-pss', { key: fixtureInput('rsa.key.pem'), rsaScheme: 'pss' }],
        ['ec', { key: fixtureInput('leaf.key.pem') }],
    ] as const;

    it.skipIf(!has('create_certificate'))('verifies a CA and a leaf for each signature family (verify, -purpose sslserver)', async () => {
        for (const [family, signer] of families) {
            const ca = await produce('create_certificate', { spec: { serialNumber: 1, subject: { C: 'FR', O: 'Interop', CN: `Interop ${family} CA` }, notBefore: NOT_BEFORE, validityDays: 3650, extensions: CA_EXT }, signer });
            const caFile = file(`ca-${family}.crt`, ca.bytes);
            openssl('x509-text', { file: caFile });
            openssl('verify', { file: caFile, caFile });
            const leaf = await produce('create_certificate', {
                spec: { serialNumber: '0x1001', subject: { CN: `${family}.interop.example.test` }, notBefore: NOT_BEFORE, validityDays: 730, extensions: { keyUsage: ['digitalSignature'], extendedKeyUsage: ['serverAuth'], subjectAltName: { dns: [`${family}.interop.example.test`], ip: ['192.0.2.9', '2001:db8::9'] } } },
                issuerCertificate: fixtureInput(ca.bytes.length > 0 ? 'leaf.pub.pem' : 'leaf.pub.pem') && { derBase64: ca.bytes.toString('base64') },
                subjectPublicKey: fixtureInput(family === 'ec' ? 'ed25519.crt.pem' : 'leaf.pub.pem'),
                signer,
            });
            expect(leaf.structured['summary']).toMatchObject({ signatureVerified: true, selfSigned: false });
            openssl('verify-sslserver', { file: file(`leaf-${family}.crt`, leaf.bytes), caFile });
        }
    }, 120_000);

    it.skipIf(!has('create_csr'))('verifies the self-signature of the requests (req -verify)', async () => {
        for (const [family, signer] of families) {
            const csr = await produce('create_csr', { spec: { subject: { CN: `${family}.req.example.test` }, extensions: { subjectAltName: { dns: [`${family}.req.example.test`] } } }, signer });
            openssl('req-verify', { file: file(`${family}.csr`, csr.bytes) });
        }
    }, 60_000);

    it.skipIf(!has('sign_cms'))('verifies the attached and detached CMS signatures (cms -verify)', async () => {
        const content = fixtureInput('content.txt');
        const contentFile = fixture('content.txt');
        for (const detached of [false, true]) {
            const p7 = await produce('sign_cms', { content: { base64: 'derBase64' in content ? content.derBase64 : '' }, detached, certificate: fixtureInput('leaf.crt.pem'), chain: [fixtureInput('inter.crt.pem')], signer: { key: fixtureInput('leaf.key.pem') }, signingTime: AT });
            const p7File = file(`signed-${detached ? 'detached' : 'attached'}.p7s`, p7.bytes);
            if (detached) openssl('cms-verify-detached', { file: p7File, caFile: fixture('root.crt.pem'), content: contentFile });
            else openssl('cms-verify-attached', { file: p7File, caFile: fixture('root.crt.pem') });
        }
    }, 60_000);

    it.skipIf(!has('create_ocsp_request'))('reads the OCSP request (ocsp -req_text names the serial)', async () => {
        const req = await produce('create_ocsp_request', { certificate: fixtureInput('leaf.crt.pem'), issuer: fixtureInput('inter.crt.pem'), hashAlgorithm: 'SHA-256', nonce: '0102030405060708' });
        const r = judgeWithOpenssl('ocsp-req-text', { file: file('leaf.orq', req.bytes) });
        expect(r.ok, r.detail).toBe(true);
        expect(r.run.stdout).toMatch(/Serial Number: 1001/);
    });

    it.skipIf(!has('create_timestamp_request'))('reads the time-stamp request (ts -query -text prints the nonce)', async () => {
        const content = fixtureInput('content.txt');
        const tsq = await produce('create_timestamp_request', { data: { base64: 'derBase64' in content ? content.derBase64 : '' }, hashAlgorithm: 'SHA-256', nonce: '42' });
        const r = judgeWithOpenssl('ts-query-text', { file: file('content.tsq', tsq.bytes) });
        expect(r.ok, r.detail).toBe(true);
        expect(r.run.stdout).toMatch(/Nonce: 0x2A/);
    });
});

// ── The reverse direction: OpenSSL wrote the fixtures, the read tools parse them ──

type Reader = { readonly tool: string; readonly args: (name: string) => Record<string, unknown> };

/** Which read tool parses a fixture, by its name; null for the content file. */
export function readerFor(name: string): Reader | null {
    const input = (): Record<string, unknown> => ({ ...fixtureInput(name) });
    if (name === 'content.txt') return null;
    if (/\.crt\.(pem|der)$/.test(name)) return { tool: 'inspect_certificate', args: () => ({ certificate: input() }) };
    if (/\.csr\.(pem|der)$/.test(name)) return { tool: 'inspect_csr', args: () => ({ request: input() }) };
    if (/\.crl\.(pem|der)$/.test(name)) return { tool: 'inspect_crl', args: () => ({ crl: input() }) };
    if (/\.key\.(pem|der)$|\.key\.enc\.pem$/.test(name)) return { tool: 'inspect_private_key', args: () => ({ key: input() }) };
    if (name.endsWith('.p12')) return { tool: 'inspect_pkcs12', args: () => ({ pkcs12: input() }) };
    if (name.endsWith('.p7s')) return { tool: 'inspect_cms', args: () => ({ signedData: input() }) };
    if (name.endsWith('.ocsp.der')) return { tool: 'inspect_ocsp_response', args: () => ({ response: input() }) };
    if (name.endsWith('.tsr') || name.endsWith('.tst')) return { tool: 'inspect_timestamp', args: () => ({ input: input() }) };
    if (name.endsWith('.pub.pem') || name.endsWith('.ocsp-req.der') || name.endsWith('.tsq')) return { tool: 'decode_asn1', args: () => ({ input: input() }) };
    return null;
}

/** Fixtures a read tool refuses by doctrine, with the codes the refusal may carry. */
const DOCUMENTED_REFUSALS: Readonly<Record<string, readonly string[]>> = {
    'legacy.p12': ['PKI_KEY_ENCRYPTION_UNSUPPORTED', 'PKI_KEY_MAC_UNSUPPORTED'],
};

describe('the read tools parse every OpenSSL-made fixture', () => {
    const readable = FIXTURE_FILES.map((name) => [name, readerFor(name)] as const).filter((x): x is readonly [string, Reader] => x[1] !== null);

    it('maps every fixture but content.txt to a read tool', () => {
        expect(FIXTURE_FILES).toHaveLength(42);
        expect(readable.map(([n]) => n)).toEqual(FIXTURE_FILES.filter((n) => n !== 'content.txt'));
    });

    for (const [name, reader] of readable) {
        it.skipIf(!has(reader.tool))(`${name} → ${reader.tool}`, async () => {
            const r = await callToolDirect(reader.tool, reader.args(name));
            const allowed = DOCUMENTED_REFUSALS[name];
            const code = (r._meta as { error?: { code?: string } } | undefined)?.error?.code;
            if (r.isError === true) {
                expect(allowed, `${name}: ${(r.content[0] as { text?: string }).text ?? ''}`).toBeDefined();
                expect(allowed, name).toContain(code);
            } else {
                expect(r.structuredContent).toBeTypeOf('object');
            }
        });
    }

    it.skipIf(!has('open_pkcs12'))('refuses legacy.p12 as a negative verdict (the documented refusal) even with its password, and opens leaf.p12', async () => {
        const legacy = await callToolDirect('open_pkcs12', { pkcs12: fixtureInput('legacy.p12'), password: PASSWORD });
        const verdict = legacy.structuredContent as { valid?: boolean; reasons?: Array<{ code: string }> } | undefined;
        if (legacy.isError === true) {
            expect(DOCUMENTED_REFUSALS['legacy.p12']).toContain((legacy._meta as { error?: { code?: string } }).error?.code);
        } else {
            expect(verdict?.valid).toBe(false);
            expect(verdict?.reasons?.map((r) => r.code)).toEqual(expect.arrayContaining(['PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED']));
        }
        const ok = await callToolDirect('open_pkcs12', { pkcs12: fixtureInput('leaf.p12'), password: PASSWORD });
        expect(ok.isError, (ok.content[0] as { text?: string }).text).not.toBe(true);
        expect((ok.structuredContent as { valid?: boolean }).valid).toBe(true);
    });
});
