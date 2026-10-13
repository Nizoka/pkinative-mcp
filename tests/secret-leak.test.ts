/**
 * Secret-leak sweep: every tool × every key-bearing fixture × every password
 * situation, and no result, no stderr line, no cache file and no error
 * message may carry a needle of `tests/_secrets.ts` (the PEM bodies, the DER
 * as hex / base64, the private scalars in every encoding, the encrypted-key
 * bodies, the password).
 *
 * Three campaigns:
 *   1. the tools that take a key, a PKCS#12 file or a signer, driven on every
 *      key fixture with no password, the right one, a wrong one, and the
 *      operator variable (PKINATIVE_MCP_PASSWORD) instead of the input;
 *   2. every PKI input of every tool fed a private key or a PKCS#12 file —
 *      the refusal names the problem, never the bytes;
 *   3. with the cache enabled: no file under PKINATIVE_MCP_CACHE_DIR holds a
 *      needle after the whole run, and no secret-bearing call was cached.
 */
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { prepareSandbox, removeSandbox } from '../scripts/helpers/io.js';
import { PASSWORD_ENV } from '../src/secrets.js';
import { callToolDirect, ensureEngineReady, listToolsPayload, toolDefinition } from '../src/server.js';
import { assertNoSecret, assertResultClean, errorCodeOf } from './_pki-assert.js';
import { AT, fixtureInput, PASSWORD } from './_pki-fixtures.js';
import { SECRET_NEEDLES } from './_secrets.js';

const KEY_FIXTURES = ['leaf.key.pem', 'leaf.key.der', 'leaf.key.enc.pem', 'rsa.key.pem', 'rsa.key.enc.pem', 'ed25519.key.pem'] as const;
const P12_FIXTURES = ['leaf.p12', 'rsa.p12', 'ed25519.p12', 'certs-only.p12', 'legacy.p12', 'nomac.p12', 'plain-keybag.p12'] as const;
const WRONG = 'definitely-not-the-password';
const LEAF = fixtureInput('leaf.crt.pem');

type Pw = { readonly label: string; readonly input?: string; readonly env?: string };
const PASSWORDS: readonly Pw[] = [
    { label: 'no password' },
    { label: 'right password (input)', input: PASSWORD },
    { label: 'wrong password (input)', input: WRONG },
    { label: 'right password (env)', env: PASSWORD },
    { label: 'wrong password (env)', env: WRONG },
];

/** Captured stderr / console output of the run. */
const captured: string[] = [];
const originalStderrWrite = process.stderr.write.bind(process.stderr);
const originalWarn = console.warn;
const originalError = console.error;

let sandbox: string | null = null;
let cacheDir: string;

beforeAll(async () => {
    await ensureEngineReady();
    sandbox = prepareSandbox('pkinative-mcp-leak-');
    cacheDir = mkdtempSync(path.join(tmpdir(), 'pkinative-mcp-leak-cache-'));
    process.env['PKINATIVE_MCP_CACHE_DIR'] = cacheDir;
    (process.stderr as { write: unknown }).write = ((chunk: unknown): boolean => {
        captured.push(String(chunk));
        return true;
    }) as typeof process.stderr.write;
    console.warn = (...args: unknown[]): void => { captured.push(args.map(String).join(' ')); };
    console.error = (...args: unknown[]): void => { captured.push(args.map(String).join(' ')); };
    expect(SECRET_NEEDLES.length).toBeGreaterThan(20);
});

afterAll(() => {
    (process.stderr as { write: unknown }).write = originalStderrWrite;
    console.warn = originalWarn;
    console.error = originalError;
    delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    delete process.env[PASSWORD_ENV];
    removeSandbox(sandbox);
    rmSync(cacheDir, { recursive: true, force: true });
});

async function sweep(tool: string, args: Record<string, unknown>, pw: Pw, label: string): Promise<void> {
    delete process.env[PASSWORD_ENV];
    if (pw.env !== undefined) process.env[PASSWORD_ENV] = pw.env;
    const input = pw.input !== undefined ? { ...args, password: pw.input } : args;
    try {
        const result = await callToolDirect(tool, input);
        assertResultClean(result, `${label} [${pw.label}]`);
        // A secret-bearing call (a password, the operator variable, a signer) is never a cache hit.
        if (pw.input !== undefined || pw.env !== undefined || 'signer' in args) {
            expect((result._meta as Record<string, unknown> | undefined)?.['cached'], `${label} [${pw.label}] was served from the cache`).toBeUndefined();
        }
        if (result.isError === true) {
            const code = errorCodeOf(result);
            expect(code, `${label} [${pw.label}]`).not.toBeNull();
            const text = (result.content[0] as { text?: string }).text ?? '';
            if (pw.input !== undefined) expect(text, `${label} echoes the password`).not.toContain(pw.input);
            if (pw.env !== undefined) expect(text, `${label} echoes the operator password`).not.toContain(pw.env);
        }
    } finally {
        delete process.env[PASSWORD_ENV];
    }
}

describe('campaign 1: the key, PKCS#12 and signer tools on every key fixture and password situation', () => {
    for (const name of KEY_FIXTURES) {
        it(`inspect_private_key × ${name}`, async () => {
            for (const pw of PASSWORDS) {
                await sweep('inspect_private_key', { key: fixtureInput(name) }, pw, name);
                await sweep('inspect_private_key', { key: fixtureInput(name), tryImport: true, keyType: name.startsWith('rsa') ? 'rsa' : name.startsWith('ed') ? 'ed25519' : 'ec-p256', rsaScheme: 'pss' }, pw, `${name} tryImport`);
            }
        }, 60_000);

        it(`sign_cms / create_csr / create_certificate × ${name}`, async () => {
            const key = fixtureInput(name);
            for (const pw of PASSWORDS) {
                const signer = { key, ...(pw.input !== undefined ? { password: pw.input } : {}), keyType: name.startsWith('rsa') ? 'rsa' : name.startsWith('ed') ? 'ed25519' : 'ec-p256', ...(name.startsWith('rsa') ? { rsaScheme: 'pss' } : {}) };
                const pwEnvOnly: Pw = { label: pw.label, ...(pw.env !== undefined ? { env: pw.env } : {}) };
                await sweep('sign_cms', { content: { text: 'hello' }, detached: true, certificate: LEAF, signingTime: AT, signer }, pwEnvOnly, `sign_cms ${name}`);
                await sweep('create_csr', { spec: { subject: { CN: 'leak.test' } }, signer }, pwEnvOnly, `create_csr ${name}`);
                await sweep('create_certificate', { spec: { subject: { CN: 'leak.test' }, notBefore: AT, serialNumber: 1 }, signer }, pwEnvOnly, `create_certificate ${name}`);
                await sweep('encode_x509_structure', { structure: 'signature-algorithm', signer }, pwEnvOnly, `encode_x509_structure ${name}`);
            }
        }, 120_000);
    }

    for (const name of P12_FIXTURES) {
        it(`inspect_pkcs12 / open_pkcs12 / signer.p12 × ${name}`, async () => {
            const p12 = fixtureInput(name);
            for (const pw of PASSWORDS) {
                await sweep('inspect_pkcs12', { pkcs12: p12 }, pw, `inspect_pkcs12 ${name}`);
                await sweep('open_pkcs12', { pkcs12: p12, rsaScheme: 'pkcs1', exportCertificates: true }, pw, `open_pkcs12 ${name}`);
                await sweep('open_pkcs12', { pkcs12: p12, allowUnverifiedIntegrity: true }, pw, `open_pkcs12 unverified ${name}`);
                const signer = { p12, ...(pw.input !== undefined ? { password: pw.input } : {}), rsaScheme: 'pkcs1' };
                const pwEnvOnly: Pw = { label: pw.label, ...(pw.env !== undefined ? { env: pw.env } : {}) };
                await sweep('sign_cms', { content: { text: 'hello' }, signingTime: AT, signer }, pwEnvOnly, `sign_cms ${name}`);
                await sweep('create_csr', { spec: { subject: { CN: 'leak.test' } }, signer }, pwEnvOnly, `create_csr ${name}`);
            }
        }, 120_000);
    }
});

describe('campaign 2: a private key or a PKCS#12 file fed to every PKI input of every tool', () => {
    const tools = listToolsPayload().tools;
    const SECRET_INPUTS = ['leaf.key.pem', 'leaf.key.der', 'leaf.key.enc.pem', 'leaf.p12', 'plain-keybag.p12'] as const;

    for (const tool of tools) {
        const properties = (tool.inputSchema as { properties?: Record<string, Record<string, unknown>> }).properties ?? {};
        const pkiProps = Object.entries(properties).filter(([, s]) => {
            const props = s['properties'] as Record<string, unknown> | undefined;
            const items = (s['items'] as Record<string, unknown> | undefined)?.['properties'] as Record<string, unknown> | undefined;
            return (props !== undefined && 'pem' in props) || (items !== undefined && 'pem' in items);
        });
        if (pkiProps.length === 0) continue;
        it(`${tool.name}: ${pkiProps.map(([n]) => n).join(', ')}`, async () => {
            const base = { ...(toolDefinition(tool.name)!.examples?.[0]?.input ?? {}) };
            for (const [name, schema] of pkiProps) {
                const bundle = schema['items'] !== undefined;
                for (const fixture of SECRET_INPUTS) {
                    const value = bundle ? [fixtureInput(fixture)] : fixtureInput(fixture);
                    await sweep(tool.name, { ...base, [name]: value }, { label: 'no password' }, `${tool.name}.${name} ← ${fixture}`);
                    await sweep(tool.name, { ...base, [name]: value, allowSha1: true }, { label: 'no password' }, `${tool.name}.${name} ← ${fixture} (allowSha1)`).catch(() => undefined);
                }
            }
        }, 120_000);
    }
});

describe('campaign 3: nothing leaked around the calls', () => {
    it('stderr and the console carried no needle', () => {
        assertNoSecret(captured.join('\n'), 'stderr');
    });

    it('no cache file holds a needle, and the cache holds no password-bearing or signer-bearing input', () => {
        const files = readdirSync(cacheDir).filter((f) => f.endsWith('.json'));
        for (const f of files) {
            const text = readFileSync(path.join(cacheDir, f), 'utf8');
            assertNoSecret(text, `cache file ${f}`);
            expect(text, `cache file ${f} holds a password`).not.toContain(WRONG);
        }
    });
});
