/**
 * Server-level cache policy: what the opt-in response cache may serve, how a
 * hit is signalled, and what the key is namespaced by.
 *
 * Never cached: sandbox references (a `path` anywhere — a path is a
 * reference, not content), `outputMode: 'file'` (the write is the effect), a
 * call carrying a `password` or a `signer` (secrets), a `'random'` / `'now'`
 * value, an instant input left to the wall clock, `describe_engine`
 * (environment) and `draft_governance_issue` (environment embedded in the
 * draft) — and never an `isError` result.
 */
import { mkdtempSync, readdirSync, readFileSync, rmSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { PKINATIVE_VERSION } from '../src/engine.js';
import { callToolDirect, ensureEngineReady } from '../src/server.js';
import { TOOL_API_VERSION, PKINATIVE_MCP_VERSION } from '../src/version.js';
import { assertResultClean } from './_pki-assert.js';
import { AT, fixture, fixtureInput, PASSWORD } from './_pki-fixtures.js';

let cacheDir: string;

beforeAll(async () => {
    await ensureEngineReady();
});

beforeEach(() => {
    cacheDir = mkdtempSync(join(tmpdir(), 'pkinative-cache-policy-'));
    process.env['PKINATIVE_MCP_CACHE_DIR'] = cacheDir;
    delete process.env['PKINATIVE_MCP_AT'];
});

afterEach(() => {
    delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
    delete process.env['PKINATIVE_MCP_AT'];
    rmSync(cacheDir, { recursive: true, force: true });
});

const INSPECT = { certificate: fixtureInput('leaf.crt.pem'), issuer: fixtureInput('inter.crt.pem') };
const CHAIN = { leaf: fixtureInput('leaf.crt.pem'), candidates: [fixtureInput('inter.crt.pem')], trustAnchors: [fixtureInput('root.crt.pem')], at: AT };
const CA_SPEC = { serialNumber: 1, subject: { CN: 'cache' }, notBefore: AT, validityDays: 1 };

function cachedFiles(): string[] {
    return readdirSync(cacheDir).filter((f) => f.endsWith('.json'));
}

function cachedFlag(result: { _meta?: Record<string, unknown> }): unknown {
    return (result._meta as Record<string, unknown> | undefined)?.['cached'];
}

describe('response cache policy', () => {
    it('marks a served-from-cache inspect_certificate result with _meta.cached=true and leaves the first (fresh) result unmarked', async () => {
        const fresh = await callToolDirect('inspect_certificate', INSPECT);
        expect(fresh.isError).not.toBe(true);
        expect(cachedFlag(fresh)).toBeUndefined();
        expect(cachedFiles()).toHaveLength(1);
        const hit = await callToolDirect('inspect_certificate', INSPECT);
        expect(cachedFlag(hit)).toBe(true);
        expect(hit.structuredContent).toEqual(fresh.structuredContent);
        expect(hit.content).toEqual(fresh.content);
    });

    it('a cached hit is projected on its projected form; a different projection is a different key', async () => {
        const args = { ...INSPECT, verbosity: 'summary', fields: ['serialNumberHex', 'signatureValid'] };
        const fresh = await callToolDirect('inspect_certificate', args);
        expect(fresh.isError).not.toBe(true);
        const hit = await callToolDirect('inspect_certificate', args);
        expect(cachedFlag(hit)).toBe(true);
        expect(hit.structuredContent).toEqual({ serialNumberHex: '1001', signatureValid: true });
        const other = await callToolDirect('inspect_certificate', { ...INSPECT, verbosity: 'summary' });
        expect(cachedFlag(other)).toBeUndefined();
        expect(cachedFiles()).toHaveLength(2);
    });

    it('namespaces the key by tool API version, package version and engine version (engine lock-step)', async () => {
        await callToolDirect('inspect_certificate', INSPECT);
        const [file] = cachedFiles();
        const entry = JSON.parse(readFileSync(join(cacheDir, file!), 'utf8')) as { apiVersion: string; tool: string };
        expect(entry.tool).toBe('inspect_certificate');
        expect(entry.apiVersion).toBe(`${TOOL_API_VERSION}/${PKINATIVE_MCP_VERSION}/${PKINATIVE_VERSION}`);
    });

    it('caches a verdict only when its instant is pinned (input or PKINATIVE_MCP_AT), never the wall clock', async () => {
        await callToolDirect('verify_certificate_chain', CHAIN);
        expect(cachedFlag(await callToolDirect('verify_certificate_chain', CHAIN))).toBe(true);
        const { at: _at, ...clock } = CHAIN;
        void _at;
        await callToolDirect('verify_certificate_chain', clock);
        expect(cachedFlag(await callToolDirect('verify_certificate_chain', clock))).toBeUndefined();
        await callToolDirect('verify_certificate_chain', { ...clock, at: 'now' });
        expect(cachedFlag(await callToolDirect('verify_certificate_chain', { ...clock, at: 'now' }))).toBeUndefined();
        expect(cachedFiles()).toHaveLength(1);
        process.env['PKINATIVE_MCP_AT'] = AT;
        await callToolDirect('verify_certificate_chain', clock);
        expect(cachedFlag(await callToolDirect('verify_certificate_chain', clock))).toBe(true);
        expect(cachedFiles()).toHaveLength(2);
    });

    it('never caches a call carrying a signer or a password, and no cache file ever holds one', async () => {
        const signed = { spec: CA_SPEC, signer: { key: fixtureInput('ed25519.key.pem') } };
        const a = await callToolDirect('create_certificate', signed);
        expect(a.isError, JSON.stringify(a.content[0])).not.toBe(true);
        expect(cachedFlag(await callToolDirect('create_certificate', signed))).toBeUndefined();
        const p12 = { spec: CA_SPEC, signer: { p12: fixtureInput('leaf.p12'), password: PASSWORD } };
        await callToolDirect('create_certificate', p12);
        expect(cachedFlag(await callToolDirect('create_certificate', p12))).toBeUndefined();
        expect(cachedFiles()).toHaveLength(0);
        for (const r of [a]) assertResultClean(r);
    });

    it("never caches a 'random' serial or a clock-dependent notBefore", async () => {
        const random = { spec: { subject: { CN: 'r' }, notBefore: AT, serialNumber: 'random' }, signer: { key: fixtureInput('ed25519.key.pem') } };
        await callToolDirect('create_certificate', random);
        await callToolDirect('create_certificate', random);
        expect(cachedFiles()).toHaveLength(0);
    });

    it('never caches describe_engine (environment-dependent) or draft_governance_issue (environment-embedding)', async () => {
        for (let i = 0; i < 2; i++) {
            const engine = await callToolDirect('describe_engine', {});
            expect(engine.isError).not.toBe(true);
            expect(cachedFlag(engine)).toBeUndefined();
            const draft = await callToolDirect('draft_governance_issue', {
                title: 'inspect_certificate reports the wrong serial rendering',
                summary: 'The serial hex is rendered with a leading zero that OpenSSL omits in the summary projection.',
                issueType: 'bug',
                reproduction: { command: 'inspect_certificate { certificate, verbosity: "summary" }', result: 'serialNumberHex "01"' },
                expectedBehavior: 'serialNumberHex "1"',
                duplicateSearchPerformed: true,
            });
            expect(draft.isError).not.toBe(true);
            expect(cachedFlag(draft)).toBeUndefined();
        }
        expect(cachedFiles()).toHaveLength(0);
    });

    it('never caches file-mode output (the write is the effect) nor a path reference (a path is a reference, not content)', async () => {
        const outDir = mkdtempSync(join(tmpdir(), 'pkinative-cache-out-'));
        process.env['PKINATIVE_MCP_OUTPUT_DIR'] = outDir;
        try {
            copyFileSync(fixture('leaf.crt.pem'), join(outDir, 'leaf.crt.pem'));
            copyFileSync(fixture('ed25519.key.pem'), join(outDir, 'ed.key'));
            const file = await callToolDirect('create_certificate', { spec: CA_SPEC, signer: { key: { path: 'ed.key' } }, outputMode: 'file', outputPath: 'a.crt.pem' });
            expect(file.isError, JSON.stringify(file.content[0])).not.toBe(true);
            for (const [tool, args] of [
                ['inspect_certificate', { certificate: { path: 'leaf.crt.pem' } }],
                ['verify_certificate_chain', { ...CHAIN, candidates: [{ path: 'leaf.crt.pem' }] }],
            ] as const) {
                const a = await callToolDirect(tool, args);
                expect(a.isError, `${tool}: ${JSON.stringify(a.content[0])}`).not.toBe(true);
                expect(cachedFlag(await callToolDirect(tool, args)), tool).toBeUndefined();
            }
            expect(cachedFiles()).toHaveLength(0);
        } finally {
            rmSync(outDir, { recursive: true, force: true });
        }
    });

    it('a cached error is never served: refusals are not persisted', async () => {
        const args = { certificate: { derBase64: 'AAAAAAAA' } };
        const a = await callToolDirect('inspect_certificate', args);
        expect(a.isError).toBe(true);
        expect(cachedFiles()).toHaveLength(0);
        const b = await callToolDirect('inspect_certificate', args);
        expect(b.isError).toBe(true);
        expect(cachedFlag(b)).toBeUndefined();
    });
});
