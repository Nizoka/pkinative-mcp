/**
 * The opt-in response cache observed ON THE WIRE: a second identical
 * `tools/call` is served from PKINATIVE_MCP_CACHE_DIR and flagged
 * `_meta.cached: true` over the in-memory legacy transport and over Streamable
 * HTTP in both eras (the 2026-07-28 envelope keeps its per-result serverInfo
 * next to the flag). The non-cacheable inputs stay uncached on every path.
 */
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { ensureEngineReady } from '../src/server.js';
import { JSON_HEADERS, legacyInitBody, modernRequest, send, startHttpFixture, type HttpFixture } from './_http-fixture.js';
import { connectLegacy } from './_mcp-harness.js';
import { AT, fixtureInput } from './_pki-fixtures.js';

const SERVER_INFO_KEY = 'io.modelcontextprotocol/serverInfo';
const INSPECT = { certificate: fixtureInput('leaf.crt.pem'), issuer: fixtureInput('inter.crt.pem'), fingerprints: ['SHA-256', 'SHA-1'] };
const CHAIN = { leaf: fixtureInput('leaf.crt.pem'), candidates: [fixtureInput('inter.crt.pem')], trustAnchors: [fixtureInput('root.crt.pem')], at: AT, verbosity: 'summary' };
let cacheDir: string;

function cachedFiles(): string[] {
    return readdirSync(cacheDir).filter((f) => f.endsWith('.json'));
}

beforeAll(async () => {
    await ensureEngineReady();
});
beforeEach(() => {
    cacheDir = mkdtempSync(join(tmpdir(), 'pkinative-cache-wire-'));
    process.env['PKINATIVE_MCP_CACHE_DIR'] = cacheDir;
    delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
    delete process.env['PKINATIVE_MCP_AT'];
});
afterEach(() => {
    delete process.env['PKINATIVE_MCP_CACHE_DIR'];
    rmSync(cacheDir, { recursive: true, force: true });
});

describe('cache hit through the in-memory legacy transport', () => {
    it('the second identical inspect_certificate is served from the cache with _meta.cached and identical content', async () => {
        const client = await connectLegacy();
        try {
            type Res = { isError?: boolean; _meta?: Record<string, unknown>; structuredContent?: unknown; content: Array<{ type: string; text?: string }> };
            const fresh = await client.callTool<Res>('inspect_certificate', INSPECT);
            expect(fresh.isError).not.toBe(true);
            expect(fresh._meta?.['cached']).toBeUndefined();
            expect(cachedFiles()).toHaveLength(1);
            const hit = await client.callTool<Res>('inspect_certificate', INSPECT);
            expect(hit._meta?.['cached']).toBe(true);
            expect(hit.structuredContent).toEqual(fresh.structuredContent);
            expect(hit.content).toEqual(fresh.content);
            // A different argument is a different key.
            const other = await client.callTool<Res>('inspect_certificate', { ...INSPECT, fingerprints: ['SHA-512'] });
            expect(other._meta?.['cached']).toBeUndefined();
            expect(cachedFiles()).toHaveLength(2);
            // A verdict with a pinned instant is cached on its projected form.
            await client.callTool<Res>('verify_certificate_chain', CHAIN);
            const again = await client.callTool<Res>('verify_certificate_chain', CHAIN);
            expect(again._meta?.['cached']).toBe(true);
            expect(again.structuredContent).toMatchObject({ valid: true, pathLength: 3 });
        } finally {
            await client.close();
        }
    });
});

describe('cache hit over Streamable HTTP', () => {
    let fx: HttpFixture;

    beforeAll(async () => {
        fx = await startHttpFixture();
    });
    afterAll(async () => {
        await fx.close();
    });

    it('2026-07-28 envelope: the second call carries _meta.cached next to the per-result serverInfo', async () => {
        const call = async (): Promise<Record<string, unknown>> => {
            const { headers, body } = modernRequest('tools/call', { name: 'inspect_certificate', arguments: INSPECT });
            const r = await send(fx.port, { headers, body });
            expect(r.status).toBe(200);
            return r.json!['result'] as Record<string, unknown>;
        };
        const fresh = await call();
        expect((fresh['_meta'] as Record<string, unknown>)['cached']).toBeUndefined();
        const hit = await call();
        const meta = hit['_meta'] as Record<string, unknown>;
        expect(meta['cached']).toBe(true);
        expect(meta[SERVER_INFO_KEY]).toBeDefined();
        expect(hit['resultType']).toBe('complete');
        expect(hit['structuredContent']).toEqual(fresh['structuredContent']);
        expect(cachedFiles()).toHaveLength(1);
    });

    it('2025-era initialize + tools/call: the flag reaches legacy HTTP clients too; a signed artefact is never cached', async () => {
        const init = await send(fx.port, { headers: JSON_HEADERS, body: legacyInitBody('2025-11-25') });
        expect(init.status).toBe(200);
        const call = async (name: string, args: Record<string, unknown>, id: number): Promise<Record<string, unknown>> => {
            const r = await send(fx.port, { headers: { ...JSON_HEADERS, 'mcp-protocol-version': '2025-11-25' }, body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }) });
            expect(r.status).toBe(200);
            return r.json!['result'] as Record<string, unknown>;
        };
        await call('inspect_certificate', INSPECT, 2);
        const hit = await call('inspect_certificate', INSPECT, 3);
        expect((hit['_meta'] as Record<string, unknown>)['cached']).toBe(true);
        const signed = { spec: { serialNumber: 1, subject: { CN: 'wire' }, notBefore: AT, validityDays: 1 }, signer: { key: fixtureInput('ed25519.key.pem') } };
        await call('create_certificate', signed, 4);
        const again = await call('create_certificate', signed, 5);
        expect((again['_meta'] as Record<string, unknown> | undefined)?.['cached']).toBeUndefined();
        expect(cachedFiles()).toHaveLength(1);
    });
});
