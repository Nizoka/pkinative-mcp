import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { callToolDirect, ensureEngineReady, SERVER_CACHE_HINTS, toolNames } from '../src/server.js';
import { startHttpFixture, send, modernRequest, legacyInitBody, JSON_HEADERS, type HttpFixture } from './_http-fixture.js';
import { connectLegacy } from './_mcp-harness.js';
import { fixtureText } from './_pki-fixtures.js';

const SERVER_INFO_KEY = 'io.modelcontextprotocol/serverInfo';

/**
 * MCP 2026-07-28 conformance over Streamable HTTP: stateless per-request
 * envelope (`_meta` protocol fields + `Mcp-Method`/`Mcp-Name` headers),
 * `server/discover`, `resultType`, cacheable-result hints (`ttlMs` /
 * `cacheScope`), per-result `serverInfo`, and the −32602 resource-not-found code.
 */
describe('HTTP transport — MCP 2026-07-28 clients', () => {
    let fx: HttpFixture;

    beforeAll(async () => {
        await ensureEngineReady();
        fx = await startHttpFixture();
    });
    afterAll(async () => {
        await fx.close();
    });

    async function modern(method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
        const { headers, body } = modernRequest(method, params);
        const r = await send(fx.port, { headers, body });
        expect(r.status, `${method}: ${r.text.slice(0, 300)}`).toBe(200);
        expect(r.json, `${method}: no JSON-RPC body in ${r.text.slice(0, 300)}`).toBeDefined();
        return r.json!;
    }

    it('answers server/discover with supported versions, capabilities, instructions and cache hints', async () => {
        const msg = await modern('server/discover');
        const result = msg['result'] as Record<string, unknown>;
        expect(result['resultType']).toBe('complete');
        expect(result['supportedVersions']).toContain('2026-07-28');
        const caps = result['capabilities'] as Record<string, unknown>;
        expect(Object.keys(caps)).toEqual(expect.arrayContaining(['tools', 'prompts', 'resources']));
        expect(caps['logging']).toBeUndefined(); // deprecated in 2026-07-28 — never advertised
        expect(String(result['instructions'])).toContain('DECISION TREE');
        expect(result['ttlMs']).toBe(SERVER_CACHE_HINTS['server/discover'].ttlMs);
        expect(result['cacheScope']).toBe('public');
        const meta = result['_meta'] as Record<string, unknown>;
        expect((meta[SERVER_INFO_KEY] as { name: string }).name).toBe('pkinative-mcp');
    });

    it('tools/list is cacheable (public, 24h), deterministic, and keeps _meta.apiVersion / examples', async () => {
        const a = (await modern('tools/list'))['result'] as Record<string, unknown>;
        const b = (await modern('tools/list'))['result'] as Record<string, unknown>;
        expect(a['resultType']).toBe('complete');
        expect(a['ttlMs']).toBe(86_400_000);
        expect(a['cacheScope']).toBe('public');
        const tools = a['tools'] as Array<Record<string, unknown>>;
        expect(tools.map((t) => t['name'])).toEqual((b['tools'] as Array<Record<string, unknown>>).map((t) => t['name']));
        for (const t of tools) {
            expect((t['_meta'] as { apiVersion?: string }).apiVersion).toMatch(/^\d+\.\d+\.\d+$/);
            expect(t['execution']).toBeUndefined();
            expect(t['inputSchema']).toBeDefined();
            expect(t['outputSchema']).toBeDefined();
        }
    });

    it('prompts/list and resources/* carry the configured cache scopes', async () => {
        const prompts = (await modern('prompts/list'))['result'] as Record<string, unknown>;
        expect(prompts['cacheScope']).toBe('public');
        const resources = (await modern('resources/list'))['result'] as Record<string, unknown>;
        expect(resources['ttlMs']).toBe(0);
        expect(resources['cacheScope']).toBe('private');
        const templates = (await modern('resources/templates/list'))['result'] as Record<string, unknown>;
        expect(templates['cacheScope']).toBe('private');
    });

    it('A-016: resources/read carries the private / ttl 0 cache hints on the wire and serves the sandbox file', async () => {
        const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'pkinative-http-res-'));
        process.env['PKINATIVE_MCP_OUTPUT_DIR'] = dir;
        try {
            const created = await callToolDirect('create_certificate', { spec: { serialNumber: 3, subject: { CN: 'wire' }, notBefore: '2027-01-01T00:00:00Z', validityDays: 1 }, signer: { key: { pem: fixtureText('ed25519.key.pem') } }, outputMode: 'file', outputPath: 'wire.crt.pem' });
            expect(created.isError).not.toBe(true);
            const uri = 'pkinative://output/wire.crt.pem';
            const msg = await modern('resources/read', { uri });
            const result = msg['result'] as Record<string, unknown>;
            expect(result['resultType']).toBe('complete');
            expect(result['ttlMs']).toBe(SERVER_CACHE_HINTS['resources/read'].ttlMs);
            expect(result['cacheScope']).toBe('private');
            expect(result['ttlMs']).toBe(0);
            const contents = result['contents'] as Array<{ uri: string; mimeType: string; text?: string; blob?: string }>;
            expect(contents).toHaveLength(1);
            expect(contents[0]).toMatchObject({ uri, mimeType: 'application/x-pem-file' });
            expect(contents[0]!.text).toContain('-----BEGIN CERTIFICATE-----');
            expect((result['_meta'] as Record<string, unknown>)[SERVER_INFO_KEY]).toBeDefined();
            // The listing agrees (private, ttl 0) and names the same resource.
            const list = (await modern('resources/list'))['result'] as { resources: Array<{ uri: string }>; cacheScope: string; ttlMs: number };
            expect(list.resources.map((r) => r.uri)).toEqual([uri]);
            expect(list.cacheScope).toBe('private');
        } finally {
            delete process.env['PKINATIVE_MCP_OUTPUT_DIR'];
            await fs.rm(dir, { recursive: true, force: true });
        }
    });

    it('tools/call returns resultType=complete with a payload identical to the legacy path', async () => {
        const args = { certificate: { pem: fixtureText('leaf.crt.pem') }, verbosity: 'summary' };
        const msg = await modern('tools/call', { name: 'inspect_certificate', arguments: args });
        const result = msg['result'] as Record<string, unknown>;
        expect(result['resultType']).toBe('complete');
        expect(result['isError']).not.toBe(true);
        expect((result['_meta'] as Record<string, unknown>)[SERVER_INFO_KEY]).toBeDefined();

        const client = await connectLegacy();
        const legacy = await client.callTool<{ structuredContent?: unknown; content?: unknown }>('inspect_certificate', args);
        await client.close();
        expect(result['structuredContent']).toEqual(legacy.structuredContent);
        expect(result['content']).toEqual(legacy.content);
    });

    it('reports an unknown tool as -32602 (protocol error) and a validation failure as an isError result', async () => {
        // MCP 2026-07-28 server/tools §Error Handling: unknown tool → JSON-RPC -32602, not isError.
        const unknown = (await modern('tools/call', { name: 'nope', arguments: {} }))['error'] as Record<string, unknown>;
        expect(unknown['code']).toBe(-32602);
        expect(String(unknown['message'])).toContain('[UNKNOWN_TOOL] Unknown tool: nope');
        const invalid = (await modern('tools/call', { name: 'create_certificate', arguments: { spec: 'nope' } }))['result'] as Record<string, unknown>;
        expect(invalid['isError']).toBe(true);
        expect(String((invalid['content'] as Array<{ text: string }>)[0]?.text)).toContain('VALIDATION_ERROR');
    });

    it('reports an unknown resource as -32602 (Invalid params)', async () => {
        const { headers, body } = modernRequest('resources/read', { uri: 'pkinative://output/missing.crt' });
        const r = await send(fx.port, { headers, body });
        const err = r.json?.['error'] as { code: number } | undefined;
        expect(err?.code).toBe(-32602);
    });

    it('rejects a 2026-07-28 request missing the Mcp-Method header', async () => {
        const { headers, body } = modernRequest('tools/list');
        const { 'mcp-method': _dropped, ...rest } = headers;
        void _dropped;
        const r = await send(fx.port, { headers: rest, body });
        expect(r.status).toBeGreaterThanOrEqual(400);
    });

    it('rejects a modern-looking request whose _meta envelope lacks the protocol version', async () => {
        const body = JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/list', params: { _meta: { 'io.modelcontextprotocol/clientCapabilities': {} } } });
        const r = await send(fx.port, { headers: { ...JSON_HEADERS, 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/list' }, body });
        expect(r.status).toBeGreaterThanOrEqual(400);
    });
});

/**
 * Header/body agreement and framing errors, asserted against the exact
 * JSON-RPC codes the SDK v2 handler returns (SEP-2243 / 2026-07-28):
 *   −32020 header/body mismatch · −32022 unsupported protocol version ·
 *   −32700 parse error · −32600 invalid request · −32602 invalid params.
 */
describe('HTTP transport — MCP 2026-07-28 hardening (header/body agreement, framing)', () => {
    let fx: HttpFixture;

    beforeAll(async () => {
        await ensureEngineReady();
        fx = await startHttpFixture();
    });
    afterAll(async () => {
        await fx.close();
    });

    function errorOf(r: { json: Record<string, unknown> | undefined }): { code: number; message: string } {
        const err = r.json?.['error'] as { code: number; message: string } | undefined;
        expect(err, 'expected a JSON-RPC error body').toBeDefined();
        return err!;
    }

    it('Mcp-Name header disagreeing with params.name → 400 / −32020', async () => {
        const { headers, body } = modernRequest('tools/call', { name: 'inspect_certificate', arguments: {} });
        const r = await send(fx.port, { headers: { ...headers, 'mcp-name': 'other_tool' }, body });
        expect(r.status).toBe(400);
        const err = errorOf(r);
        expect(err.code).toBe(-32020);
        expect(err.message).toContain('Mcp-Name');
        expect(r.json?.['id']).toBe(1);
    });

    it('Mcp-Method header disagreeing with the body method → 400 / −32020', async () => {
        const { headers, body } = modernRequest('tools/list');
        const r = await send(fx.port, { headers: { ...headers, 'mcp-method': 'prompts/list' }, body });
        expect(r.status).toBe(400);
        const err = errorOf(r);
        expect(err.code).toBe(-32020);
        expect(err.message).toContain('Mcp-Method');
    });

    it('missing MCP-Protocol-Version header with a modern _meta envelope is refused with 400 / −32020 (SDK 2.3 behaviour)', async () => {
        // The SDK v2.3 handler requires the header on every 2026-07-28 request: the
        // _meta envelope alone no longer classifies the request. Documented as observed
        // SDK behaviour (2.0 accepted it), not a contract of this server.
        const { headers, body } = modernRequest('tools/list');
        const { 'mcp-protocol-version': _dropped, ...rest } = headers;
        void _dropped;
        const r = await send(fx.port, { headers: rest, body });
        expect(r.status).toBe(400);
        expect(errorOf(r).code).toBe(-32020);
    });

    it('MCP-Protocol-Version header disagreeing with the _meta envelope → 400 / −32020', async () => {
        const { headers, body } = modernRequest('tools/list');
        const r = await send(fx.port, { headers: { ...headers, 'mcp-protocol-version': '1999-01-01' }, body });
        expect(r.status).toBe(400);
        expect(errorOf(r).code).toBe(-32020);
    });

    it('unsupported protocol version (header and envelope agree) → 400 / −32022 listing the supported versions', async () => {
        const { headers, body } = modernRequest('tools/list');
        const parsed = JSON.parse(body) as { params: { _meta: Record<string, string> } };
        parsed.params._meta['io.modelcontextprotocol/protocolVersion'] = '1999-01-01';
        const r = await send(fx.port, { headers: { ...headers, 'mcp-protocol-version': '1999-01-01' }, body: JSON.stringify(parsed) });
        expect(r.status).toBe(400);
        const err = errorOf(r);
        expect(err.code).toBe(-32022);
        expect((r.json?.['error'] as { data: { supported: string[] } }).data.supported).toContain('2026-07-28');
    });

    it('modern request with a non-loopback Origin → 403 before reaching MCP', async () => {
        const { headers, body } = modernRequest('tools/list');
        const r = await send(fx.port, { headers: { ...headers, origin: 'http://evil.example.com' }, body });
        expect(r.status).toBe(403);
        expect(errorOf(r).code).toBe(-32000);
        expect(errorOf(r).message).toContain('Origin');
    });

    it('JSON-RPC notification → 202 with an empty body', async () => {
        const { headers } = modernRequest('notifications/initialized');
        const body = JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' } } });
        const r = await send(fx.port, { headers, body });
        expect(r.status).toBe(202);
        expect(r.text).toBe('');
    });

    it('malformed JSON → 400 / −32700 on both eras', async () => {
        const modern = await send(fx.port, { headers: { ...JSON_HEADERS, 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/list' }, body: '{not json' });
        expect(modern.status).toBe(400);
        expect(errorOf(modern).code).toBe(-32700);
        expect(modern.json?.['id']).toBeNull();
        const legacy = await send(fx.port, { headers: JSON_HEADERS, body: '{not json' });
        expect(legacy.status).toBe(400);
        expect(errorOf(legacy).code).toBe(-32700);
    });

    it('body without a jsonrpc member → 400 / −32600 on both eras', async () => {
        const body = JSON.stringify({ id: 1, method: 'tools/list', params: {} });
        const modern = await send(fx.port, { headers: { ...JSON_HEADERS, 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/list' }, body });
        expect(modern.status).toBe(400);
        expect(errorOf(modern).code).toBe(-32600);
        const legacy = await send(fx.port, { headers: JSON_HEADERS, body });
        expect(legacy.status).toBe(400);
        expect(errorOf(legacy).code).toBe(-32600);
    });

    it.each(['2025-03-26', '2025-06-18', '2025-11-25'])('legacy initialize with %s negotiates that version and tools/list works', async (version) => {
        const init = await send(fx.port, { headers: JSON_HEADERS, body: legacyInitBody(version) });
        expect(init.status).toBe(200);
        const result = init.json?.['result'] as Record<string, unknown>;
        expect(result['protocolVersion']).toBe(version);
        expect(Object.keys(result['capabilities'] as Record<string, unknown>)).toEqual(expect.arrayContaining(['tools', 'prompts', 'resources']));
        const list = await send(fx.port, {
            headers: { ...JSON_HEADERS, 'mcp-protocol-version': version },
            body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
        });
        expect(list.status).toBe(200);
        const tools = (list.json?.['result'] as { tools: Array<{ name: string }> }).tools;
        expect(tools.map((t) => t.name)).toContain('inspect_certificate');
    });

    it('accepts a 2025-03-26 JSON-RPC batch array over HTTP and answers every request', async () => {
        const batch = await send(fx.port, {
            headers: { ...JSON_HEADERS, 'mcp-protocol-version': '2025-03-26' },
            body: JSON.stringify([
                { jsonrpc: '2.0', id: 10, method: 'ping', params: {} },
                { jsonrpc: '2.0', id: 11, method: 'tools/list', params: {} },
            ]),
        });
        expect(batch.status).toBe(200);
        const frames = batch.text
            .split('\n')
            .filter((l) => l.startsWith('data:'))
            .map((l) => JSON.parse(l.slice(5).trim()) as { id?: number; result?: unknown });
        const ids = frames.map((f) => f.id).sort();
        expect(ids).toEqual([10, 11]);
        expect((frames.find((f) => f.id === 11)?.result as { tools: unknown[] }).tools.length).toBe(toolNames().length);
    });
});
