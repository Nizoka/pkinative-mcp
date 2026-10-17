import { describe, it, expect, beforeAll, afterAll } from 'vitest';

import { ensureEngineReady } from '../src/server.js';
import { toolNames } from '../src/server.js';
import { startHttpFixture, send, legacyInitBody, JSON_HEADERS, type HttpFixture } from './_http-fixture.js';
import { connectLegacy } from './_mcp-harness.js';
import { fixtureText } from './_pki-fixtures.js';

/**
 * Legacy-era (2025-xx) HTTP transport: DNS-rebinding / Origin protection and
 * the stateless `initialize` fallback that today's hosts rely on.
 *
 * The fixture reproduces src/cli.ts's wiring (node:http → src/http.ts →
 * createMcpHandler with `legacy: 'stateless'`). Host and Origin are pinned to
 * the loopback authority; any foreign value is answered with 403, matching
 * MCP's Security Best Practices.
 */
describe('HTTP transport — legacy 2025-era clients', () => {
    let fx: HttpFixture;

    beforeAll(async () => {
        await ensureEngineReady();
        fx = await startHttpFixture();
    });
    afterAll(async () => {
        await fx.close();
    });

    const initBody = legacyInitBody();

    it('rejects a foreign Host header with 403', async () => {
        const r = await send(fx.port, { headers: { ...JSON_HEADERS, host: 'evil.example.com' }, body: initBody });
        expect(r.status).toBe(403);
    });

    it('rejects a foreign Origin header with 403', async () => {
        const r = await send(fx.port, {
            headers: { ...JSON_HEADERS, host: `127.0.0.1:${fx.port}`, origin: 'http://evil.example.com' },
            body: initBody,
        });
        expect(r.status).toBe(403);
    });

    it('accepts the loopback Host/Origin and negotiates the legacy protocol version', async () => {
        const r = await send(fx.port, {
            headers: { ...JSON_HEADERS, host: `127.0.0.1:${fx.port}`, origin: `http://127.0.0.1:${fx.port}` },
            body: initBody,
        });
        expect(r.status).toBeLessThan(400);
        const result = r.json?.['result'] as Record<string, unknown> | undefined;
        expect(result?.['protocolVersion']).toBe('2025-06-18');
        expect((result?.['serverInfo'] as { name?: string } | undefined)?.name).toBe('pkinative-mcp');
        expect(typeof result?.['instructions']).toBe('string');
        // Legacy results never carry 2026-07-28 wire fields.
        expect(result?.['resultType']).toBeUndefined();
    });

    it('serves tools/list and tools/call statelessly (no session) with results identical to the in-memory path', async () => {
        const list = await send(fx.port, {
            headers: JSON_HEADERS,
            body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
        });
        expect(list.status).toBe(200);
        const tools = (list.json?.['result'] as { tools: Array<{ name: string }> }).tools;
        expect(tools.length).toBe(toolNames().length);

        const args = { certificate: { pem: fixtureText('leaf.crt.pem') }, verbosity: 'summary' };
        const call = await send(fx.port, {
            headers: JSON_HEADERS,
            body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'inspect_certificate', arguments: args } }),
        });
        expect(call.status).toBe(200);
        const overHttp = call.json?.['result'] as { structuredContent?: unknown; isError?: boolean };
        expect(overHttp.isError).not.toBe(true);

        const client = await connectLegacy();
        const inMemory = await client.callTool<{ structuredContent?: unknown }>('inspect_certificate', args);
        await client.close();
        expect(overHttp.structuredContent).toEqual(inMemory.structuredContent);
    });

    it('answers 405 to GET/DELETE (stateless serving), 404 off /mcp and 415 on a wrong content-type', async () => {
        expect((await send(fx.port, { method: 'GET', headers: { accept: 'text/event-stream' } })).status).toBe(405);
        expect((await send(fx.port, { method: 'DELETE', headers: {} })).status).toBe(405);
        expect((await send(fx.port, { path: '/other', headers: JSON_HEADERS, body: initBody })).status).toBe(404);
        expect((await send(fx.port, { headers: { 'content-type': 'text/plain', accept: 'application/json, text/event-stream' }, body: initBody })).status).toBe(415);
    });
});
