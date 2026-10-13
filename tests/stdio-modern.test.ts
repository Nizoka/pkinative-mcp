/**
 * MCP 2026-07-28 over stdio, against the built binary (dist/cli.js): the
 * `server/discover` probe pins the connection to the modern era, after which
 * every request must carry the per-request `_meta` envelope
 * (`io.modelcontextprotocol/protocolVersion` + `clientCapabilities`, plus
 * `clientInfo`) — the SDK v2 stdio entry answers an envelope-less request with
 * -32602. Asserted here: `tools/list` cache hints and `_meta.serverInfo`,
 * `tools/call` payload identity with the legacy in-process path, the JSON-RPC
 * batch-array rejection (stdio has no batch since 2025-06-18; the frame is
 * dropped without killing the process), and the unknown-tool protocol error.
 *
 * Requires `npm run build`; skipped locally without dist/, a hard failure under
 * CI (see tests/cli-stdio.test.ts).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { ensureEngineReady, SERVER_CACHE_HINTS, toolNames } from '../src/server.js';
import { expectCleanStdioExit, hasDist, McpRpcError, modernEnvelope, openAgent, SERVER_INFO_KEY, type AgentClient } from './_agent-client.js';
import { connectLegacy } from './_mcp-harness.js';
import { fixtureText } from './_pki-fixtures.js';

const ENVELOPE = modernEnvelope();

describe.skipIf(!hasDist)('dist/cli.js over stdio — MCP 2026-07-28 envelope', () => {
    let agent: AgentClient;

    beforeAll(async () => {
        await ensureEngineReady();
        agent = await openAgent('stdio-modern', { env: {} });
    }, 30_000);

    afterAll(async () => {
        const report = await agent.close();
        for (const line of report.stdoutLines) {
            expect(() => JSON.parse(line), `non-JSON stdout line: ${line.slice(0, 120)}`).not.toThrow();
        }
        expectCleanStdioExit(report);
    });

    it('server/discover pinned the modern era (resultType complete)', () => {
        expect(agent.handshake['resultType']).toBe('complete');
        expect(agent.handshake['supportedVersions']).toContain('2026-07-28');
    });

    it('tools/list with the _meta envelope: resultType, 24 h public cache hint, per-result serverInfo', async () => {
        const list = await agent.request<Record<string, unknown>>('tools/list');
        expect(list['resultType']).toBe('complete');
        expect(list['ttlMs']).toBe(SERVER_CACHE_HINTS['tools/list'].ttlMs);
        expect(list['cacheScope']).toBe('public');
        expect((list['tools'] as unknown[]).length).toBe(toolNames().length);
        const info = (list['_meta'] as Record<string, unknown>)[SERVER_INFO_KEY] as { name: string; version: string };
        expect(info.name).toBe('pkinative-mcp');
        expect(info.version).toMatch(/^\d+\.\d+\.\d+$/);
    });

    it('tools/call inspect_certificate with the envelope: resultType complete, serverInfo, payload identical to the legacy path', async () => {
        const args = { certificate: { pem: fixtureText('leaf.crt.pem') }, issuer: { pem: fixtureText('inter.crt.pem') }, verbosity: 'summary' };
        const modern = await agent.callTool('inspect_certificate', args);
        expect(modern.isError).not.toBe(true);
        expect(modern.resultType).toBe('complete');
        expect((modern._meta as Record<string, unknown>)[SERVER_INFO_KEY]).toBeDefined();

        const client = await connectLegacy();
        const legacy = await client.callTool<{ structuredContent?: unknown; content?: unknown }>('inspect_certificate', args);
        await client.close();
        expect(modern.structuredContent).toEqual(legacy.structuredContent);
        expect(modern.content).toEqual(legacy.content);
    });

    it('a request without the _meta envelope on the modern-pinned connection is refused with -32602', async () => {
        // Bypass the client's automatic envelope: write the frame ourselves.
        const id = 9_001;
        agent.sendRaw(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/list', params: {} }));
        const report = await peekStdout(agent, id);
        expect(report?.error?.code).toBe(-32602);
        expect(report?.error?.message).toContain('_meta envelope');
    });

    it('a JSON-RPC batch array is rejected on stdio without killing the process; the next valid request is answered', async () => {
        agent.sendRaw(JSON.stringify([
            { jsonrpc: '2.0', id: 9_101, method: 'prompts/list', params: { _meta: ENVELOPE } },
            { jsonrpc: '2.0', id: 9_102, method: 'tools/list', params: { _meta: ENVELOPE } },
        ]));
        const list = await agent.request<{ tools: unknown[] }>('tools/list');
        expect(list.tools.length).toBe(toolNames().length);
        // The batch never produced a frame for either of its ids.
        expect(await peekStdout(agent, 9_101)).toBeUndefined();
        expect(await peekStdout(agent, 9_102)).toBeUndefined();
    });

    it('an unknown tool is a JSON-RPC -32602 protocol error (not an isError result)', async () => {
        await expect(agent.request('tools/call', { name: 'nope', arguments: {} })).rejects.toSatisfy(
            (e: unknown) => e instanceof McpRpcError && e.code === -32602 && e.message.includes('[UNKNOWN_TOOL] Unknown tool: nope'),
        );
        // A validation failure stays an isError result on the same connection.
        const invalid = await agent.callTool('create_certificate', { spec: 'nope' });
        expect(invalid.isError).toBe(true);
        expect((invalid._meta as { error: { code: string } }).error.code).toBe('VALIDATION_ERROR');
    });

    it('a legacy initialize on the modern-pinned connection is refused with -32022 (supported versions listed)', async () => {
        const id = 9_201;
        agent.sendRaw(JSON.stringify({ jsonrpc: '2.0', id, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'late', version: '0' } } }));
        const frame = await peekStdout(agent, id);
        expect(frame?.error?.code).toBe(-32022);
        expect((frame?.error?.data as { supported?: string[] } | undefined)?.supported).toContain('2026-07-28');
        expect((await agent.request<{ tools: unknown[] }>('tools/list')).tools.length).toBe(toolNames().length);
    });
});

interface RawFrame {
    id?: unknown;
    error?: { code: number; message: string; data?: unknown };
}

/**
 * Frames written outside the client's request path (raw writes) are not
 * correlated by the client; find them by id in the live stdout transcript. A
 * `prompts/list` round-trip ordered after the raw write guarantees the server
 * has processed the raw frame (stdio is a single ordered queue) before we look
 * (`ping` is not a 2026-07-28 method: the modern era answers it with -32601).
 */
async function peekStdout(agent: AgentClient, id: number): Promise<RawFrame | undefined> {
    await agent.request('prompts/list');
    for (const line of agent.transcript()) {
        try {
            const frame = JSON.parse(line) as RawFrame;
            if (frame.id === id) return frame;
        } catch {
            /* non-JSON line — asserted on close */
        }
    }
    return undefined;
}
