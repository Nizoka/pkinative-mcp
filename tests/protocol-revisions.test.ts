/**
 * Protocol-revision matrix: every revision `@modelcontextprotocol/core` 2.0.0
 * negotiates — the five legacy revisions through `initialize`
 * (2024-10-07, 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25) and 2026-07-28
 * through `server/discover` — is proven on BOTH transports: Streamable HTTP
 * (the in-process fixture wired like src/cli.ts) and stdio (the built
 * dist/cli.js). Each cell negotiates exactly the requested revision and serves
 * the full catalogue afterwards. Six revisions × two transports.
 *
 * The stdio cells need `npm run build`; skipped locally without dist/, a hard
 * failure under CI (see tests/cli-stdio.test.ts).
 */
import { beforeAll, describe, expect, it } from 'vitest';

import { ensureEngineReady, toolNames } from '../src/server.js';
import { expectCleanStdioExit, hasDist, openAgent, type AgentTransport } from './_agent-client.js';

export const LEGACY_REVISIONS = ['2024-10-07', '2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'] as const;
export const MODERN_REVISION = '2026-07-28';

async function proveLegacy(transport: 'http-legacy' | 'stdio-legacy', version: string): Promise<void> {
    const agent = await openAgent(transport, { env: {}, legacyVersion: version });
    try {
        expect(agent.handshake['protocolVersion']).toBe(version);
        expect((agent.handshake['serverInfo'] as { name: string }).name).toBe('pkinative-mcp');
        expect(Object.keys(agent.handshake['capabilities'] as Record<string, unknown>)).toEqual(expect.arrayContaining(['tools', 'prompts', 'resources']));
        const list = await agent.request<{ tools: Array<{ name: string }>; ttlMs?: number }>('tools/list');
        expect(list.tools.map((t) => t.name)).toEqual(toolNames());
        expect(list.tools).toHaveLength(toolNames().length);
        expect(list.ttlMs).toBeUndefined(); // 2026-07-28 cache hints never leak into a legacy session
    } finally {
        const report = await agent.close();
        if (transport === 'stdio-legacy') expectCleanStdioExit(report);
    }
}

async function proveModern(transport: 'http-modern' | 'stdio-modern'): Promise<void> {
    const agent = await openAgent(transport, { env: {} });
    try {
        expect(agent.handshake['resultType']).toBe('complete');
        expect(agent.handshake['supportedVersions']).toEqual([MODERN_REVISION]);
        const list = await agent.request<{ tools: Array<{ name: string }>; resultType?: string }>('tools/list');
        expect(list.resultType).toBe('complete');
        expect(list.tools.map((t) => t.name)).toEqual(toolNames());
        expect(list.tools).toHaveLength(toolNames().length);
    } finally {
        const report = await agent.close();
        if (transport === 'stdio-modern') expectCleanStdioExit(report);
    }
}

describe('protocol revisions over Streamable HTTP', () => {
    beforeAll(async () => {
        await ensureEngineReady();
    });

    it.each(LEGACY_REVISIONS)('legacy initialize %s negotiates exactly that revision and serves the catalogue', async (version) => {
        await proveLegacy('http-legacy', version);
    });

    it(`${MODERN_REVISION} via server/discover serves the catalogue`, async () => {
        await proveModern('http-modern');
    });
});

describe.skipIf(!hasDist)('protocol revisions over stdio (dist/cli.js)', () => {
    it.each(LEGACY_REVISIONS)('legacy initialize %s negotiates exactly that revision and serves the catalogue', async (version) => {
        await proveLegacy('stdio-legacy', version);
    });

    it(`${MODERN_REVISION} via server/discover serves the catalogue`, async () => {
        await proveModern('stdio-modern');
    });
});

/** Every cell of the matrix, for the documentation table (README § MCP protocol compliance). */
export const PROTOCOL_MATRIX: ReadonlyArray<{ revision: string; transport: AgentTransport; handshake: 'initialize' | 'server/discover' }> = [
    ...LEGACY_REVISIONS.flatMap((revision) => [
        { revision, transport: 'http-legacy' as const, handshake: 'initialize' as const },
        { revision, transport: 'stdio-legacy' as const, handshake: 'initialize' as const },
    ]),
    { revision: MODERN_REVISION, transport: 'http-modern', handshake: 'server/discover' },
    { revision: MODERN_REVISION, transport: 'stdio-modern', handshake: 'server/discover' },
];
