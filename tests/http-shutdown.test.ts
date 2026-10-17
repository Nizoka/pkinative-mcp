/**
 * A-016 — the built binary in HTTP mode: `dist/cli.js` with PKINATIVE_MCP_PORT
 * answers `server/discover` on the loopback endpoint, exits cleanly on SIGTERM
 * (exit 0 on POSIX; on win32 `kill('SIGTERM')` is TerminateProcess, so only
 * termination is asserted) and releases the port.
 *
 * Requires `npm run build`; skipped locally without dist/, a hard failure under
 * CI (see tests/cli-stdio.test.ts).
 */
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createServer as createNetServer, type AddressInfo } from 'node:net';

import { describe, expect, it } from 'vitest';

import { CLI_PATH, hasDist, inCi } from './_agent-client.js';
import { modernRequest, send } from './_http-fixture.js';

async function freePort(): Promise<number> {
    return new Promise((resolve, reject) => {
        const srv = createNetServer();
        srv.once('error', reject);
        srv.listen(0, '127.0.0.1', () => {
            const port = (srv.address() as AddressInfo).port;
            srv.close(() => resolve(port));
        });
    });
}

async function portIsFree(port: number): Promise<boolean> {
    return new Promise((resolve) => {
        const srv = createNetServer();
        srv.once('error', () => resolve(false));
        srv.listen(port, '127.0.0.1', () => srv.close(() => resolve(true)));
    });
}

interface HttpSession {
    child: ChildProcessWithoutNullStreams;
    port: number;
    stderr: () => string;
    exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

async function startHttpServer(env: Record<string, string> = {}): Promise<HttpSession> {
    const port = await freePort();
    const child = spawn(process.execPath, [CLI_PATH], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, PKINATIVE_MCP_PORT: String(port), PKINATIVE_MCP_HTTP_TOKEN: '', PKINATIVE_MCP_OUTPUT_DIR: '', PKINATIVE_MCP_CACHE_DIR: '', ...env },
    });
    let stderr = '';
    const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => child.on('exit', (code, signal) => resolve({ code, signal })));
    await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`HTTP server did not report ready; stderr: ${stderr}`)), 20_000);
        child.stderr.on('data', (c: Buffer) => {
            stderr += c.toString('utf8');
            if (stderr.includes('ready (HTTP transport')) {
                clearTimeout(timer);
                resolve();
            }
        });
        void exited.then(() => {
            clearTimeout(timer);
            reject(new Error(`HTTP server exited before ready; stderr: ${stderr}`));
        });
    });
    return { child, port, stderr: () => stderr, exited };
}

describe('dist/cli.js presence', () => {
    it.runIf(inCi)('is built before the HTTP shutdown suite runs in CI', () => {
        expect(hasDist).toBe(true);
    });
});

describe.skipIf(!hasDist)('A-016: dist/cli.js in HTTP mode', () => {
    it('answers server/discover on /mcp, then exits on SIGTERM and releases the port', async () => {
        const session = await startHttpServer();
        expect(session.stderr()).toContain(`127.0.0.1:${session.port}/mcp`);
        expect(session.stderr()).toContain('no authentication (loopback only)');
        const { headers, body } = modernRequest('server/discover');
        const r = await send(session.port, { headers, body });
        expect(r.status).toBe(200);
        const result = r.json?.['result'] as Record<string, unknown>;
        expect(result['resultType']).toBe('complete');
        expect(result['supportedVersions']).toContain('2026-07-28');
        expect(Object.keys(result['capabilities'] as Record<string, unknown>)).toEqual(expect.arrayContaining(['tools', 'prompts', 'resources']));
        // A non-/mcp path is 404; stdout carries nothing (HTTP mode logs to stderr only).
        expect((await send(session.port, { path: '/', method: 'GET' })).status).toBe(404);

        session.child.kill('SIGTERM');
        const { code, signal } = await session.exited;
        if (process.platform === 'win32') {
            expect(code !== null || signal !== null).toBe(true);
        } else {
            expect(signal, `killed by ${signal}; stderr: ${session.stderr()}`).toBeNull();
            expect(code, session.stderr()).toBe(0);
            expect(session.stderr()).toContain('received SIGTERM, shutting down');
        }
        expect(await portIsFree(session.port)).toBe(true);
    }, 40_000);

    it('refuses to start with a weak bearer token (configuration error, exit 1, the token never echoed)', async () => {
        const port = await freePort();
        const child = spawn(process.execPath, [CLI_PATH], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, PKINATIVE_MCP_PORT: String(port), PKINATIVE_MCP_HTTP_TOKEN: 'short' } });
        let stderr = '';
        child.stderr.on('data', (c: Buffer) => {
            stderr += c.toString('utf8');
        });
        const { code } = await new Promise<{ code: number | null }>((resolve) => child.on('exit', (c) => resolve({ code: c })));
        expect(code).toBe(1);
        expect(stderr).toContain('fatal:');
        expect(stderr).toContain('PKINATIVE_MCP_HTTP_TOKEN');
        expect(stderr).not.toContain('short');
        expect(await portIsFree(port)).toBe(true);
    }, 30_000);
});
