import { describe, it, expect } from 'vitest';
import { spawn } from 'node:child_process';
import { PassThrough } from 'node:stream';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { STDIO_MAX_FRAME_BYTES } from '../src/caps.js';
import { toolNames } from '../src/server.js';
import { fixtureText } from './_pki-fixtures.js';

/**
 * End-to-end stdio smoke: spawns the built CLI and drives it over
 * newline-delimited JSON-RPC exactly as an MCP host would.
 *
 * Guards the two properties a stdio server cannot violate: stdout carries
 * nothing but JSON-RPC frames (engine diagnostics go through the sink, never stdout), and
 * both protocol eras are served by the same process (2025 `initialize`
 * handshake here; `server/discover` probe for 2026-07-28 hosts).
 *
 * Requires `npm run build` (dist/cli.js). Locally the suite is skipped with a
 * console note when dist/ is absent; under CI (`process.env.CI` set) a missing
 * dist/ is a hard failure — the workflows must build before testing, otherwise
 * this end-to-end smoke would silently vanish from the release gate.
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(here, '..', 'dist', 'cli.js');
const hasDist = existsSync(CLI);
const inCi = process.env.CI !== undefined && process.env.CI !== '' && process.env.CI !== 'false';

if (!hasDist && !inCi) {
    console.warn(`[cli-stdio] dist/cli.js not found — run \`npm run build\` first; skipping the stdio smoke suite (it FAILS under CI).`);
}

describe('dist/cli.js presence', () => {
    it.runIf(inCi)('is built before the test run in CI (build must precede test in every workflow)', () => {
        expect(hasDist, `dist/cli.js is missing under CI — run \`npm run build\` before \`npm test\` (see .github/workflows/*.yml)`).toBe(true);
    });
});

interface Frame {
    id?: number;
    result?: Record<string, unknown>;
    error?: { code: number; message: string };
}

interface StdioSession {
    frames: Frame[];
    stdoutLines: string[];
    stderr: string;
    exitCode: number | null;
    signal: NodeJS.Signals | null;
}

/**
 * After every expected response arrived the child is asked to stop. On POSIX
 * that is a real SIGTERM (the server's handler closes the transport and exits
 * 0). On win32 `child.kill('SIGTERM')` is Node's emulation over
 * TerminateProcess: the process is torn down without running any handler and
 * reports `{ code: null, signal: 'SIGTERM' }` (or code 1), so a clean-exit
 * assertion is impossible there — the tests below only assert termination on
 * Windows and assert `code 0 / signal null` on POSIX.
 */
function runStdioSession(messages: Array<Record<string, unknown>>, expectIds: number[]): Promise<StdioSession> {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [CLI], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, PKINATIVE_MCP_PORT: '' } });
        const stdoutLines: string[] = [];
        const frames: Frame[] = [];
        let stderr = '';
        let buffer = '';
        const pending = new Set(expectIds);
        const timer = setTimeout(() => {
            child.kill('SIGKILL');
            reject(new Error(`stdio session timed out; stderr: ${stderr}`));
        }, 20_000);

        child.stderr.on('data', (c: Buffer) => {
            stderr += c.toString('utf8');
        });
        child.stdout.on('data', (c: Buffer) => {
            buffer += c.toString('utf8');
            let idx: number;
            while ((idx = buffer.indexOf('\n')) >= 0) {
                const line = buffer.slice(0, idx).trim();
                buffer = buffer.slice(idx + 1);
                if (line.length === 0) continue;
                stdoutLines.push(line);
                try {
                    const frame = JSON.parse(line) as Frame;
                    frames.push(frame);
                    if (typeof frame.id === 'number') pending.delete(frame.id);
                } catch {
                    /* non-JSON line — asserted by the test */
                }
                if (pending.size === 0) {
                    child.kill('SIGTERM');
                }
            }
        });
        child.on('exit', (code, signal) => {
            clearTimeout(timer);
            resolve({ frames, stdoutLines, stderr, exitCode: code, signal });
        });
        child.on('error', reject);
        for (const m of messages) child.stdin.write(`${JSON.stringify(m)}\n`);
    });
}

/** Clean-exit assertion, platform-aware (see runStdioSession). */
function expectCleanExit(session: StdioSession): void {
    if (process.platform === 'win32') {
        // TerminateProcess: the child is gone, but no exit code is meaningful.
        expect(session.exitCode !== null || session.signal !== null, 'child process did not terminate').toBe(true);
        return;
    }
    expect(session.signal, `server was killed by ${session.signal} instead of exiting on SIGTERM; stderr: ${session.stderr}`).toBeNull();
    expect(session.exitCode, `SIGTERM exit code; stderr: ${session.stderr}`).toBe(0);
}

describe.skipIf(!hasDist)('dist/cli.js over stdio', () => {
    it.each(['2025-03-26', '2025-06-18'])('negotiates the older 2025 revision %s on stdio and serves tools/list', async (version) => {
        const session = await runStdioSession(
            [
                { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: version, capabilities: {}, clientInfo: { name: 'legacy', version: '0' } } },
                { jsonrpc: '2.0', method: 'notifications/initialized' },
                { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
            ],
            [1, 2],
        );
        const init = session.frames.find((f) => f.id === 1)?.result as { protocolVersion?: string } | undefined;
        expect(init?.protocolVersion).toBe(version);
        const tools = (session.frames.find((f) => f.id === 2)?.result as { tools?: Array<{ name: string }> } | undefined)?.tools ?? [];
        expect(tools.length).toBe(toolNames().length);
    });

    it('serves a legacy initialize → tools/list → tools/call session with JSON-only stdout', async () => {
        const session = await runStdioSession(
            [
                { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'smoke', version: '0' } } },
                { jsonrpc: '2.0', method: 'notifications/initialized' },
                { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
                {
                    jsonrpc: '2.0',
                    id: 3,
                    method: 'tools/call',
                    // A signature check and a produced artefact: every byte of the answer must be a JSON-RPC frame, never a stray log line.
                    params: { name: 'create_certificate', arguments: { spec: { serialNumber: 7, subject: { CN: 'stdio smoke' }, notBefore: '2027-01-01T00:00:00Z', validityDays: 1 }, signer: { key: { pem: fixtureText('ed25519.key.pem') } } } },
                },
            ],
            [1, 2, 3],
        );

        // Every stdout line must be a JSON-RPC frame — engine diagnostics (the
        // unpinned-timestamp warning triggered above) must never leak onto stdout.
        for (const line of session.stdoutLines) {
            expect(() => JSON.parse(line), `non-JSON stdout line: ${line.slice(0, 120)}`).not.toThrow();
        }
        expect(session.stderr).toContain('[pkinative-mcp] ready (stdio transport');

        const init = session.frames.find((f) => f.id === 1)?.result as { protocolVersion?: string; serverInfo?: { name?: string } } | undefined;
        expect(init?.protocolVersion).toBe('2025-11-25');
        expect(init?.serverInfo?.name).toBe('pkinative-mcp');

        const tools = (session.frames.find((f) => f.id === 2)?.result as { tools?: Array<{ name: string }> } | undefined)?.tools ?? [];
        expect(tools.length).toBe(toolNames().length);

        const call = session.frames.find((f) => f.id === 3)?.result as { isError?: boolean; content?: Array<{ type: string; resource?: { mimeType?: string } }>; structuredContent?: { diagnostics?: Array<{ code: string }> } } | undefined;
        expect(call?.isError).not.toBe(true);
        expect(call?.content?.some((c) => c.type === 'resource' && c.resource?.mimeType === 'application/x-pem-file')).toBe(true);
        expect((call?.structuredContent as { summary?: { signatureVerified?: boolean } } | undefined)?.summary?.signatureVerified).toBe(true);
        // The private key given inline never comes back in any frame.
        expect(session.stdoutLines.join('\n')).not.toContain(fixtureText('ed25519.key.pem').split('\n')[1]);
    });

    it('exits cleanly on SIGTERM once the session is done', async () => {
        const session = await runStdioSession(
            [{ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'smoke', version: '0' } } }],
            [1],
        );
        expect(session.frames.find((f) => f.id === 1)?.result).toBeDefined();
        expectCleanExit(session);
    });

    it('answers a 2026-07-28 server/discover probe', async () => {
        const session = await runStdioSession(
            [
                {
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'server/discover',
                    params: {
                        _meta: {
                            'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                            'io.modelcontextprotocol/clientCapabilities': {},
                            'io.modelcontextprotocol/clientInfo': { name: 'smoke', version: '0' },
                        },
                    },
                },
            ],
            [1],
        );
        const result = session.frames.find((f) => f.id === 1)?.result as { supportedVersions?: string[]; resultType?: string; capabilities?: Record<string, unknown>; instructions?: string; ttlMs?: number; cacheScope?: string; _meta?: Record<string, unknown> } | undefined;
        expect(result?.resultType).toBe('complete');
        expect(result?.supportedVersions).toContain('2026-07-28');
        // A-016: the discover capabilities on stdio match the HTTP transport (tools / prompts / resources, never logging).
        expect(Object.keys(result?.capabilities ?? {})).toEqual(expect.arrayContaining(['tools', 'prompts', 'resources']));
        expect(result?.capabilities?.['logging']).toBeUndefined();
        expect(String(result?.instructions)).toContain('DECISION TREE');
        expect(result?.ttlMs).toBe(3_600_000);
        expect(result?.cacheScope).toBe('public');
        expect((result?._meta?.['io.modelcontextprotocol/serverInfo'] as { name: string } | undefined)?.name).toBe('pkinative-mcp');
    });
});

/**
 * The 256 MiB frame edge (STDIO_MAX_FRAME_BYTES), asserted at the exact
 * boundary the SDK enforces: `ReadBuffer.append` refuses a chunk once
 * `buffered + chunk.length > maxBufferSize`, so a line of CAP − 1 bytes plus
 * its newline (= CAP bytes) is the largest frame accepted and a line of CAP
 * bytes plus its newline is refused ("ReadBuffer exceeded maximum size").
 *
 * The transport is driven IN PROCESS with the exact wiring of src/cli.ts
 * (`StdioServerTransport` with the raised cap + `serveStdio` legacy 'serve')
 * on PassThrough streams, pushing each frame as ONE chunk: the boundary is
 * only exact per chunk, and the SDK re-concatenates the buffer on every pipe
 * chunk (quadratic — a 256 MiB frame through a real 64 KiB-chunked pipe takes
 * well over ten minutes, which is a transport-throughput property, not a
 * cap property). Half a gigabyte of strings is still involved, so the pair
 * runs only under PKINATIVE_MCP_SLOW_TESTS=1.
 */
describe.skipIf(!process.env['PKINATIVE_MCP_SLOW_TESTS'])('stdio transport — the 256 MiB frame edge (PKINATIVE_MCP_SLOW_TESTS)', () => {
    const HEAD = '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inspect_certificate","arguments":{"certificate":{"derBase64":"';
    const TAIL = '"}}}}';

    /** A JSON-RPC line of exactly `lineBytes` bytes (ASCII, so bytes = chars). */
    function lineOf(lineBytes: number): string {
        return `${HEAD}${'A'.repeat(lineBytes - HEAD.length - TAIL.length)}${TAIL}`;
    }

    interface InProcess {
        stdin: PassThrough;
        frames: Frame[];
        errors: Error[];
        waitFor(id: number, timeoutMs: number): Promise<Frame | undefined>;
        close(): Promise<void>;
    }

    async function openInProcess(): Promise<InProcess> {
        const { serveStdio, StdioServerTransport } = await import('@modelcontextprotocol/server/stdio');
        const { createServer } = await import('../src/server.js');
        const stdin = new PassThrough();
        const stdout = new PassThrough();
        const transport = new StdioServerTransport(stdin, stdout, { maxBufferSize: STDIO_MAX_FRAME_BYTES });
        const errors: Error[] = [];
        const frames: Frame[] = [];
        const waiters = new Map<number, (f: Frame) => void>();
        let buffer = '';
        stdout.on('data', (c: Buffer) => {
            buffer += c.toString('utf8');
            let idx: number;
            while ((idx = buffer.indexOf('\n')) >= 0) {
                const line = buffer.slice(0, idx).trim();
                buffer = buffer.slice(idx + 1);
                if (line.length === 0) continue;
                const frame = JSON.parse(line) as Frame;
                frames.push(frame);
                if (typeof frame.id === 'number') waiters.get(frame.id)?.(frame);
            }
        });
        const handle = serveStdio(() => createServer(), { legacy: 'serve', onerror: (e) => errors.push(e), transport });
        // serveStdio installs its own wire error hook; observe it too so a read-buffer refusal is visible either way.
        const previous = transport.onerror;
        transport.onerror = (e): void => {
            errors.push(e);
            previous?.(e);
        };
        const write = (line: string): void => {
            stdin.write(`${line}\n`);
        };
        write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'edge', version: '0' } } }));
        const waitFor = (id: number, timeoutMs: number): Promise<Frame | undefined> => new Promise((resolve) => {
            const known = frames.find((f) => f.id === id);
            if (known !== undefined) {
                resolve(known);
                return;
            }
            const timer = setTimeout(() => {
                waiters.delete(id);
                resolve(undefined);
            }, timeoutMs);
            waiters.set(id, (f) => {
                clearTimeout(timer);
                resolve(f);
            });
        });
        expect(await waitFor(1, 20_000), 'initialize answered').toBeDefined();
        write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }));
        return { stdin, frames, errors, waitFor, close: () => handle.close() };
    }

    it('a line of CAP − 1 bytes (CAP with its newline) is accepted and answered — INPUT_TOO_LARGE, since 192 MiB decoded exceeds the 64 MiB maxInputBytes cap', async () => {
        const session = await openInProcess();
        try {
            session.stdin.write(Buffer.from(`${lineOf(STDIO_MAX_FRAME_BYTES - 1)}\n`, 'latin1'));
            const answer = await session.waitFor(2, 240_000);
            expect(session.errors.map((e) => e.message)).toEqual([]);
            const call = answer?.result as { isError?: boolean; content?: Array<{ text?: string }> } | undefined;
            expect(call?.isError).toBe(true);
            expect(call?.content?.[0]?.text).toContain('INPUT_TOO_LARGE');
            // The transport is still alive afterwards.
            session.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} })}\n`);
            expect((await session.waitFor(3, 20_000))?.result).toBeDefined();
        } finally {
            await session.close();
        }
    }, 300_000);

    it('a line of CAP bytes (CAP + 1 with its newline) is refused by the read buffer, never answered, and the transport closes', async () => {
        const session = await openInProcess();
        try {
            session.stdin.write(Buffer.from(`${lineOf(STDIO_MAX_FRAME_BYTES)}\n`, 'latin1'));
            expect(await session.waitFor(2, 15_000)).toBeUndefined();
            expect(session.errors.map((e) => e.message).join('\n')).toContain(`ReadBuffer exceeded maximum size of ${STDIO_MAX_FRAME_BYTES} bytes`);
            // Closed: a further request is never answered.
            session.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} })}\n`);
            expect(await session.waitFor(3, 3_000)).toBeUndefined();
        } finally {
            await session.close().catch(() => undefined);
        }
    }, 300_000);
});
