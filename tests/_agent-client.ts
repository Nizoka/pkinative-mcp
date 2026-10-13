/**
 * Scripted "autonomous agent" client: ONE interface over the four transport ×
 * era combinations the server promises to serve, so a scenario written once
 * (tests/autonomy.test.ts) is replayed verbatim against each of them.
 *
 *   stdio-legacy   spawn dist/cli.js, 2025-era `initialize` + `notifications/initialized`
 *   stdio-modern   spawn dist/cli.js, 2026-07-28 `server/discover` probe, then every
 *                  request carries the per-request `_meta` envelope (the SDK v2 stdio
 *                  entry pins the connection to the modern era and refuses an
 *                  envelope-less request with -32602 — verified empirically)
 *   http-legacy    in-process Streamable HTTP fixture (tests/_http-fixture.ts),
 *                  2025-era `initialize`, plain requests with `mcp-protocol-version`
 *   http-modern    same fixture, `Mcp-Method` / `Mcp-Name` headers + `_meta` envelope,
 *                  optional `Authorization: Bearer` (PKINATIVE_MCP_HTTP_TOKEN)
 *
 * The stdio transports talk newline-delimited JSON-RPC to the real binary (a
 * child process with the caller's environment); the HTTP transports apply the
 * environment to this process (the fixture builds servers in-process) and
 * restore it on close. Every `isError` tool result is recorded in `errors` so a
 * scenario can assert the error contract over the whole run.
 */
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { expect } from 'vitest';
import type { CallToolResult } from '@modelcontextprotocol/server';

import { __resetCeilingsForTests } from '../src/caps.js';
import { JSON_HEADERS, legacyInitBody, modernRequest, send, startHttpFixture, type HttpFixture } from './_http-fixture.js';
import { McpRpcError, type JsonRpcError } from './_mcp-harness.js';

export { McpRpcError } from './_mcp-harness.js';

export type AgentTransport = 'stdio-legacy' | 'stdio-modern' | 'http-legacy' | 'http-modern';

export const AGENT_TRANSPORTS: readonly AgentTransport[] = ['stdio-legacy', 'stdio-modern', 'http-legacy', 'http-modern'];

export interface AgentOptions {
    /** Environment applied to the child (stdio) or to this process (HTTP) for the session's lifetime. */
    readonly env: Record<string, string>;
    /** Bearer token (http-modern); also exported as PKINATIVE_MCP_HTTP_TOKEN. */
    readonly token?: string;
    /** Legacy revision to negotiate (stdio-legacy / http-legacy). Default 2025-11-25. */
    readonly legacyVersion?: string;
    /** Per-request timeout in ms (stdio). */
    readonly requestTimeoutMs?: number;
}

export interface AgentCloseReport {
    exitCode: number | null;
    signal: NodeJS.Signals | null;
    /** Every non-empty stdout line the child wrote (stdio) — empty for HTTP. */
    stdoutLines: string[];
    /** Child stderr (stdio) or the fixture's `onerror` sink messages joined by newlines (HTTP). */
    stderr: string;
}

/** A wire `tools/call` result: the SDK's shape plus the 2026-07-28 additions. */
export type AgentCallToolResult = CallToolResult & { resultType?: string; _meta?: Record<string, unknown> };

export interface RecordedError {
    readonly tool: string;
    readonly args: Record<string, unknown>;
    readonly result: AgentCallToolResult;
}

export interface AgentClient {
    readonly transport: AgentTransport;
    readonly era: 'legacy' | 'modern';
    /** The `initialize` result (legacy) or the `server/discover` result (modern). */
    readonly handshake: Record<string, unknown>;
    /** Every `isError` result seen through `callTool`, in call order. */
    readonly errors: RecordedError[];
    request<T = Record<string, unknown>>(method: string, params?: Record<string, unknown>): Promise<T>;
    callTool(name: string, args?: Record<string, unknown>): Promise<AgentCallToolResult>;
    /** Write one raw line to the child's stdin (stdio only; throws on HTTP). */
    sendRaw(line: string): void;
    /** Every non-empty stdout line received so far (stdio; empty on HTTP) — the live transcript. */
    transcript(): readonly string[];
    close(): Promise<AgentCloseReport>;
}

const here = path.dirname(fileURLToPath(import.meta.url));
/** The built CLI the stdio transports spawn. */
export const CLI_PATH = path.resolve(here, '..', 'dist', 'cli.js');
export const hasDist = existsSync(CLI_PATH);
export const inCi = process.env.CI !== undefined && process.env.CI !== '' && process.env.CI !== 'false';

export const MODERN_PROTOCOL_VERSION = '2026-07-28';
export const DEFAULT_LEGACY_VERSION = '2025-11-25';
export const SERVER_INFO_KEY = 'io.modelcontextprotocol/serverInfo';

/** The 2026-07-28 per-request envelope every modern request carries in `params._meta`. */
export function modernEnvelope(): Record<string, unknown> {
    return {
        'io.modelcontextprotocol/protocolVersion': MODERN_PROTOCOL_VERSION,
        'io.modelcontextprotocol/clientCapabilities': {},
        'io.modelcontextprotocol/clientInfo': { name: 'agent', version: '0' },
    };
}

function isModern(transport: AgentTransport): boolean {
    return transport === 'stdio-modern' || transport === 'http-modern';
}

function isStdio(transport: AgentTransport): boolean {
    return transport === 'stdio-legacy' || transport === 'stdio-modern';
}

export function isStdioTransport(transport: AgentTransport): boolean {
    return isStdio(transport);
}

export function isModernTransport(transport: AgentTransport): boolean {
    return isModern(transport);
}

/**
 * Platform-aware clean-exit assertion for a stdio session (same rationale as
 * tests/cli-stdio.test.ts): on POSIX SIGTERM runs the server's handler and the
 * child exits 0; on win32 `kill('SIGTERM')` is TerminateProcess and only
 * termination can be asserted.
 */
export function expectCleanStdioExit(report: AgentCloseReport): void {
    if (process.platform === 'win32') {
        expect(report.exitCode !== null || report.signal !== null, 'child process did not terminate').toBe(true);
        return;
    }
    expect(report.signal, `server was killed by ${report.signal} instead of exiting on SIGTERM; stderr: ${report.stderr}`).toBeNull();
    expect(report.exitCode, `SIGTERM exit code; stderr: ${report.stderr}`).toBe(0);
}

interface Pending {
    resolve: (v: unknown) => void;
    reject: (e: Error) => void;
    timer: NodeJS.Timeout;
}

function rpcError(err: unknown): McpRpcError {
    return new McpRpcError(err as JsonRpcError);
}

// ── stdio ────────────────────────────────────────────────────────────

async function openStdio(transport: 'stdio-legacy' | 'stdio-modern', opts: AgentOptions): Promise<AgentClient> {
    if (!hasDist) throw new Error(`dist/cli.js not found at ${CLI_PATH} — run \`npm run build\` first`);
    const modern = transport === 'stdio-modern';
    const timeoutMs = opts.requestTimeoutMs ?? 30_000;
    const env: NodeJS.ProcessEnv = {
        ...process.env,
        // Never inherit a transport / auth choice from the parent test process.
        PKINATIVE_MCP_PORT: '',
        PKINATIVE_MCP_HTTP_TOKEN: '',
        PKINATIVE_MCP_OUTPUT_DIR: '',
        PKINATIVE_MCP_CACHE_DIR: '',
        PKINATIVE_MCP_MAX_ENTRIES: '',
        PKINATIVE_MCP_MAX_UNCOMPRESSED_BYTES: '',
        PKINATIVE_MCP_WORKERS: '',
        ...opts.env,
        ...(opts.token !== undefined ? { PKINATIVE_MCP_HTTP_TOKEN: opts.token } : {}),
    };
    const child: ChildProcessWithoutNullStreams = spawn(process.execPath, [CLI_PATH], { stdio: ['pipe', 'pipe', 'pipe'], env });
    const stdoutLines: string[] = [];
    let stderr = '';
    let buffer = '';
    let nextId = 1;
    const pending = new Map<number, Pending>();
    const errors: RecordedError[] = [];
    const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
        child.on('exit', (code, signal) => resolve({ code, signal }));
    });
    let exitedFlag = false;
    void exited.then(() => {
        exitedFlag = true;
        for (const [id, p] of pending) {
            pending.delete(id);
            clearTimeout(p.timer);
            p.reject(new Error(`server exited before answering request ${id}; stderr: ${stderr}`));
        }
    });

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
            let frame: { id?: unknown; result?: unknown; error?: unknown };
            try {
                frame = JSON.parse(line) as { id?: unknown; result?: unknown; error?: unknown };
            } catch {
                continue; // non-JSON stdout is asserted by the scenario (stdoutLines)
            }
            if (typeof frame.id !== 'number') continue;
            const entry = pending.get(frame.id);
            if (entry === undefined) continue;
            pending.delete(frame.id);
            clearTimeout(entry.timer);
            if (frame.error !== undefined) entry.reject(rpcError(frame.error));
            else entry.resolve(frame.result);
        }
    });

    const write = (message: Record<string, unknown>): void => {
        child.stdin.write(`${JSON.stringify(message)}\n`);
    };

    const request = <T,>(method: string, params: Record<string, unknown> = {}): Promise<T> => {
        const id = nextId++;
        const wireParams = modern ? { ...params, _meta: { ...modernEnvelope(), ...((params['_meta'] as Record<string, unknown> | undefined) ?? {}) } } : params;
        return new Promise<T>((resolve, reject) => {
            if (exitedFlag) {
                reject(new Error(`server already exited; stderr: ${stderr}`));
                return;
            }
            const timer = setTimeout(() => {
                pending.delete(id);
                reject(new Error(`${transport}: request ${id} (${method}) timed out after ${timeoutMs} ms; stderr: ${stderr}`));
            }, timeoutMs);
            pending.set(id, { resolve: (v) => resolve(v as T), reject, timer });
            write({ jsonrpc: '2.0', id, method, params: wireParams });
        });
    };

    let handshake: Record<string, unknown>;
    if (modern) {
        handshake = await request<Record<string, unknown>>('server/discover');
    } else {
        handshake = await request<Record<string, unknown>>('initialize', {
            protocolVersion: opts.legacyVersion ?? DEFAULT_LEGACY_VERSION,
            capabilities: {},
            clientInfo: { name: 'agent', version: '0' },
        });
        write({ jsonrpc: '2.0', method: 'notifications/initialized' });
    }

    return {
        transport,
        era: modern ? 'modern' : 'legacy',
        handshake,
        errors,
        request,
        callTool: async (name, args = {}) => {
            const result = await request<AgentCallToolResult>('tools/call', { name, arguments: args });
            if (result.isError === true) errors.push({ tool: name, args, result });
            return result;
        },
        sendRaw: (line) => {
            child.stdin.write(line.endsWith('\n') ? line : `${line}\n`);
        },
        transcript: () => stdoutLines,
        close: async () => {
            if (!exitedFlag) child.kill('SIGTERM');
            const killer = setTimeout(() => {
                if (!exitedFlag) child.kill('SIGKILL');
            }, 15_000);
            const { code, signal } = await exited;
            clearTimeout(killer);
            return { exitCode: code, signal, stdoutLines, stderr };
        },
    };
}

// ── HTTP (in-process fixture) ────────────────────────────────────────

const ENV_KEYS = [
    'PKINATIVE_MCP_OUTPUT_DIR',
    'PKINATIVE_MCP_CACHE_DIR',
    'PKINATIVE_MCP_MAX_ENTRIES',
    'PKINATIVE_MCP_MAX_UNCOMPRESSED_BYTES',
    'PKINATIVE_MCP_WORKERS',
    'PKINATIVE_MCP_HTTP_TOKEN',
    'PKINATIVE_MCP_PORT',
] as const;

async function openHttp(transport: 'http-legacy' | 'http-modern', opts: AgentOptions): Promise<AgentClient> {
    const modern = transport === 'http-modern';
    const legacyVersion = opts.legacyVersion ?? DEFAULT_LEGACY_VERSION;

    // Apply the environment to this process for the session (restored on close).
    const saved = new Map<string, string | undefined>();
    for (const key of ENV_KEYS) saved.set(key, process.env[key]);
    for (const key of ENV_KEYS) delete process.env[key];
    for (const [key, value] of Object.entries(opts.env)) process.env[key] = value;
    if (opts.token !== undefined) process.env['PKINATIVE_MCP_HTTP_TOKEN'] = opts.token;
    __resetCeilingsForTests();

    const fx: HttpFixture = await startHttpFixture(opts.token !== undefined ? { httpToken: opts.token } : undefined);
    const errors: RecordedError[] = [];
    let nextId = 1;
    const auth: Record<string, string> = opts.token !== undefined ? { authorization: `Bearer ${opts.token}` } : {};

    const request = async <T,>(method: string, params: Record<string, unknown> = {}): Promise<T> => {
        const id = nextId++;
        let headers: Record<string, string>;
        let body: string;
        if (modern) {
            const built = modernRequest(method, params, id);
            headers = { ...built.headers, ...auth };
            body = built.body;
        } else {
            headers = { ...JSON_HEADERS, 'mcp-protocol-version': legacyVersion, ...auth };
            body = JSON.stringify({ jsonrpc: '2.0', id, method, params });
        }
        const reply = await send(fx.port, { headers, body });
        if (reply.json === undefined) {
            throw new Error(`${transport}: ${method} → HTTP ${reply.status} without a JSON-RPC body: ${reply.text.slice(0, 300)}`);
        }
        if (reply.json['error'] !== undefined) throw rpcError(reply.json['error']);
        if (reply.status !== 200) throw new Error(`${transport}: ${method} → HTTP ${reply.status}: ${reply.text.slice(0, 300)}`);
        return reply.json['result'] as T;
    };

    let handshake: Record<string, unknown>;
    if (modern) {
        handshake = await request<Record<string, unknown>>('server/discover');
    } else {
        const init = await send(fx.port, { headers: { ...JSON_HEADERS, ...auth }, body: legacyInitBody(legacyVersion) });
        if (init.json === undefined || init.json['error'] !== undefined) {
            throw init.json?.['error'] !== undefined ? rpcError(init.json['error']) : new Error(`${transport}: initialize → HTTP ${init.status}: ${init.text.slice(0, 300)}`);
        }
        handshake = init.json['result'] as Record<string, unknown>;
        await send(fx.port, {
            headers: { ...JSON_HEADERS, 'mcp-protocol-version': legacyVersion, ...auth },
            body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
        });
    }

    return {
        transport,
        era: modern ? 'modern' : 'legacy',
        handshake,
        errors,
        request,
        callTool: async (name, args = {}) => {
            const result = await request<AgentCallToolResult>('tools/call', { name, arguments: args });
            if (result.isError === true) errors.push({ tool: name, args, result });
            return result;
        },
        sendRaw: () => {
            throw new Error(`${transport}: sendRaw is a stdio-only operation`);
        },
        transcript: () => [],
        close: async () => {
            await fx.close();
            for (const key of ENV_KEYS) {
                const previous = saved.get(key);
                if (previous === undefined) delete process.env[key];
                else process.env[key] = previous;
            }
            __resetCeilingsForTests();
            return { exitCode: 0, signal: null, stdoutLines: [], stderr: fx.errors.map((e) => e.message).join('\n') };
        },
    };
}

/** Open a scripted agent session on one transport × era; the handshake is complete when it resolves. */
export function openAgent(transport: AgentTransport, opts: AgentOptions): Promise<AgentClient> {
    switch (transport) {
        case 'stdio-legacy':
        case 'stdio-modern':
            return openStdio(transport, opts);
        case 'http-legacy':
        case 'http-modern':
            return openHttp(transport, opts);
    }
}
