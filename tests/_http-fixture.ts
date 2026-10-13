/**
 * Shared HTTP test fixture: boots the exact wiring `src/cli.ts` uses in HTTP
 * mode (node:http → `src/http.ts` bridge → `createMcpHandler` with the
 * stateless legacy fallback) on an ephemeral loopback port.
 */
import { createServer as createHttpServer, request as httpRequest, type Agent, type Server as HttpServer } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createMcpHandler, type McpHttpHandler } from '@modelcontextprotocol/server';

import { guardBearer } from '../src/auth.js';
import { guardLoopback, RequestTooLargeError, sendWebResponse, toWebRequest } from '../src/http.js';
import { createServer } from '../src/server.js';

export interface HttpFixture {
    port: number;
    origin: string;
    handler: McpHttpHandler;
    /** Underlying node:http server (for socket-level assertions). */
    httpServer: HttpServer;
    /** Errors routed to the `onerror` sink (mirrors `src/cli.ts`'s stderr log). */
    errors: Error[];
    close(): Promise<void>;
}

export interface HttpFixtureOptions {
    /** Override the request-body cap (default: `MAX_REQUEST_BODY_BYTES`). */
    readonly maxBodyBytes?: number;
    /** Opt-in bearer token (mirrors PKINATIVE_MCP_HTTP_TOKEN in src/cli.ts). */
    readonly httpToken?: string;
}

export async function startHttpFixture(opts?: HttpFixtureOptions): Promise<HttpFixture> {
    const errors: Error[] = [];
    const onerror = (err: Error): void => {
        errors.push(err);
    };
    const handler = createMcpHandler(() => createServer(), { legacy: 'stateless', onerror });
    const httpServer: HttpServer = createHttpServer();
    await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', () => resolve()));
    const port = (httpServer.address() as AddressInfo).port;
    const origin = `http://127.0.0.1:${port}`;

    // Keep this request handler byte-for-byte in step with the one in src/cli.ts
    // (404 for non-/mcp, 413 for RequestTooLargeError, 500 otherwise).
    httpServer.on('request', (req, res) => {
        void (async () => {
            try {
                const path = new URL(req.url ?? '/', origin).pathname;
                if (path !== '/mcp') {
                    res.writeHead(404, { 'Content-Type': 'text/plain' });
                    res.end('Not Found. MCP endpoint is POST /mcp');
                    return;
                }
                const request = await toWebRequest(req, origin, res, opts?.maxBodyBytes !== undefined ? { maxBodyBytes: opts.maxBodyBytes } : undefined);
                const response = guardLoopback(request) ?? guardBearer(request, opts?.httpToken ?? null) ?? (await handler.fetch(request));
                await sendWebResponse(res, response);
            } catch (err) {
                if (err instanceof RequestTooLargeError) {
                    if (!res.headersSent) res.writeHead(413, { 'Content-Type': 'text/plain' });
                    res.end('Payload Too Large');
                    return;
                }
                onerror(err instanceof Error ? err : new Error(String(err)));
                if (!res.headersSent) {
                    res.writeHead(500, { 'Content-Type': 'text/plain' });
                }
                res.end();
            }
        })();
    });

    return {
        port,
        origin,
        handler,
        httpServer,
        errors,
        close: async () => {
            await handler.close();
            await new Promise<void>((resolve) => httpServer.close(() => resolve()));
        },
    };
}

export interface HttpReply {
    status: number;
    headers: Record<string, string | string[] | undefined>;
    text: string;
    /** First JSON-RPC message found in the body (plain JSON or SSE `data:` frame). */
    json: Record<string, unknown> | undefined;
}

/** Send a raw request to the fixture and collect the whole response body. */
export function send(
    port: number,
    opts: { method?: string; path?: string; headers?: Record<string, string>; body?: string; agent?: Agent },
): Promise<HttpReply> {
    const body = opts.body;
    return new Promise<HttpReply>((resolve, reject) => {
        const req = httpRequest(
            {
                host: '127.0.0.1',
                port,
                path: opts.path ?? '/mcp',
                method: opts.method ?? 'POST',
                ...(opts.agent !== undefined ? { agent: opts.agent } : {}),
                headers: {
                    ...(body !== undefined ? { 'content-length': Buffer.byteLength(body) } : {}),
                    ...(opts.headers ?? {}),
                },
            },
            (res) => {
                const chunks: Buffer[] = [];
                res.on('data', (c: Buffer) => chunks.push(c));
                res.on('end', () => {
                    const text = Buffer.concat(chunks).toString('utf8');
                    resolve({ status: res.statusCode ?? 0, headers: res.headers, text, json: parseFirstJson(text) });
                });
            },
        );
        req.on('error', reject);
        req.end(body);
    });
}

function parseFirstJson(text: string): Record<string, unknown> | undefined {
    const trimmed = text.trim();
    if (trimmed.startsWith('{')) {
        try {
            return JSON.parse(trimmed) as Record<string, unknown>;
        } catch {
            return undefined;
        }
    }
    for (const line of trimmed.split('\n')) {
        if (line.startsWith('data:')) {
            try {
                return JSON.parse(line.slice(5).trim()) as Record<string, unknown>;
            } catch {
                /* keep scanning */
            }
        }
    }
    return undefined;
}

/** Standard JSON + SSE accept headers every MCP POST needs. */
export const JSON_HEADERS = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
} as const;

/** Legacy (2025-era) `initialize` body. */
export function legacyInitBody(protocolVersion = '2025-06-18'): string {
    return JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion, capabilities: {}, clientInfo: { name: 'test', version: '0' } },
    });
}

/** 2026-07-28 request: per-request `_meta` envelope + `Mcp-Method` / `Mcp-Name` headers. */
export function modernRequest(
    method: string,
    params: Record<string, unknown> = {},
    id = 1,
): { headers: Record<string, string>; body: string } {
    // SEP-2243: `Mcp-Name` mirrors `params.name` (tools/call, prompts/get) or `params.uri` (resources/read).
    const source = method === 'resources/read' ? params['uri'] : params['name'];
    const name = typeof source === 'string' ? source : undefined;
    return {
        headers: {
            ...JSON_HEADERS,
            'mcp-protocol-version': '2026-07-28',
            'mcp-method': method,
            ...(name !== undefined ? { 'mcp-name': name } : {}),
        },
        body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            method,
            params: {
                ...params,
                _meta: {
                    'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                    'io.modelcontextprotocol/clientCapabilities': {},
                    'io.modelcontextprotocol/clientInfo': { name: 'test', version: '0' },
                },
            },
        }),
    };
}
