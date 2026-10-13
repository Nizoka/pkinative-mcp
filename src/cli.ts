#!/usr/bin/env node
/**
 * CLI entry — wires the MCP server to a stdio transport (default) or a
 * Streamable HTTP endpoint when PKINATIVE_MCP_PORT is set.
 *
 * Protocol: MCP 2026-07-28 (stateless, `server/discover`, `subscriptions/listen`)
 * with automatic fallback to the 2025-era `initialize` handshake, so both
 * current and legacy clients (Claude Desktop, Cursor, Continue, …) are served
 * by the same binary.
 *
 * Transport selection:
 *   - stdio (default): suitable for local host integration (Claude Desktop, Cursor, etc.)
 *   - PKINATIVE_MCP_MAX_INPUT_BYTES / PKINATIVE_MCP_MAX_KDF_ITERATIONS /
 *     PKINATIVE_MCP_MAX_PATHS_EXPLORED are the operator ceilings per-call
 *     `limits` cannot exceed (read once; an invalid value refuses to start).
 *   - PKINATIVE_MCP_AT pins the instant every omitted `at` / `notBefore` /
 *     `signingTime` falls back to (read once; an invalid value refuses to start).
 *   - PKINATIVE_MCP_PASSWORD is the operator-side password source (its value
 *     is never logged; only its presence is).
 *   - HTTP: set PKINATIVE_MCP_PORT=<port> to expose the MCP endpoint on that port.
 *           Requests are POST /mcp (2026-07-28 clients send `Mcp-Method` / `Mcp-Name`
 *           headers and the `_meta` envelope; 2025-era clients use `initialize`).
 *           GET/DELETE answer 405 (stateless serving; no SSE resumability).
 *           Bound to 127.0.0.1 only; foreign Host/Origin headers are rejected (403).
 *
 * @example Claude Desktop config (stdio)
 * ```json
 * {
 *   "mcpServers": {
 *     "pkinative": {
 *       "command": "npx",
 *       "args": ["-y", "pkinative-mcp"],
 *       "env": { "PKINATIVE_MCP_OUTPUT_DIR": "/Users/me/Documents/mcp-pki" }
 *     }
 *   }
 * }
 * ```
 *
 * @example HTTP mode
 * ```bash
 * PKINATIVE_MCP_PORT=3000 npx pkinative-mcp
 * # Then connect via: http://127.0.0.1:3000/mcp
 * ```
 */
import { getCeilings, MAX_INPUT_BYTES_ENV, MAX_KDF_ITERATIONS_ENV, MAX_PATHS_EXPLORED_ENV, STDIO_MAX_FRAME_BYTES } from './caps.js';
import { PASSWORD_ENV } from './secrets.js';
import { createServer, ensureEngineReady } from './server.js';
import { AT_ENV, formatInstant, readPinnedInstant } from './time.js';

function log(line: string): void {
    process.stderr.write(`[pkinative-mcp] ${line}\n`);
}

async function main(): Promise<void> {
    await ensureEngineReady();
    // Operator knobs are read once; an invalid value throws before serving.
    const ceilings = getCeilings();
    for (const [env, value] of [[MAX_INPUT_BYTES_ENV, ceilings.maxInputBytes], [MAX_KDF_ITERATIONS_ENV, ceilings.maxKdfIterations], [MAX_PATHS_EXPLORED_ENV, ceilings.maxPathsExplored]] as const) {
        if (process.env[env] !== undefined && process.env[env] !== '') log(`${env} = ${value}`);
    }
    const pinned = readPinnedInstant();
    if (pinned !== null) log(`${AT_ENV} = ${formatInstant(pinned)}`);
    if ((process.env[PASSWORD_ENV] ?? '') !== '') log(`${PASSWORD_ENV} is set (value never logged)`);

    const factory = (): ReturnType<typeof createServer> => createServer();
    const onerror = (err: Error): void => log(`transport error: ${err.message}`);
    const portEnv = process.env['PKINATIVE_MCP_PORT'];
    const port = portEnv !== undefined ? parseInt(portEnv, 10) : NaN;

    if (!Number.isNaN(port) && port > 0 && port < 65536) {
        // --- HTTP / Streamable HTTP transport ---
        const { createMcpHandler } = await import('@modelcontextprotocol/server');
        const { guardLoopback, sendWebResponse, toWebRequest, RequestTooLargeError } = await import('./http.js');
        const { createServer: createHttpServer } = await import('node:http');
        const { guardBearer, readHttpToken } = await import('./auth.js');
        // Opt-in bearer token (PKINATIVE_MCP_HTTP_TOKEN); a weak value throws before we listen.
        const httpToken = readHttpToken();

        // Both eras: 2026-07-28 requests are served by a fresh per-request instance;
        // 2025-era requests fall back to the stateless streamable-HTTP idiom.
        const handler = createMcpHandler(factory, { legacy: 'stateless', onerror });
        const origin = `http://127.0.0.1:${port}`;

        const httpServer = createHttpServer((req, res) => {
            void (async () => {
                try {
                    const path = new URL(req.url ?? '/', origin).pathname;
                    if (path !== '/mcp') {
                        res.writeHead(404, { 'Content-Type': 'text/plain' });
                        res.end('Not Found. MCP endpoint is POST /mcp');
                        return;
                    }
                    const request = await toWebRequest(req, origin, res);
                    const response = guardLoopback(request) ?? guardBearer(request, httpToken) ?? (await handler.fetch(request));
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

        const shutdown = async (signal: string): Promise<void> => {
            log(`received ${signal}, shutting down...`);
            try {
                await handler.close();
                httpServer.close();
            } finally {
                process.exit(0);
            }
        };
        process.on('SIGINT', () => void shutdown('SIGINT'));
        process.on('SIGTERM', () => void shutdown('SIGTERM'));

        await new Promise<void>((resolve, reject) => {
            httpServer.listen(port, '127.0.0.1', () => {
                log(`ready (HTTP transport, MCP 2026-07-28 + legacy) on ${origin}/mcp${httpToken !== null ? ' — bearer token required' : ' — no authentication (loopback only)'}`);
                resolve();
            });
            httpServer.once('error', reject);
        });
    } else {
        // --- stdio transport (default) ---
        const { serveStdio, StdioServerTransport } = await import('@modelcontextprotocol/server/stdio');

        // SDK v2 caps a single stdio frame at 10 MiB by default and closes the
        // transport (exiting the server) on overflow. Our tools legitimately
        // accept far larger inputs (multi-MiB PEM bundles and CMS messages), so
        // raise the cap to the server's own envelope (see STDIO_MAX_FRAME_BYTES).
        const transport = new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: STDIO_MAX_FRAME_BYTES });

        // The opening exchange pins the protocol era for this process
        // (`server/discover` probe → 2026-07-28, `initialize` → legacy).
        const handle = serveStdio(factory, { legacy: 'serve', onerror, transport });

        const shutdown = async (signal: string): Promise<void> => {
            log(`received ${signal}, shutting down...`);
            try {
                await handle.close();
            } finally {
                process.exit(0);
            }
        };
        process.on('SIGINT', () => void shutdown('SIGINT'));
        process.on('SIGTERM', () => void shutdown('SIGTERM'));

        log('ready (stdio transport, MCP 2026-07-28 + legacy)');
    }
}

main().catch((err: unknown) => {
    // Configuration errors (weak token, bad ceiling, bad pin) are reported as one clean line; anything
    // unexpected keeps its stack so the operator can file it. A password value is never part of either.
    const configError = err instanceof Error && /PKINATIVE_MCP_/.test(err.message);
    const message = err instanceof Error ? (configError ? err.message : err.stack ?? err.message) : String(err);
    log(`fatal: ${message}`);
    process.exit(1);
});
