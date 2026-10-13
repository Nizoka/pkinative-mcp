import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { Agent, request as httpRequest } from 'node:http';
import type { Socket } from 'node:net';

import { ensureEngineReady } from '../src/server.js';
import { MAX_REQUEST_BODY_BYTES } from '../src/http.js';
import { startHttpFixture, send, modernRequest, JSON_HEADERS, type HttpFixture } from './_http-fixture.js';

/**
 * HTTP transport hardening regressions:
 *   - the request-body cap (413 path) — exercised through an injected
 *     cap so the test does not have to push 256 MiB over loopback.
 *   - keep-alive connections must not accumulate socket listeners
 *     (the disconnect guard is observed on the per-request response object).
 *   - 2026-07-28 `subscriptions/listen`: what this stateless server answers
 *     when nothing is subscribable, and that a client hang-up tears it down.
 */
describe('HTTP transport — request-body cap', () => {
    const CAP = 4096;
    let fx: HttpFixture;

    beforeAll(async () => {
        await ensureEngineReady();
        fx = await startHttpFixture({ maxBodyBytes: CAP });
    });
    afterAll(async () => {
        await fx.close();
    });

    it('keeps the production default at 256 MiB', () => {
        expect(MAX_REQUEST_BODY_BYTES).toBe(256 * 1024 * 1024);
    });

    it('answers 413 Payload Too Large (the src/cli.ts contract) when the body exceeds the cap', async () => {
        // A syntactically valid JSON-RPC body padded past the cap — the cap must win before parsing.
        const padding = 'x'.repeat(CAP);
        const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: { note: padding } } });
        expect(Buffer.byteLength(body)).toBeGreaterThan(CAP);
        const r = await send(fx.port, { headers: JSON_HEADERS, body });
        expect(r.status).toBe(413);
        expect(r.headers['content-type']).toBe('text/plain');
        expect(r.text).toBe('Payload Too Large');
        // Not an internal error: nothing reached the onerror sink.
        expect(fx.errors).toEqual([]);
    });

    it('serves a body just under the cap normally', async () => {
        const { headers, body } = modernRequest('tools/list');
        expect(Buffer.byteLength(body)).toBeLessThanOrEqual(CAP);
        const r = await send(fx.port, { headers, body });
        expect(r.status).toBe(200);
        const result = r.json?.['result'] as Record<string, unknown>;
        expect(Array.isArray(result['tools'])).toBe(true);
    });

    it('still serves the next request on the same server after a 413', async () => {
        const over = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: { note: 'y'.repeat(CAP) } } });
        expect((await send(fx.port, { headers: JSON_HEADERS, body: over })).status).toBe(413);
        const { headers, body } = modernRequest('server/discover');
        expect((await send(fx.port, { headers, body })).status).toBe(200);
    });
});

describe('HTTP transport — keep-alive listener hygiene', () => {
    let fx: HttpFixture;
    const sockets = new Set<Socket>();
    const warnings: Error[] = [];
    const onWarning = (w: Error): void => {
        warnings.push(w);
    };

    beforeAll(async () => {
        await ensureEngineReady();
        fx = await startHttpFixture();
        fx.httpServer.on('connection', (socket) => sockets.add(socket));
        process.on('warning', onWarning);
    });
    afterAll(async () => {
        process.off('warning', onWarning);
        await fx.close();
    });

    it('serves 30 requests over one keep-alive socket without MaxListenersExceededWarning and with bounded socket listeners', async () => {
        const agent = new Agent({ keepAlive: true, maxSockets: 1 });
        try {
            const { headers, body } = modernRequest('server/discover');
            for (let i = 0; i < 30; i++) {
                const r = await send(fx.port, { headers, body, agent });
                expect(r.status, `request #${i}`).toBe(200);
            }
        } finally {
            agent.destroy();
        }
        // One connection carried every request (the premise of the regression).
        expect(sockets.size).toBe(1);
        const socket = [...sockets][0]!;
        // The per-request guard lives on the response, so the shared socket must
        // not grow a 'close' listener per request (Node warns at > 10).
        expect(socket.listenerCount('close')).toBeLessThanOrEqual(10);
        expect(warnings.filter((w) => w.name === 'MaxListenersExceededWarning')).toEqual([]);
    });
});

describe('HTTP transport — subscriptions/listen on a stateless server', () => {
    let fx: HttpFixture;

    beforeAll(async () => {
        await ensureEngineReady();
        fx = await startHttpFixture();
    });
    afterAll(async () => {
        await fx.close();
    });
    afterEach(() => {
        expect(fx.errors).toEqual([]);
    });

    /** Open a listen stream, resolve with the first SSE frame, then hang up like a vanished client. */
    function listenFirstFrame(params: Record<string, unknown>): Promise<{ status: number; contentType: string; first: Record<string, unknown>; closed: Promise<void> }> {
        const { headers, body } = modernRequest('subscriptions/listen', params);
        return new Promise((resolve, reject) => {
            const req = httpRequest(
                { host: '127.0.0.1', port: fx.port, path: '/mcp', method: 'POST', headers: { ...headers, 'content-length': Buffer.byteLength(body) } },
                (res) => {
                    let buffer = '';
                    const closed = new Promise<void>((done) => res.once('close', () => done()));
                    res.on('data', (chunk: Buffer) => {
                        buffer += chunk.toString('utf8');
                        const line = buffer.split('\n').find((l) => l.startsWith('data:'));
                        if (line === undefined) return;
                        res.removeAllListeners('data');
                        req.destroy(); // client goes away mid-stream
                        resolve({ status: res.statusCode ?? 0, contentType: String(res.headers['content-type']), first: JSON.parse(line.slice(5).trim()) as Record<string, unknown>, closed });
                    });
                },
            );
            req.on('error', (err: NodeJS.ErrnoException) => {
                // ECONNRESET after our own destroy() is the expected outcome.
                if (err.code !== 'ECONNRESET' && err.message !== 'socket hang up') reject(err);
            });
            req.end(body);
        });
    }

    it('acknowledges with an empty filter (nothing is subscribable) and keeps an SSE stream open', async () => {
        const { status, contentType, first, closed } = await listenFirstFrame({ notifications: { toolsListChanged: true } });
        expect(status).toBe(200);
        expect(contentType).toContain('text/event-stream');
        expect(first['method']).toBe('notifications/subscriptions/acknowledged');
        const params = first['params'] as Record<string, unknown>;
        // Stateless serving: no list-changed or resource subscription is honoured.
        expect(params['notifications']).toEqual({});
        expect((params['_meta'] as Record<string, unknown>)['io.modelcontextprotocol/subscriptionId']).toBeDefined();
        await closed;
    });

    it('rejects a listen request without a notifications filter with -32602', async () => {
        const { headers, body } = modernRequest('subscriptions/listen', {});
        const r = await send(fx.port, { headers, body });
        expect(r.status).toBe(200);
        expect((r.json?.['error'] as { code: number }).code).toBe(-32602);
    });

    it('tears the stream down when the client hangs up and keeps serving afterwards', async () => {
        const { closed } = await listenFirstFrame({ notifications: { resourcesListChanged: true } });
        await closed;
        const { headers, body } = modernRequest('server/discover');
        const r = await send(fx.port, { headers, body });
        expect(r.status).toBe(200);
        expect((r.json?.['result'] as Record<string, unknown>)['resultType']).toBe('complete');
    });
});
