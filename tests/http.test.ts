import { describe, it, expect, afterEach } from 'vitest';
import { createServer as createHttpServer, request as httpRequest, type Server as HttpServer } from 'node:http';
import type { AddressInfo } from 'node:net';

import { guardLoopback, RequestTooLargeError, sendWebResponse, toWebRequest } from '../src/http.js';

/** Unit tests for the dependency-free node:http ↔ web Request/Response bridge. */
describe('src/http.ts bridge', () => {
    let server: HttpServer | undefined;
    afterEach(async () => {
        if (server !== undefined) {
            await new Promise<void>((resolve) => server!.close(() => resolve()));
            server = undefined;
        }
    });

    async function serve(handler: (request: Request) => Promise<Response> | Response): Promise<number> {
        server = createHttpServer((req, res) => {
            void (async () => {
                const origin = `http://127.0.0.1:${(server!.address() as AddressInfo).port}`;
                const request = await toWebRequest(req, origin, res);
                await sendWebResponse(res, await handler(request));
            })();
        });
        await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', () => resolve()));
        return (server.address() as AddressInfo).port;
    }

    function raw(
        port: number,
        opts: { method: string; path?: string; headers?: Record<string, string | string[]>; body?: string },
    ): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; text: string }> {
        return new Promise((resolve, reject) => {
            const req = httpRequest({ host: '127.0.0.1', port, path: opts.path ?? '/', method: opts.method, headers: opts.headers }, (res) => {
                const chunks: Buffer[] = [];
                res.on('data', (c: Buffer) => chunks.push(c));
                res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
            });
            req.on('error', reject);
            req.end(opts.body);
        });
    }

    it('converts method, URL, headers (array values joined) and buffered body', async () => {
        let seen: { method: string; url: string; accept: string | null; body: string } | undefined;
        const port = await serve(async (request) => {
            seen = { method: request.method, url: request.url, accept: request.headers.get('accept'), body: await request.text() };
            return new Response('ok', { status: 201, headers: { 'x-test': '1' } });
        });
        const r = await raw(port, { method: 'POST', path: '/mcp?x=1', headers: { accept: ['application/json', 'text/event-stream'], 'content-type': 'text/plain' }, body: 'payload' });
        expect(r.status).toBe(201);
        expect(r.headers['x-test']).toBe('1');
        expect(r.text).toBe('ok');
        expect(seen?.method).toBe('POST');
        expect(seen?.url).toBe(`http://127.0.0.1:${port}/mcp?x=1`);
        expect(seen?.accept).toBe('application/json, text/event-stream');
        expect(seen?.body).toBe('payload');
    });

    it('passes GET without a body and writes an empty response for a null body', async () => {
        const port = await serve((request) => new Response(null, { status: 204, headers: { 'x-method': request.method } }));
        const r = await raw(port, { method: 'GET' });
        expect(r.status).toBe(204);
        expect(r.headers['x-method']).toBe('GET');
        expect(r.text).toBe('');
    });

    it('streams a ReadableStream body (SSE-style) to the Node response', async () => {
        const port = await serve(() => {
            const stream = new ReadableStream<Uint8Array>({
                start(controller) {
                    controller.enqueue(new TextEncoder().encode('event: a\ndata: 1\n\n'));
                    controller.enqueue(new TextEncoder().encode('event: b\ndata: 2\n\n'));
                    controller.close();
                },
            });
            return new Response(stream, { status: 200, headers: { 'content-type': 'text/event-stream' } });
        });
        const r = await raw(port, { method: 'GET' });
        expect(r.status).toBe(200);
        expect(r.headers['content-type']).toBe('text/event-stream');
        expect(r.text).toContain('data: 1');
        expect(r.text).toContain('data: 2');
    });

    it('throws RequestTooLargeError when the body exceeds the injected cap and reads a body at the cap', async () => {
        const outcomes: Array<string | number> = [];
        server = createHttpServer((req, res) => {
            void (async () => {
                const origin = `http://127.0.0.1:${(server!.address() as AddressInfo).port}`;
                try {
                    const request = await toWebRequest(req, origin, res, { maxBodyBytes: 8 });
                    outcomes.push((await request.text()).length);
                    res.writeHead(200).end('ok');
                } catch (err) {
                    outcomes.push(err instanceof RequestTooLargeError ? `${err.name}:${err.message}` : 'other');
                    res.writeHead(413).end();
                }
            })();
        });
        await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', () => resolve()));
        const port = (server.address() as AddressInfo).port;
        expect((await raw(port, { method: 'POST', body: '12345678' })).status).toBe(200);
        expect((await raw(port, { method: 'POST', body: '123456789' })).status).toBe(413);
        expect(outcomes).toEqual([8, 'RequestTooLargeError:request body exceeds 8 bytes']);
    });

    it('guardLoopback rejects foreign Host/Origin and accepts loopback', () => {
        const ok = new Request('http://127.0.0.1:1234/mcp', { method: 'POST', headers: { host: '127.0.0.1:1234', origin: 'http://localhost:1234' } });
        expect(guardLoopback(ok)).toBeUndefined();
        const noOrigin = new Request('http://127.0.0.1:1234/mcp', { method: 'POST', headers: { host: 'localhost:1234' } });
        expect(guardLoopback(noOrigin)).toBeUndefined();
        const badHost = new Request('http://127.0.0.1:1234/mcp', { method: 'POST', headers: { host: 'evil.example.com' } });
        expect(guardLoopback(badHost)?.status).toBe(403);
        const badOrigin = new Request('http://127.0.0.1:1234/mcp', { method: 'POST', headers: { host: '127.0.0.1:1234', origin: 'http://evil.example.com' } });
        expect(guardLoopback(badOrigin)?.status).toBe(403);
    });

    it('guardLoopback pins the Origin port: a local page on another port is still cross-site', async () => {
        for (const origin of ['http://localhost:3000', 'http://127.0.0.1', 'https://localhost', 'http://[::1]:9999']) {
            const r = new Request('http://127.0.0.1:1234/mcp', { method: 'POST', headers: { host: '127.0.0.1:1234', origin } });
            const res = guardLoopback(r);
            expect(res?.status, origin).toBe(403);
            expect(await res!.text()).toMatch(/Origin port/);
        }
        const same = new Request('http://127.0.0.1:1234/mcp', { method: 'POST', headers: { host: '127.0.0.1:1234', origin: 'http://[::1]:1234' } });
        expect(guardLoopback(same)).toBeUndefined();
    });
});

describe('src/http.ts bridge — client disconnect aborts the in-flight request', () => {
    // Synchronised on events only: the client hangs up once the server has built
    // the web Request, and the test waits for the signal's own 'abort' event.
    it('aborts the web Request signal when the POST client goes away before the response', async () => {
        const server = createHttpServer();
        let requestReady!: (request: Request) => void;
        const gotRequest = new Promise<Request>((resolve) => {
            requestReady = resolve;
        });
        let release!: () => void;
        const released = new Promise<void>((resolve) => {
            release = resolve;
        });
        server.on('request', (req, res) => {
            void (async () => {
                const port = (server.address() as AddressInfo).port;
                const request = await toWebRequest(req, `http://127.0.0.1:${port}`, res);
                requestReady(request);
                await released; // hold the response until the test has observed the abort
                res.end();
            })();
        });
        await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
        const port = (server.address() as AddressInfo).port;

        const client = httpRequest({ host: '127.0.0.1', port, path: '/mcp', method: 'POST', headers: { 'content-type': 'application/json' } });
        client.on('error', () => undefined);
        client.end('{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}');

        const request = await gotRequest;
        expect(request.signal.aborted).toBe(false);
        const aborted = new Promise<void>((resolve) => request.signal.addEventListener('abort', () => resolve(), { once: true }));
        client.destroy();
        await aborted;
        expect(request.signal.aborted).toBe(true);

        release();
        await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it('does not abort the signal when the response completes normally', async () => {
        const server = createHttpServer();
        const gotRequest = new Promise<Request>((resolve) => {
            server.on('request', (req, res) => {
                void (async () => {
                    const port = (server.address() as AddressInfo).port;
                    const request = await toWebRequest(req, `http://127.0.0.1:${port}`, res);
                    await sendWebResponse(res, new Response('ok', { status: 200 }));
                    resolve(request);
                })();
            });
        });
        await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
        const port = (server.address() as AddressInfo).port;
        const done = new Promise<void>((resolve, reject) => {
            const client = httpRequest({ host: '127.0.0.1', port, path: '/mcp', method: 'POST' }, (res) => {
                res.resume();
                res.once('end', () => resolve());
            });
            client.on('error', reject);
            client.end('{}');
        });
        const request = await gotRequest;
        await done;
        expect(request.signal.aborted).toBe(false);
        await new Promise<void>((resolve) => server.close(() => resolve()));
    });
});
