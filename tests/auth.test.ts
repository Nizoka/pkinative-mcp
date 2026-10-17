/**
 * Opt-in HTTP bearer token (`PKINATIVE_MCP_HTTP_TOKEN`): the loopback bind and
 * Host/Origin guard do not stop other local processes, so operators can require
 * a shared secret on every request.
 */
import { describe, expect, it } from 'vitest';

import { HTTP_TOKEN_ENV, HTTP_TOKEN_MIN_LENGTH, guardBearer, readHttpToken } from '../src/auth.js';
import { toolNames } from '../src/server.js';

const TOKEN = 'correct-horse-battery-staple-42';

function req(authorization?: string): Request {
    return new Request('http://127.0.0.1:9/mcp', { method: 'POST', headers: authorization !== undefined ? { authorization } : {} });
}

describe('readHttpToken', () => {
    it('returns null when unset or empty (documented no-auth loopback default)', () => {
        expect(readHttpToken({})).toBeNull();
        expect(readHttpToken({ [HTTP_TOKEN_ENV]: '' })).toBeNull();
    });

    it('refuses weak or whitespace-bearing values instead of silently running unprotected', () => {
        expect(() => readHttpToken({ [HTTP_TOKEN_ENV]: 'short' })).toThrow(new RegExp(`at least ${HTTP_TOKEN_MIN_LENGTH}`));
        expect(() => readHttpToken({ [HTTP_TOKEN_ENV]: 'has whitespace inside it' })).toThrow(/no whitespace/);
        expect(readHttpToken({ [HTTP_TOKEN_ENV]: TOKEN })).toBe(TOKEN);
    });
});

describe('guardBearer', () => {
    it('is a no-op when no token is configured', () => {
        expect(guardBearer(req(), null)).toBeUndefined();
    });

    it('answers 401 + WWW-Authenticate without echoing the token for missing, malformed or wrong credentials', async () => {
        for (const header of [undefined, 'Basic abc', `Bearer ${TOKEN}x`, 'Bearer', `Bearer ${TOKEN.slice(0, -1)}`]) {
            const res = guardBearer(req(header), TOKEN);
            expect(res, String(header)).toBeDefined();
            expect(res!.status).toBe(401);
            expect(res!.headers.get('www-authenticate')).toMatch(/^Bearer realm="pkinative-mcp"/);
            // RFC 6750 §3.1: the error attribute only when credentials were actually presented.
            expect(res!.headers.get('www-authenticate')?.includes('error=')).toBe(header !== undefined);
            const body = await res!.text();
            expect(body).not.toContain(TOKEN);
            expect(JSON.parse(body)).toMatchObject({ jsonrpc: '2.0', id: null, error: { code: -32600 } });
        }
    });

    it('lets a matching bearer through (case-insensitive scheme, trailing whitespace tolerated)', () => {
        expect(guardBearer(req(`Bearer ${TOKEN}`), TOKEN)).toBeUndefined();
        expect(guardBearer(req(`bearer ${TOKEN} `), TOKEN)).toBeUndefined();
    });
});

describe('HTTP fixture with a bearer token (end-to-end)', () => {
    it('rejects unauthenticated requests with 401 and serves authenticated ones', async () => {
        const { startHttpFixture, send, modernRequest } = await import('./_http-fixture.js');
        const fx = await startHttpFixture({ httpToken: TOKEN });
        try {
            const req = modernRequest('tools/list');
            const denied = await send(fx.port, { headers: req.headers, body: req.body });
            expect(denied.status).toBe(401);
            expect(denied.headers['www-authenticate']).toMatch(/^Bearer /);
            const ok = await send(fx.port, { headers: { ...req.headers, authorization: `Bearer ${TOKEN}` }, body: req.body });
            expect(ok.status).toBe(200);
            expect(((ok.json?.['result'] as { tools?: unknown[] })?.tools ?? []).length).toBe(toolNames().length);
        } finally {
            await fx.close();
        }
    });
});
