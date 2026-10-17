/**
 * Opt-in bearer-token gate for the HTTP transport.
 *
 * The HTTP endpoint binds to loopback and validates Host / Origin, which stops
 * DNS rebinding but not *other local processes* on the same machine. MCP
 * Security Best Practices ("Local MCP Server Compromise") asks locally-run
 * HTTP servers to restrict access, e.g. with an authorization token. Setting
 * `PKINATIVE_MCP_HTTP_TOKEN` turns that on: every request to `/mcp` must carry
 * `Authorization: Bearer <token>` or is answered with 401 + WWW-Authenticate
 * before the MCP handler runs. stdio mode is unaffected (the host process owns
 * the pipe). The token is never logged or echoed.
 */
import { createHash, timingSafeEqual } from 'node:crypto';

export const HTTP_TOKEN_ENV = 'PKINATIVE_MCP_HTTP_TOKEN';
/** Shorter secrets are guessable over a local loopback in seconds. */
export const HTTP_TOKEN_MIN_LENGTH = 16;

/**
 * Read the configured token. `null` when unset (no auth, the documented
 * default for loopback deployments); throws on a weak value so a typo never
 * silently runs the server unprotected-but-"configured".
 */
export function readHttpToken(env: NodeJS.ProcessEnv = process.env): string | null {
    const raw = env[HTTP_TOKEN_ENV];
    if (raw === undefined || raw === '') return null;
    if (raw.length < HTTP_TOKEN_MIN_LENGTH || /\s/.test(raw)) {
        throw new Error(`${HTTP_TOKEN_ENV} must be at least ${HTTP_TOKEN_MIN_LENGTH} characters with no whitespace.`);
    }
    return raw;
}

function sameSecret(a: string, b: string): boolean {
    // Hash both sides so the comparison is constant-time regardless of length.
    const ha = createHash('sha256').update(a, 'utf8').digest();
    const hb = createHash('sha256').update(b, 'utf8').digest();
    return timingSafeEqual(ha, hb);
}

/**
 * Returns a 401 `Response` when a token is configured and the request does
 * not present it; `undefined` when the request may proceed.
 */
export function guardBearer(request: Request, token: string | null): Response | undefined {
    if (token === null) return undefined;
    const header = request.headers.get('authorization') ?? '';
    const match = /^Bearer\s+(\S+)\s*$/i.exec(header);
    if (match !== null && sameSecret(match[1] as string, token)) return undefined;
    // RFC 6750 §3.1: no error code when the request carried no credentials at all.
    const challenge = header === '' ? 'Bearer realm="pkinative-mcp"' : 'Bearer realm="pkinative-mcp", error="invalid_token"';
    return new Response(
        JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: { code: -32600, message: 'Unauthorized: a valid "Authorization: Bearer <token>" header is required for this endpoint.' },
        }),
        {
            status: 401,
            headers: {
                'content-type': 'application/json',
                'www-authenticate': challenge,
            },
        },
    );
}
