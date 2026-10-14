/**
 * A-009 — the "no network" doctrine, held mechanically: no `fetch(`, no
 * `https`, no `dns`, no WebSocket anywhere under src/; `node:http` only in
 * the loopback listener (src/http.ts) and the CLI that starts it
 * (src/cli.ts, dynamically, so a stdio session never loads it); `node:net`
 * only in src/names.ts and only for the pure `isIPv4` / `isIPv6` parsers
 * (RFC 5280 iPAddress octets). No tool input is named like a URL.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { listToolsPayload } from '../src/server.js';

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');

function walk(dir: string, out: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
        const full = path.join(dir, entry);
        if (statSync(full).isDirectory()) walk(full, out);
        else if (entry.endsWith('.ts')) out.push(full);
    }
    return out;
}

/** Source with comments stripped: the doctrine is about code, and a comment may name what the code refuses. */
function code(text: string): string {
    return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

const FILES = walk(SRC).map((f) => [path.relative(SRC, f).split(path.sep).join('/'), code(readFileSync(f, 'utf8'))] as const);

describe('A-009: no network code path', () => {
    it('no fetch, https, dns, net listener or WebSocket anywhere under src/', () => {
        for (const [file, text] of FILES) {
            // A global fetch() is a network client; `handler.fetch(request)` is the SDK's in-process Web-API handler.
            expect(text, file).not.toMatch(/(?<![.\w])fetch\s*\(/);
            // Import specifiers only: a description may mention 'https' as a scheme the certificate names.
            expect(text, file).not.toMatch(/from\s+['"](?:node:)?(?:https|dns|tls|net\/|http2)['"]|require\(['"](?:node:)?(?:https|dns|tls|http2)['"]\)|import\(['"](?:node:)?(?:https|dns|tls|http2)['"]\)|WebSocket/);
        }
    });

    it('node:http is imported only by the loopback listener and, dynamically, by the CLI that starts it', () => {
        const importers = FILES.filter(([, text]) => /['"]node:http['"]|['"]http['"]/.test(text)).map(([file]) => file).sort();
        expect(importers).toEqual(['cli.ts', 'http.ts']);
        const cli = FILES.find(([file]) => file === 'cli.ts')![1];
        expect(cli).toMatch(/await import\(['"]node:http['"]\)/);
        expect(cli).not.toMatch(/^import .* from ['"]node:http['"]/m);
        const http = FILES.find(([file]) => file === 'http.ts')![1];
        expect(http).toMatch(/localhostAllowedHostnames/);
        expect(cli).toMatch(/listen\(port, '127\.0\.0\.1'/);
        expect(http).not.toMatch(/\bhttp\.(request|get)\(|createConnection|\brequest\(\s*['"`]http/);
    });

    it('node:net is imported only by src/names.ts, and only for the pure isIPv4 / isIPv6 parsers', () => {
        const importers = FILES.filter(([, text]) => /['"]node:net['"]|['"]net['"]/.test(text)).map(([file]) => file);
        expect(importers).toEqual(['names.ts']);
        const names = FILES.find(([file]) => file === 'names.ts')![1];
        expect(names).toMatch(/^import \{ isIPv4, isIPv6 \} from 'node:net';$/m);
        expect(names).not.toMatch(/createConnection|createServer|Socket/);
    });

    it('no tool input is named like a URL or an endpoint', () => {
        const names = new Set<string>();
        const collect = (schema: unknown): void => {
            if (schema === null || typeof schema !== 'object') return;
            const props = (schema as { properties?: Record<string, unknown> }).properties;
            if (props !== undefined) {
                for (const [k, v] of Object.entries(props)) {
                    names.add(k);
                    collect(v);
                }
            }
            const items = (schema as { items?: unknown }).items;
            if (items !== undefined) collect(items);
            for (const arm of ((schema as { anyOf?: unknown[] }).anyOf ?? (schema as { oneOf?: unknown[] }).oneOf ?? [])) collect(arm);
        };
        for (const tool of listToolsPayload().tools) collect(tool.inputSchema);
        // `uri` is the uniformResourceIdentifier VALUE of a subjectAltName spec (data the certificate carries, never fetched).
        const DATA_ONLY = new Set(['uri']);
        const offenders = [...names].filter((n) => !DATA_ONLY.has(n) && /url|uri|endpoint|href|fetch|download|proxy/i.test(n));
        expect(offenders).toEqual([]);
    });
});
