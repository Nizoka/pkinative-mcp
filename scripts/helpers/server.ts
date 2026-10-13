/**
 * The built server, as a script sees it.
 *
 * Scripts never import `src/`: they load `dist/server.js` — what `npm publish`
 * ships — and call its `callToolDirect()`, the same function the `tools/call`
 * request handler delegates to. A path that resolves in source but not in the
 * emitted tree therefore fails here, before a release. The tool catalogue is
 * discovered at run time (`toolNames()`, `listToolsPayload()`): no script
 * hard-codes the list, so the corpus and the samples keep working while the
 * catalogue grows.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { REPO_ROOT } from './io.js';

export const SERVER_MODULE = join(REPO_ROOT, 'dist', 'server.js');

export interface ContentBlock {
    readonly type: string;
    readonly text?: string;
    readonly uri?: string;
    readonly mimeType?: string;
    readonly resource?: { readonly uri?: string; readonly blob?: string; readonly text?: string; readonly mimeType?: string };
}

export interface ToolResult {
    readonly isError?: boolean;
    readonly content?: readonly ContentBlock[];
    readonly structuredContent?: Readonly<Record<string, unknown>>;
    readonly _meta?: { readonly error?: { readonly code?: string; readonly message?: string; readonly data?: unknown }; readonly [key: string]: unknown };
}

export interface ToolListing {
    readonly name: string;
    readonly title?: string;
    readonly annotations?: { readonly readOnlyHint?: boolean; readonly idempotentHint?: boolean; readonly destructiveHint?: boolean; readonly openWorldHint?: boolean };
    readonly inputSchema: { readonly properties?: Readonly<Record<string, unknown>>; readonly [key: string]: unknown };
    readonly outputSchema?: unknown;
    readonly _meta?: { readonly examples?: readonly unknown[] };
}

export interface BuiltServer {
    readonly callToolDirect: (name: string, args: unknown) => Promise<ToolResult>;
    readonly ensureEngineReady: () => Promise<void>;
    readonly listToolsPayload: () => { readonly tools: readonly ToolListing[] };
    readonly toolNames: () => string[];
    /** `SERVER_INSTRUCTIONS`, re-exported for the size budget of `scripts/tool-shape.ts --check`. */
    readonly __serverInstructions: string;
}

/** Null when `dist/` is absent — callers print the build hint and exit 2. */
export async function loadBuiltServer(): Promise<BuiltServer | null> {
    if (!existsSync(SERVER_MODULE)) return null;
    const mod = (await import(pathToFileURL(SERVER_MODULE).href)) as unknown as BuiltServer;
    await mod.ensureEngineReady();
    return mod;
}

/** The version `dist/` was built from (package.json is the reference the smoke step holds `serverInfo.version` to). */
export function packageVersion(): string {
    return (JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as { version: string }).version;
}

/** The one-line error text of a failed result, with its wrapper code when the server attached one. */
export function errorText(name: string, result: ToolResult): string {
    const first = result.content?.[0];
    const code = result._meta?.error?.code;
    return `${name}${code !== undefined ? ` [${code}]` : ''}: ${first?.type === 'text' && first.text !== undefined ? first.text : 'unknown error'}`;
}

/** The wrapper / engine code of a failed result (`_meta.error.code`), or null. */
export function errorCode(result: ToolResult): string | null {
    const code = result._meta?.error?.code;
    return typeof code === 'string' ? code : null;
}

/** Call a tool; throws with the tool's error text when `isError` is set. */
export async function callOrThrow(server: BuiltServer, name: string, args: unknown): Promise<ToolResult> {
    const result = await server.callToolDirect(name, args);
    if (result.isError === true) throw new Error(errorText(name, result));
    return result;
}

export interface Artefact {
    /** The delivered bytes: DER, or the UTF-8 of the PEM text. */
    readonly bytes: Buffer;
    readonly encoding: 'pem' | 'der' | 'hex';
    readonly mimeType: string;
}

/**
 * The artefact a result delivers, once: the embedded resource block (PEM as
 * `text`, DER as `blob`), the `hex` member of structuredContent, or — in file
 * mode — the file the resource_link points at inside the sandbox. Null for a
 * JSON-only result (the read tools).
 */
export function artefactOf(result: ToolResult): Artefact | null {
    for (const c of result.content ?? []) {
        if (c.type === 'resource' && c.resource !== undefined) {
            const mimeType = c.resource.mimeType ?? 'application/octet-stream';
            if (typeof c.resource.text === 'string' && c.resource.text.length > 0) return { bytes: Buffer.from(c.resource.text, 'utf8'), encoding: 'pem', mimeType };
            if (typeof c.resource.blob === 'string' && c.resource.blob.length > 0) return { bytes: Buffer.from(c.resource.blob, 'base64'), encoding: 'der', mimeType };
        }
    }
    const structured = result.structuredContent ?? {};
    const hex = structured['hex'];
    if (typeof hex === 'string' && hex.length > 0) return { bytes: Buffer.from(hex, 'hex'), encoding: 'hex', mimeType: 'application/octet-stream' };
    const filePath = structured['filePath'];
    if (typeof filePath === 'string' && existsSync(filePath)) {
        const encoding = structured['encoding'] === 'pem' ? 'pem' : 'der';
        return { bytes: readFileSync(filePath), encoding, mimeType: encoding === 'pem' ? 'application/x-pem-file' : 'application/octet-stream' };
    }
    return null;
}

/** Call a tool and return the DER / PEM bytes it produced. */
export async function produce(server: BuiltServer, name: string, args: unknown): Promise<Artefact> {
    const artefact = artefactOf(await callOrThrow(server, name, args));
    if (artefact === null) throw new Error(`${name}: no artefact in the tool result.`);
    return artefact;
}
