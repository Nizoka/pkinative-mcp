/**
 * Assertions shared by the tool suites: a result (or any text) holds no
 * secret needle; a tool result is well-formed; a DER artefact round-trips.
 */
import { decodeAsn1 } from 'pkinative';
import { expect } from 'vitest';

import { ToolError } from '../src/errors.js';
import { findNeedle } from './_secrets.js';

/** Fail when any secret needle (key bytes, scalars, password) appears in the text. */
export function assertNoSecret(text: string, what = 'text'): void {
    const needle = findNeedle(text);
    expect(needle, `${what} leaks a secret needle`).toBeNull();
}

/** Walk a whole tool result (content, structuredContent, _meta) and fail on a needle. */
export function assertResultClean(result: unknown, what = 'result'): void {
    assertNoSecret(JSON.stringify(result), what);
}

/** The code of a rejected promise (`ToolError.code`), 'OK' when it resolved, or the thrown value. */
export async function codeOf(p: Promise<unknown>): Promise<string> {
    try {
        await p;
        return 'OK';
    } catch (e) {
        return e instanceof ToolError ? e.code : `THROW:${String(e)}`;
    }
}

/** The `_meta.error.code` of an `isError` tool result, or null. */
export function errorCodeOf(result: { isError?: boolean; _meta?: Record<string, unknown> }): string | null {
    if (result.isError !== true) return null;
    const error = result._meta?.['error'] as { code?: string } | undefined;
    return error?.code ?? null;
}

/** Decode the artefact bytes delivered by an artefact result (base64 mode: the embedded resource). */
export function artefactBytes(result: { content: ReadonlyArray<Record<string, unknown>> }): Uint8Array {
    const block = result.content.find((c) => c['type'] === 'resource') as { resource: { blob?: string; text?: string; mimeType: string } } | undefined;
    expect(block, 'an embedded resource block').toBeDefined();
    const res = (block as { resource: { blob?: string; text?: string; mimeType: string } }).resource;
    if (res.text !== undefined) {
        const body = res.text.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
        return new Uint8Array(Buffer.from(body, 'base64'));
    }
    return new Uint8Array(Buffer.from(res.blob ?? '', 'base64'));
}

/** The bytes parse as exactly one DER value. */
export function assertValidDer(bytes: Uint8Array): void {
    expect(bytes.length).toBeGreaterThan(2);
    expect(() => decodeAsn1(bytes)).not.toThrow();
}
