/**
 * The content input of the signing / verification / time-stamping tools:
 * exactly one of `text` (UTF-8), `base64` or `path` (a relative sandbox
 * path; no extension restriction — it is the bytes being signed, not a PKI
 * object). Bounded by the inline and path caps.
 */
import { promises as fs } from 'node:fs';
import { z } from 'zod';

import { decodeBase64Field } from './base64.js';
import { assertInputWithin, MAX_CONTENT_INLINE_BYTES, MAX_CONTENT_PATH_BYTES } from './caps.js';
import { ToolError } from './errors.js';
import { resolveInputFile } from './sandbox.js';

export interface ContentInputFields {
    readonly text?: string | undefined;
    readonly base64?: string | undefined;
    readonly path?: string | undefined;
}

/** JSON Schema for a content input. */
export function contentInputSchema(what: string): Record<string, unknown> {
    return {
        type: 'object',
        additionalProperties: false,
        description: `${what}: exactly one of text / base64 / path.`,
        properties: {
            text: { type: 'string', description: `${what} as UTF-8 text. Exclusive with base64 / path.` },
            base64: { type: 'string', description: `${what} as base64 bytes (≤ 128 MiB decoded). Exclusive with text / path.` },
            path: { type: 'string', minLength: 1, description: `Relative path of a file inside the sandbox (any extension, ≤ 1 GiB). Exclusive with text / base64.` },
        },
    };
}

/** Zod twin of {@link contentInputSchema}. */
export const ContentInputSchema = z.strictObject({
    text: z.string().optional(),
    base64: z.string().optional(),
    path: z.string().min(1).optional(),
}).superRefine((v, ctx) => {
    const n = (v.text !== undefined ? 1 : 0) + (v.base64 !== undefined ? 1 : 0) + (v.path !== undefined ? 1 : 0);
    if (n !== 1) ctx.addIssue({ code: 'custom', message: 'pass exactly one of text / base64 / path', path: ['text'] });
});

/** Load the content bytes. */
export async function loadContent(input: ContentInputFields, what: string): Promise<{ bytes: Uint8Array; source: string }> {
    if (input.text !== undefined) {
        const bytes = new TextEncoder().encode(input.text);
        assertInputWithin(bytes.byteLength, MAX_CONTENT_INLINE_BYTES, `${what} (text)`);
        return { bytes, source: 'text' };
    }
    if (input.base64 !== undefined) {
        const bytes = input.base64 === '' ? new Uint8Array(0) : decodeBase64Field(input.base64, `${what}.base64`);
        assertInputWithin(bytes.byteLength, MAX_CONTENT_INLINE_BYTES, `${what} (base64, decoded)`);
        return { bytes, source: 'base64' };
    }
    if (input.path === undefined) {
        throw new ToolError('VALIDATION_ERROR', `${what}: pass exactly one of text / base64 / path`, { path: what });
    }
    const { resolved, size } = await resolveInputFile(input.path, null, `${what}.path`);
    assertInputWithin(size, MAX_CONTENT_PATH_BYTES, `${what}.path '${input.path}'`);
    const buf = await fs.readFile(resolved);
    return { bytes: new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength), source: input.path };
}

/** JSON Schema property for a hex string input (`:`, spaces and an `0x` prefix tolerated). */
export const HEX_PATTERN = '^(?:0x)?(?:[0-9a-fA-F]{2}[:\\s]?)+$';

export function hexSchema(description: string): { readonly type: 'string'; readonly minLength: 2; readonly pattern: string; readonly description: string } {
    return { type: 'string', minLength: 2, pattern: HEX_PATTERN, description: `${description} Hexadecimal (an 0x prefix, colons and spaces are tolerated).` } as const;
}

/** Zod validator for a hex string (same grammar as {@link HEX_PATTERN}). */
export const HexSchema = z.string().min(2).regex(new RegExp(HEX_PATTERN));
