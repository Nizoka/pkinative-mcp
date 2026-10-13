/**
 * Output emission for the artefact-producing tools (certificates, requests,
 * CMS, OCSP / time-stamp requests, re-encoded ASN.1, PEM bundles): the bytes
 * are delivered ONCE — as an embedded `resource` content block in base64
 * mode, or as a `resource_link` after an exclusive write inside the sandbox
 * in file mode — in the encoding the caller chose (`pem`, `der` or `hex`).
 * Mirrors zipnative-mcp `src/output.ts`.
 */
import { z } from 'zod';
import { encodePem } from 'pkinative';

import { encodeBase64 } from './base64.js';
import { MAX_BASE64_OUTPUT_BYTES, MAX_FILE_OUTPUT_BYTES, MAX_HEX_INLINE_BYTES } from './caps.js';
import { ToolError } from './errors.js';
import { guard } from './pki-errors.js';
import { OUTPUT_EXTENSIONS, relativeLabel, resolveOutputFile, TEXT_OUTPUT_EXTENSIONS, writeExclusive } from './sandbox.js';
import { toHex } from './wire.js';

/** Output mode: either return the bytes in the response, or write to a sandboxed file. */
export type OutputMode = 'base64' | 'file';
/** The encoding of an artefact. */
export type ArtefactEncoding = 'pem' | 'der' | 'hex';

export interface OutputResult {
    /** The output mode that was used. */
    readonly mode: OutputMode;
    /** The encoding that was used. */
    readonly encoding: ArtefactEncoding;
    /** Number of bytes produced (of the DER; the PEM / hex rendering is larger). */
    readonly sizeBytes: number;
    /** SHA-256 of the DER bytes (lowercase hex). */
    readonly sha256: string;
    /** Absolute file path (when `mode === 'file'`). */
    readonly filePath?: string;
    /** Base64 of the delivered bytes (when `mode === 'base64'`; PEM text is base64 of its UTF-8). */
    readonly base64?: string;
    /** The hex rendering (when `encoding === 'hex'` in base64 mode). */
    readonly hex?: string;
    /** MIME type of the delivered bytes. */
    readonly mimeType: string;
    /** Tool-specific summary echoed into `structuredContent.summary`. */
    readonly summary?: Readonly<Record<string, unknown>>;
}

/** JSON Schema properties for the output inputs (spread into the artefact-producing tools). */
export function outputInputProperties(defaultEncoding: ArtefactEncoding, extensionsHint: string): Record<string, unknown> {
    return {
        outputMode: {
            type: 'string',
            enum: ['base64', 'file'],
            default: 'base64',
            description: "'base64' (default) returns the artefact inline as an embedded resource (≤ 50 MiB). 'file' writes it inside PKINATIVE_MCP_OUTPUT_DIR (never overwrites; ≤ 1 GiB) and returns a resource_link.",
        },
        outputPath: {
            type: 'string',
            minLength: 1,
            description: `Relative path inside the sandbox (only when outputMode='file'); the extension must match the encoding (${extensionsHint}). Key-bearing extensions (.key .p8 .p12 .pfx) are refused: nothing here writes a private key.`,
        },
        encoding: {
            type: 'string',
            enum: ['pem', 'der', 'hex'],
            default: defaultEncoding,
            description: `Artefact encoding: 'pem' (RFC 7468 text), 'der' (raw bytes), 'hex' (lowercase hex in structuredContent, inline only, ≤ 64 KiB). Default '${defaultEncoding}'.`,
        },
    };
}

/** Zod twin of {@link outputInputProperties} (spread into the artefact-producing tools). */
export function outputShape(defaultEncoding: ArtefactEncoding): {
    outputMode: z.ZodDefault<z.ZodEnum<{ base64: 'base64'; file: 'file' }>>;
    outputPath: z.ZodOptional<z.ZodString>;
    encoding: z.ZodDefault<z.ZodEnum<{ pem: 'pem'; der: 'der'; hex: 'hex' }>>;
} {
    return {
        outputMode: z.enum(['base64', 'file']).default('base64'),
        outputPath: z.string().min(1).optional(),
        encoding: z.enum(['pem', 'der', 'hex']).default(defaultEncoding),
    };
}

export interface EmitOptions {
    readonly mode: OutputMode;
    readonly encoding: ArtefactEncoding;
    readonly outputPath?: string | undefined;
    /** The RFC 7468 label for `encoding: 'pem'`. */
    readonly pemLabel: string;
    /** MIME type of the DER form (the PEM form is application/x-pem-file). */
    readonly mimeType: string;
    /** Sandbox extensions accepted for the DER form (default: every PKI output extension). */
    readonly derExtensions?: readonly string[];
    readonly summary?: Readonly<Record<string, unknown>>;
}

const PEM_MIME = 'application/x-pem-file';

async function sha256(bytes: Uint8Array): Promise<string> {
    const { createHash } = await import('node:crypto');
    return createHash('sha256').update(bytes).digest('hex');
}

/** Produce the final tool output for a DER artefact. */
export async function emitArtefact(der: Uint8Array, options: EmitOptions): Promise<OutputResult> {
    const digest = await sha256(der);
    const base = { encoding: options.encoding, sizeBytes: der.byteLength, sha256: digest, ...(options.summary !== undefined ? { summary: options.summary } : {}) };
    if (options.encoding === 'hex') {
        if (options.mode === 'file') {
            throw new ToolError('VALIDATION_ERROR', "encoding:'hex' is an inline form — use 'der' or 'pem' with outputMode:'file'.", { remedy: "encoding:'der'" });
        }
        if (der.byteLength > MAX_HEX_INLINE_BYTES) {
            throw new ToolError('OUTPUT_TOO_LARGE', `The artefact (${der.byteLength} bytes) exceeds the ${MAX_HEX_INLINE_BYTES}-byte hex cap — use encoding:'der' or 'pem'.`, { sizeBytes: der.byteLength, cap: MAX_HEX_INLINE_BYTES, remedy: "encoding:'der'" });
        }
        return { ...base, mode: 'base64', hex: toHex(der), mimeType: 'application/octet-stream' };
    }
    const delivered = options.encoding === 'pem' ? new TextEncoder().encode(guard('Cannot encode PEM', () => encodePem(options.pemLabel, der))) : der;
    const mimeType = options.encoding === 'pem' ? PEM_MIME : options.mimeType;
    if (options.mode === 'file') {
        if (options.outputPath === undefined) {
            throw new ToolError('MISSING_OUTPUT_PATH', "outputPath is required when outputMode='file'.", { remedy: 'outputPath' });
        }
        if (delivered.byteLength > MAX_FILE_OUTPUT_BYTES) {
            throw new ToolError('OUTPUT_TOO_LARGE', `Output (${delivered.byteLength} bytes) exceeds the ${MAX_FILE_OUTPUT_BYTES}-byte file cap.`, { sizeBytes: delivered.byteLength, cap: MAX_FILE_OUTPUT_BYTES });
        }
        const extensions = options.encoding === 'pem' ? ['.pem'] : (options.derExtensions ?? OUTPUT_EXTENSIONS);
        const resolved = resolveOutputFile(options.outputPath, extensions);
        await writeExclusive(resolved, delivered, relativeLabel(resolved));
        return { ...base, mode: 'file', filePath: resolved, mimeType };
    }
    if (delivered.byteLength > MAX_BASE64_OUTPUT_BYTES) {
        throw new ToolError(
            'OUTPUT_TOO_LARGE',
            `Output (${delivered.byteLength} bytes) exceeds the ${MAX_BASE64_OUTPUT_BYTES}-byte inline cap — use outputMode:'file' with PKINATIVE_MCP_OUTPUT_DIR set.`,
            { sizeBytes: delivered.byteLength, cap: MAX_BASE64_OUTPUT_BYTES, remedy: "outputMode:'file'" },
        );
    }
    return { ...base, mode: 'base64', base64: encodeBase64(delivered), mimeType };
}

/**
 * Write a UTF-8 text artefact (a Markdown governance draft, a PEM bundle) to
 * a sandboxed path with the same guards; `wx` never clobbers.
 */
export async function writeSandboxedText(text: string, outputPath: string, extensions: readonly string[] = TEXT_OUTPUT_EXTENSIONS): Promise<{ filePath: string; sizeBytes: number }> {
    const bytes = Buffer.from(text, 'utf8');
    if (bytes.byteLength > MAX_BASE64_OUTPUT_BYTES) {
        throw new ToolError('OUTPUT_TOO_LARGE', `The text artefact (${bytes.byteLength} bytes) exceeds the maximum allowed size (${MAX_BASE64_OUTPUT_BYTES} bytes).`, { sizeBytes: bytes.byteLength, cap: MAX_BASE64_OUTPUT_BYTES });
    }
    const resolved = resolveOutputFile(outputPath, extensions);
    await writeExclusive(resolved, bytes, relativeLabel(resolved));
    return { filePath: resolved, sizeBytes: bytes.byteLength };
}

/** The `structuredContent` members every artefact result shares. */
export const ARTEFACT_OUTPUT_PROPERTIES = {
    mode: { type: 'string', enum: ['base64', 'file'] },
    encoding: { type: 'string', enum: ['pem', 'der', 'hex'] },
    sizeBytes: { type: 'integer', minimum: 0, description: 'Size of the DER artefact.' },
    sha256: { type: 'string', description: 'SHA-256 of the DER bytes (lowercase hex) — the reproducibility proof.' },
    filePath: { type: 'string', description: "Sandboxed absolute path (when outputMode='file')." },
    hex: { type: 'string', description: "The artefact as lowercase hex (when encoding='hex')." },
} as const;
